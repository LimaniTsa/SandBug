from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor


def run_analysis_task(analysis_id: int, file_path: str, filename: str):
    """
    RQ worker task: runs the full static → dynamic → AI-summary pipeline
    and writes results to the tables.
    """
    from app import create_app
    from app.models import (
        db, Analysis, StaticResult, YaraMatch,
        DynamicResult, IOC, AIReport,
    )
    from app.services.static_analyzer import analyse_file as static_analyse_file
    from app.services.dynamic_analyzer import analyse_file as dynamic_analyse_file, merge_risk_score
    from app.services.ai_summarizer import summarise_file
    from app.services import storage

    CLAUDE_MODEL = 'claude-haiku-4-5-20251001'

    app = create_app()
    with app.app_context():
        record = Analysis.query.get(analysis_id)
        if not record:
            return

        static_raw        = None
        dynamic_raw       = None
        static_risk_score = 0
        dynamic_failed    = False
        sandbox_skipped_reason = None

        # Run static and dynamic analysis in parallel so neither can mask the other.
        # Only skip dynamic for files that are digitally signed (trusted publisher).
        try:
            with storage.local_path(file_path) as local_file:
                local_file_str = str(local_file)

                def _run_static():
                    return static_analyse_file(local_file_str)

                def _run_dynamic():
                    return dynamic_analyse_file(local_file_str, filename)

                with ThreadPoolExecutor(max_workers=2) as executor:
                    f_static  = executor.submit(_run_static)
                    f_dynamic = executor.submit(_run_dynamic)

                    try:
                        static_raw = f_static.result()
                    except Exception as exc:
                        static_raw = {}
                        record.error_message = f'Static analysis failed: {exc}'

                    try:
                        dynamic_raw = f_dynamic.result()
                    except Exception as exc:
                        dynamic_raw = {'error': str(exc), 'dynamic_risk_score': 0, 'results': {}}

        except Exception as exc:
            record.status        = 'static_failed'
            record.error_message = f'Analysis failed: {exc}'
            db.session.commit()
            return

        static_risk_score = (static_raw or {}).get('risk_score', 0)
        dynamic_failed    = 'error' in (dynamic_raw or {})
        triage            = (dynamic_raw or {}).get('results', {}).get('triage')

        is_signed = bool((static_raw or {}).get('signature', {}).get('valid', False))

        # Write static results to DB
        sig      = (static_raw or {}).get('signature', {})
        entropy  = (static_raw or {}).get('entropy', {}).get('overall', 0)
        sections = (static_raw or {}).get('sections', [])

        sr = StaticResult(
            analysis_id       = analysis_id,
            pe_type           = (static_raw or {}).get('file_info', {}).get('file_type'),
            entropy           = entropy,
            is_packed         = any(s.get('entropy', 0) >= 7.5 for s in sections),
            is_signed         = bool(sig.get('valid', False)),
            publisher         = sig.get('publisher'),
            imports           = (static_raw or {}).get('imports'),
            sections          = sections,
            strings_extracted = {
                'ascii':   ((static_raw or {}).get('strings') or {}).get('ascii',   [])[:100],
                'unicode': ((static_raw or {}).get('strings') or {}).get('unicode', [])[:100],
            },
        )
        db.session.add(sr)

        for rule in (static_raw or {}).get('yara', {}).get('rules', []):
            tags = rule.get('tags') or []
            db.session.add(YaraMatch(
                analysis_id     = analysis_id,
                rule_name       = rule.get('rule', ''),
                category        = tags[0] if tags else None,
                severity        = rule.get('meta', {}).get('severity', 'low'),
                matched_strings = rule.get('strings'),
            ))

        for ind in (static_raw or {}).get('suspicious_indicators', []):
            db.session.add(IOC(
                analysis_id = analysis_id,
                ioc_type    = 'indicator',
                value       = str(ind)[:500],
                source      = 'static',
                severity    = 'medium',
            ))

        record.status = 'static_complete'
        db.session.commit()

        if triage:
            record.triage_sample_id = triage.get('sample_id')

            for dom in (triage.get('network') or {}).get('domains', []):
                d = dom.get('domain', '')
                if d:
                    db.session.add(IOC(
                        analysis_id = analysis_id,
                        ioc_type    = 'domain',
                        value       = d[:500],
                        source      = 'dynamic',
                        severity    = 'medium',
                    ))

            for f in (triage.get('dropped_files') or []):
                h = f.get('sha256') or f.get('md5')
                if h:
                    db.session.add(IOC(
                        analysis_id = analysis_id,
                        ioc_type    = 'hash',
                        value       = h[:500],
                        source      = 'dynamic',
                        severity    = 'medium',
                    ))

            db.session.add(DynamicResult(
                analysis_id          = analysis_id,
                sandbox_provider     = 'triage',
                sandbox_sample_id    = triage.get('sample_id'),
                executed_successfully= True,
                processes            = triage.get('processes'),
                network_activity     = triage.get('network'),
                registry_changes     = triage.get('registry'),
                dropped_files        = triage.get('dropped_files'),
                # Triage-specific fields stored here (no dedicated columns)
                file_operations      = {
                    'triage_score': triage.get('triage_score', 0),
                    'signatures':   triage.get('signatures', []),
                    'mutexes':      triage.get('mutexes', []),
                    'tags':         triage.get('tags', []),
                    'report_url':   triage.get('report_url'),
                    'errors':       triage.get('errors', []),
                },
            ))

        elif dynamic_failed:
            record.error_message = dynamic_raw.get('error')

        merged_score = merge_risk_score(
            static_risk_score,
            dynamic_raw['dynamic_risk_score'],
            dynamic_available = not dynamic_failed,
            is_signed         = is_signed,
        )
        record.risk_score = merged_score
        record.calculate_risk_level()

        if dynamic_failed:
            record.status = 'dynamic_failed'
        else:
            record.status       = 'completed'
            record.completed_at = datetime.now(timezone.utc)

        db.session.commit()

        try:
            summary_text = summarise_file(
                filename               = filename,
                file_type              = record.file_type or 'Unknown',
                risk_level             = record.risk_level or 'unknown',
                risk_score             = int(record.risk_score or 0),
                static_analysis        = static_raw or {},
                dynamic_analysis       = triage,
                sandbox_skipped_reason = sandbox_skipped_reason,
            )
            if summary_text:
                db.session.add(AIReport(
                    analysis_id = analysis_id,
                    model_used  = CLAUDE_MODEL,
                    threat_level= record.risk_level,
                    summary     = summary_text,
                ))
                db.session.commit()
        except Exception:
            pass
