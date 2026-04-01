from flask import request, jsonify, current_app, Response
from app.api import analysis_bp
from app.models import db, Analysis, UrlAnalysis
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request
from werkzeug.utils import secure_filename
import os
import hashlib
import magic
from datetime import datetime, timezone
from app.services.ai_summarizer import summarise_url


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_file_type(file_path):
    """
    Returns a human-readable file type description.
    Uses magic's descriptive mode first, then MIME type, then file extension.
    """
    MIME_LABELS = {
        'application/x-dosexec':           'PE Executable (Windows)',
        'application/x-executable':        'ELF Executable (Linux)',
        'application/x-sharedlib':         'Shared Library (.so)',
        'application/x-mach-binary':       'Mach-O Binary (macOS)',
        'application/pdf':                 'PDF Document',
        'application/zip':                 'ZIP Archive',
        'application/x-rar':               'RAR Archive',
        'application/x-7z-compressed':     '7-Zip Archive',
        'application/x-tar':               'TAR Archive',
        'application/gzip':                'GZIP Archive',
        'application/x-msdownload':        'PE Executable (Windows)',
        'application/vnd.ms-office':       'Microsoft Office Document',
        'application/msword':              'Word Document',
        'application/x-powershell':        'PowerShell Script',
        'text/x-python':                   'Python Script',
        'text/x-shellscript':              'Shell Script',
        'text/plain':                      'Plain Text',
        'application/javascript':          'JavaScript',
        'application/x-bytecode.python':   'Python Bytecode',
        'application/octet-stream':        'Binary File',
    }
    EXT_LABELS = {
        '.exe': 'Windows Executable',  '.dll': 'Windows DLL',
        '.sys': 'Windows Driver',      '.drv': 'Windows Driver',
        '.scr': 'Windows Screensaver', '.com': 'DOS Executable',
        '.pdf': 'PDF Document',        '.zip': 'ZIP Archive',
        '.rar': 'RAR Archive',         '.7z':  '7-Zip Archive',
        '.tar': 'TAR Archive',         '.gz':  'GZIP Archive',
        '.js':  'JavaScript',          '.ts':  'TypeScript',
        '.py':  'Python Script',       '.pyc': 'Python Bytecode',
        '.ps1': 'PowerShell Script',   '.bat': 'Batch Script',
        '.cmd': 'Batch Script',        '.sh':  'Shell Script',
        '.vbs': 'VBScript',            '.hta': 'HTML Application',
        '.jar': 'Java Archive',        '.apk': 'Android Package',
        '.doc': 'Word Document',       '.docx': 'Word Document (DOCX)',
        '.xls': 'Excel Spreadsheet',   '.xlsx': 'Excel Spreadsheet (XLSX)',
        '.ppt': 'PowerPoint',          '.pptx': 'PowerPoint (PPTX)',
        '.elf': 'ELF Executable',      '.so':  'Shared Library',
        '.lnk': 'Windows Shortcut',    '.iso': 'Disk Image',
    }
    try:
        desc = magic.Magic(mime=False).from_file(file_path)
        if desc and desc.lower() not in ('', 'data', 'unknown', 'very short file (no magic)'):
            return desc.split(',')[0].strip()
    except Exception:
        pass

    try:
        mime = magic.Magic(mime=True).from_file(file_path)
        if mime and mime not in ('application/octet-stream', 'inode/x-empty'):
            return MIME_LABELS.get(mime, mime)
    except Exception:
        pass

    # Extension-based fallback reliable even for truncated/test files
    ext = os.path.splitext(file_path)[1].lower()
    return EXT_LABELS.get(ext, 'Binary File')



@analysis_bp.route('/upload', methods=['POST'])
def upload_file():
    """
    Accept the file, create a DB record, and return 202 immediately.
    Analysis runs in a background thread, the client polls GET /<id> for status.
    """
    try:
        user_id = None
        try:
            verify_jwt_in_request(optional=True)
            _raw_uid = get_jwt_identity()
            user_id = int(_raw_uid) if _raw_uid is not None else None
        except Exception:
            pass

        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({
                'error': f'File type not allowed. Allowed types: {", ".join(current_app.config["ALLOWED_EXTENSIONS"])}'
            }), 400

        from app.services import storage

        original_filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{original_filename}"

        file_bytes = file.read()
        file_size  = len(file_bytes)

        # Write to a temp file for hashing and type detection before storage.
        import tempfile
        with tempfile.NamedTemporaryFile(
            suffix=os.path.splitext(original_filename)[1] or '.bin',
            delete=False,
        ) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        try:
            file_hash = get_file_hash(tmp_path)
            file_type = get_file_type(tmp_path)
        finally:
            os.remove(tmp_path)

        storage_key = storage.save(file_bytes, unique_filename)
        file_path   = storage_key

        # URL analyses are intentionally excluded — the same URL must always
        # trigger a fresh run since threat data changes and new detectors are added.
        if user_id:
            existing = Analysis.query.filter_by(
                user_id=user_id,
                file_hash=file_hash
            ).filter(Analysis.file_type != 'URL').first()
            if existing:
                storage.delete(storage_key)
                return jsonify({
                    'message': 'File already analysed',
                    'duplicate': True,
                    'analysis_id': existing.id,
                    'analysis': existing.to_dict()
                }), 200

        new_analysis = Analysis(
            user_id=user_id,
            filename=original_filename,
            file_hash=file_hash,
            file_size=file_size,
            file_type=file_type,
            file_path=file_path,
            status='processing'
        )
        db.session.add(new_analysis)
        db.session.commit()

        # Enqueue analysis task — worker picks it up asynchronously.
        # Client polls GET /<analysis_id> for status updates.
        current_app.rq_queue.enqueue(
            'app.tasks.run_analysis_task',
            new_analysis.id, file_path, original_filename,
            job_timeout=600,
        )

        return jsonify({
            'message': 'File uploaded successfully. Analysis running.',
            'analysis_id': new_analysis.id,
            'status': 'processing',
            'analysis': new_analysis.to_dict()
        }), 202

    except Exception as exc:
        db.session.rollback()
        return jsonify({'error': f'Upload failed: {str(exc)}'}), 500


@analysis_bp.route('/url', methods=['POST'])
def check_url():
    """
    POST /api/analysis/url
    Body: { "url": "https://example.com" }

    Runs URL threat analysis synchronously (fast, no file I/O) and stores
    the result in the Analysis table so the same Results page can render it.
    """
    from app.services.url_analyzer import analyse_url

    try:
        verify_jwt_in_request(optional=True)
        _raw_uid = get_jwt_identity()
        user_id = int(_raw_uid) if _raw_uid is not None else None
    except Exception:
        user_id = None

    data = request.get_json(silent=True) or {}
    url  = (data.get('url') or '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        return jsonify({'error': 'Invalid URL. Must start with http:// or https://'}), 400


    try:
        # Run analysis always fresh — URL threat data changes over time.
        result = analyse_url(url)

        redir  = result.get('redirects') or {}
        ipr    = result.get('ip_reputation') or {}

        ua = UrlAnalysis(
            user_id         = user_id,
            url_submitted   = url,
            final_url       = redir.get('final_url'),
            redirect_chain  = redir.get('chain'),
            resolved_ip     = result.get('ip'),
            abuseipdb_score = ipr.get('abuse_score') if ipr.get('checked') else None,
            gsb_threat_type = (((result.get('safe_browsing') or {}).get('threats') or [None])[0]),
            risk_score      = result['risk_score'],
            risk_level      = result['risk_level'],
            raw_result      = result,
        )
        db.session.add(ua)
        db.session.flush()   # get ua.id before Analysis insert

        import hashlib as _hashlib, time as _time
        url_hash = _hashlib.sha256(f"{url}:{_time.time()}".encode()).hexdigest()

        record = Analysis(
            user_id         = user_id,
            filename        = url,
            file_hash       = url_hash,
            file_size       = 0,
            file_path       = '',
            file_type       = 'URL',
            risk_score      = result['risk_score'],
            risk_level      = result['risk_level'],
            status          = 'completed',
            completed_at    = datetime.now(timezone.utc),
            url_analysis_id = ua.id,
        )
        db.session.add(record)
        db.session.commit()

        try:
            ua.ai_summary = summarise_url(result)
            db.session.commit()
        except Exception:
            pass

        return jsonify({
            'analysis_id': record.id,
            'status':      'completed',
            'risk_score':  result['risk_score'],
            'risk_level':  result['risk_level'],
        }), 200

    except Exception as exc:
        db.session.rollback()
        return jsonify({'error': f'URL analysis failed: {str(exc)}'}), 500


@analysis_bp.route('/<int:analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    try:
        user_id = None
        try:
            verify_jwt_in_request(optional=True)
            _raw_uid = get_jwt_identity()
            user_id = int(_raw_uid) if _raw_uid is not None else None
        except Exception:
            pass

        analysis = Analysis.query.get(analysis_id)

        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404

        if analysis.user_id and analysis.user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403

        return jsonify({'analysis': analysis.to_dict(include_results=True)}), 200

    except Exception as exc:
        return jsonify({'error': f'Failed to get analysis: {str(exc)}'}), 500


@analysis_bp.route('/history', methods=['GET'])
@jwt_required()
def get_user_analyses():
    try:
        user_id = int(get_jwt_identity())

        page     = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        status     = request.args.get('status')
        risk_level = request.args.get('risk_level')
        search     = (request.args.get('search') or '').strip()

        query = Analysis.query.filter_by(user_id=user_id)

        if status:
            query = query.filter_by(status=status)
        if risk_level:
            query = query.filter_by(risk_level=risk_level)
        if search:
            like = f'%{search}%'
            query = query.filter(
                db.or_(
                    Analysis.filename.ilike(like),
                    Analysis.url.ilike(like),
                )
            )

        query = query.order_by(Analysis.submitted_at.desc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'analyses':     [a.to_dict() for a in pagination.items],
            'total':        pagination.total,
            'pages':        pagination.pages,
            'current_page': page
        }), 200

    except Exception as exc:
        return jsonify({'error': f'Failed to get analyses: {str(exc)}'}), 500


@analysis_bp.route('/<int:analysis_id>/triage-report', methods=['GET'])
def get_triage_report(analysis_id):
    """Return the public Triage report URL for deep-dive investigation."""
    try:
        user_id = None
        try:
            verify_jwt_in_request(optional=True)
            _raw_uid = get_jwt_identity()
            user_id = int(_raw_uid) if _raw_uid is not None else None
        except Exception:
            pass

        analysis = Analysis.query.get(analysis_id)
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        if analysis.user_id and analysis.user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403

        dr = analysis.dynamic_result
        if not dr:
            return jsonify({'error': 'Dynamic analysis not complete or failed'}), 404

        fo         = dr.file_operations or {}
        report_url = fo.get('report_url')
        if not report_url:
            return jsonify({'error': 'Dynamic analysis not complete or failed'}), 404

        return jsonify({
            'report_url':   report_url,
            'sample_id':    dr.sandbox_sample_id,
            'triage_score': fo.get('triage_score'),
        }), 200

    except Exception as exc:
        return jsonify({'error': f'Failed to get Triage report: {str(exc)}'}), 500


@analysis_bp.route('/<int:analysis_id>', methods=['DELETE'])
@jwt_required()
def delete_analysis(analysis_id):
    try:
        user_id = int(get_jwt_identity())
        analysis = Analysis.query.get(analysis_id)

        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        if analysis.user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403

        if analysis.file_path:
            from app.services import storage
            storage.delete(analysis.file_path)

        db.session.delete(analysis)
        db.session.commit()

        return jsonify({'message': 'Analysis deleted successfully'}), 200

    except Exception as exc:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete analysis: {str(exc)}'}), 500


@analysis_bp.route('/<int:analysis_id>/report.pdf', methods=['GET'])
def download_pdf_report(analysis_id):
    import traceback
    try:
        from app.services.report_generator import build_pdf

        # Auth is optional — guests can download their own reports,
        # but logged-in users can only download their own analyses.
        user_id = None
        try:
            verify_jwt_in_request(optional=True)
            _raw_uid = get_jwt_identity()
            user_id = int(_raw_uid) if _raw_uid is not None else None
        except Exception:
            pass

        analysis = Analysis.query.get(analysis_id)

        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        if analysis.user_id is not None and analysis.user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403

        pdf_bytes = build_pdf(analysis)

        # Guard against silent failures producing empty/invalid output
        if not pdf_bytes or not pdf_bytes.startswith(b'%PDF-'):
            current_app.logger.error(
                f'PDF generation returned invalid output for analysis {analysis_id}'
            )
            return jsonify({'error': 'PDF generation produced invalid output. Check server logs.'}), 500

        filename = (
            f"sandbug-url-report-{analysis_id}.pdf"
            if analysis.file_type == 'URL'
            else f"sandbug-{(analysis.filename or 'report').replace(' ', '_')}-{analysis_id}.pdf"
        )

        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(pdf_bytes)),
            }
        )

    except RuntimeError as exc:
        current_app.logger.error(f'PDF RuntimeError for {analysis_id}: {exc}')
        return jsonify({'error': str(exc)}), 501
    except Exception as exc:
        current_app.logger.error(
            f'PDF generation failed for analysis {analysis_id}:\n{traceback.format_exc()}'
        )
        return jsonify({'error': f'Failed to generate PDF: {str(exc)}'}), 500


@analysis_bp.route('/<int:analysis_id>/report.json', methods=['GET'])
def download_json_report(analysis_id):
    import json as _json
    try:
        user_id = None
        try:
            verify_jwt_in_request(optional=True)
            _raw_uid = get_jwt_identity()
            user_id = int(_raw_uid) if _raw_uid is not None else None
        except Exception:
            pass

        analysis = Analysis.query.get(analysis_id)
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        if analysis.user_id is not None and analysis.user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403

        data = _json.dumps(analysis.to_dict(include_results=True), indent=2, default=str)
        filename = (
            f"sandbug-url-report-{analysis_id}.json"
            if analysis.file_type == 'URL'
            else f"sandbug-{(analysis.filename or 'report').replace(' ', '_')}-{analysis_id}.json"
        )
        return Response(
            data.encode('utf-8'),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(data.encode('utf-8'))),
            }
        )
    except Exception as exc:
        return jsonify({'error': f'Failed to generate JSON report: {str(exc)}'}), 500


@analysis_bp.route('/<int:analysis_id>/report.html', methods=['GET'])
def download_html_report(analysis_id):
    try:
        from app.services.report_generator import build_html

        user_id = None
        try:
            verify_jwt_in_request(optional=True)
            _raw_uid = get_jwt_identity()
            user_id = int(_raw_uid) if _raw_uid is not None else None
        except Exception:
            pass

        analysis = Analysis.query.get(analysis_id)
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        if analysis.user_id is not None and analysis.user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403

        html = build_html(analysis)
        filename = (
            f"sandbug-url-report-{analysis_id}.html"
            if analysis.file_type == 'URL'
            else f"sandbug-{(analysis.filename or 'report').replace(' ', '_')}-{analysis_id}.html"
        )
        return Response(
            html.encode('utf-8'),
            mimetype='text/html',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(html.encode('utf-8'))),
            }
        )
    except Exception as exc:
        return jsonify({'error': f'Failed to generate HTML report: {str(exc)}'}), 500
