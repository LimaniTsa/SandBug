import React, { useMemo, useState } from 'react';
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell,
  PieChart, Pie, ResponsiveContainer, Legend,
  ReferenceLine,
} from 'recharts';
import {
  Sparkles, ShieldAlert, Activity, FileSearch, Network, AlertTriangle,
  Hash, Cpu, Shield, Info, CheckCircle, Globe, Terminal, HardDrive,
  Key, Lock, Tag, Download, ChevronDown, ChevronUp, FileCode,
  Link, ShieldCheck, ShieldX, ArrowRight, Clock,
} from 'lucide-react';
import { ReportFormat } from '../../utils/generateReport';
import './AnalysisOverview.css';

//Types
interface YaraRule { rule: string; tags?: string[]; meta?: { severity?: string; description?: string } }
interface Section  { name: string; virtual_size?: number; raw_size?: number; entropy: number; suspicious?: string }
interface Import   { dll: string; functions: string[] }
interface StaticData {
  risk_score?: number;
  entropy?: { overall: number; interpretation?: string };
  sections?: Section[];
  imports?: Import[];
  yara?: { matched: boolean; rules: YaraRule[] };
  suspicious_indicators?: string[];
  signature?: { status: string; valid: boolean; publisher: string | null };
  file_info?: { filename?: string; size?: number; md5?: string; sha256?: string; file_type?: string };
  filename?: string; file_size?: number; file_type?: string; file_hash?: string; md5?: string; sha256?: string;
  // URL analysis fields (stored in static_analysis when file_type === 'URL')
  url?: string;
  hostname?: string;
  ip?: string;
  ssl?: { valid: boolean; expiry?: string; days_remaining?: number; error?: string };
  redirects?: { chain: string[]; final_url: string; redirects: number; status_code?: number; error?: string };
  heuristics?: { score: number; indicators: string[] };
  safe_browsing?: { checked: boolean; flagged?: boolean; threats?: string[]; reason?: string; error?: string };
  ip_reputation?: { checked: boolean; abuse_score?: number; total_reports?: number; country?: string; isp?: string; is_tor?: boolean; reason?: string; error?: string };
  ip_grabber?: { detected: boolean; confidence: string; score: number; reasons: string[]; matched_domain: string | null };
}
interface DynSig  { name: string; score: number; tags: string[]; description: string }
interface DynNet  { domains: {domain:string;ip:string}[]; hosts: string[]; http_requests: {method:string;url:string;status:number}[]; dns_requests: {query:string;type:string}[] }
interface DynProc { name: string; pid: number; cmd: string; injected: boolean; signatures: string[] }
interface DynFile { name: string; md5: string; sha256: string; type: string; size: number }
interface DynReg  { key: string; op: string; value: string }
interface TriageData {
  triage_score?: number; sample_id?: string; report_url?: string; tags?: string[];
  signatures?: DynSig[]; network?: DynNet; processes?: DynProc[];
  dropped_files?: DynFile[]; registry?: DynReg[]; mutexes?: string[]; errors?: string[];
}
interface HaData {
  ha_score?: number; verdict?: string; report_url?: string; tags?: string[];
  signatures?: { name: string; threat_level: number; description: string }[];
  network?: { domains: {domain:string}[]; hosts: string[]; http_requests: {method:string;url:string;status:number}[] };
  processes?: { name: string; pid: number; cmd: string }[];
}
interface DynamicData {
  triage?:          TriageData | null;
  hybrid_analysis?: HaData    | null;
}
interface ThreatIntel {
  found:      boolean;
  source:     string;
  tags?:      string[];
  signature?: string | null;
  file_type?: string | null;
  first_seen?: string | null;
  reporter?:  string | null;
  mb_url?:    string | null;
}
interface Props {
  staticData:  StaticData | null;
  dynamicData: DynamicData | null;
  filename:    string;
  fileSize:    number;
  fileType:    string;
  fileHash:    string;
  riskLevel:    string;
  riskScore?:   number;
  dynamicError?: string | null;
  aiSummary?:   string | null;
  threatIntel?: ThreatIntel | null;
  onDownload?:  (format: ReportFormat) => Promise<void>;
}

//Helpers

const RISK: Record<string,string> = { low:'#10b981', medium:'#f59e0b', high:'#f97316', critical:'#ef4444', unknown:'#9ca3af' };
const RISK_LABEL: Record<string,string> = { low:'Low Risk', medium:'Medium Risk', high:'High Risk', critical:'Critical Risk', unknown:'Unknown' };
const ec   = (e:number) => e > 7 ? '#ef4444' : e > 6 ? '#f97316' : '#10b981';
const sc   = (s:number) => s >= 75 ? '#ef4444' : s >= 50 ? '#f97316' : s >= 25 ? '#f59e0b' : '#10b981';
const sigc = (s:number) => s >= 7  ? '#ef4444' : s >= 4  ? '#f97316' : '#f59e0b';
const fmt  = (b:number) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b/1024).toFixed(1)} KB` : `${(b/1048576).toFixed(1)} MB`;

//Small reusable pieces
const SevBadge: React.FC<{sev:string}> = ({sev}) => (
  <span className={`ov-sev ov-sev-${sev.toLowerCase()}`}>{sev.toUpperCase()}</span>
);

const Expandable: React.FC<{label:string; count:number; accent?:string; children:React.ReactNode}> = 
({ label, count, accent, children }) => {
  const [open, setOpen] = useState(false);
  return (
    <div className="ov-expandable" style={accent ? {'--exp-accent':accent} as React.CSSProperties : undefined}>
      <button className="ov-expandable-btn" onClick={() => setOpen(o => !o)}>
        <span>{label} <span className="ov-exp-count">({count})</span></span>
        {open ? <ChevronUp size={14}/> : <ChevronDown size={14}/>}
      </button>
      {open && <div className="ov-expandable-body">{children}</div>}
    </div>
  );
};

const HoverTip: React.FC<{text: string}> = ({ text }) => (
  <span className="ov-hovertip">
    <Info size={12} className="ov-hovertip-icon"/>
    <span className="ov-hovertip-bubble">{text}</span>
  </span>
);

const TTip: React.FC<any> = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const v = payload[0].value as number;
  return (
    <div className="ov-tooltip">
      <p className="ov-tt-label">{label}</p>
      <p className="ov-tt-val" style={{color:ec(v)}}>Entropy: <strong>{v}</strong></p>
      <p className="ov-tt-hint">{v>7?'⚠ Likely packed':v>6?'Possibly compressed':'Normal'}</p>
    </div>
  );
};

const ImportTTip: React.FC<any> = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="ov-tooltip">
      <p className="ov-tt-label">{label}</p>
      <p className="ov-tt-val">{payload[0].value} functions</p>
    </div>
  );
};


// AI Summary Card 
const AiSummaryCard: React.FC<{summary?: string | null}> = ({ summary }) => (
  <div className="ov-card ov-ai-card">
    <div className="ov-card-header">
      <div className="ov-ai-icon"><Sparkles size={16}/></div>
      <span>AI Summary</span>
      <span className="ov-ai-sub-label">Powered by Claude Haiku</span>
    </div>
    <div className="ov-card-body ov-ai-body">
      {summary ? (
        <p className="ov-ai-text">{summary}</p>
      ) : (
        <div className="ov-ai-note">
          <Sparkles size={13}/>
          Add <code>ANTHROPIC_API_KEY</code> to your <code>.env</code> to enable AI summaries.
        </div>
      )}
    </div>
  </div>
);

//URL Results
const CheckRow: React.FC<{label: string; ok: boolean | null; detail?: string; icon?: React.ReactNode}> =
({ label, ok, detail, icon }) => (
  <div className="url-check-row">
    <div className="url-check-left">
      <span className={`url-check-dot ${ok === true ? 'dot-ok' : ok === false ? 'dot-bad' : 'dot-na'}`}/>
      {icon}
      <span className="url-check-label">{label}</span>
    </div>
    <div className="url-check-right">
      {ok === true  && <span className="url-badge url-badge-ok"><CheckCircle size={12}/> Pass</span>}
      {ok === false && <span className="url-badge url-badge-bad"><ShieldX size={12}/> Fail</span>}
      {ok === null  && <span className="url-badge url-badge-na">N/A</span>}
      {detail && <span className="url-check-detail">{detail}</span>}
    </div>
  </div>
);

const UrlResults: React.FC<{u: StaticData; riskLevel: string; url: string; aiSummary?: string | null}> = ({ u, riskLevel, url, aiSummary }) => {
  const riskColor = RISK[riskLevel] ?? RISK.unknown;
  const ssl       = u.ssl;
  const redir     = u.redirects;
  const heur      = u.heuristics;
  const sb        = u.safe_browsing;
  const ipr       = u.ip_reputation;

  const radarData = [
    { axis: 'Heuristics', value: heur?.score ?? 0 },
    { axis: 'SSL',        value: ssl?.valid ? 0 : 30 },
    { axis: 'Redirects',  value: Math.min((redir?.redirects ?? 0) * 15, 100) },
    { axis: 'Reputation', value: ipr?.checked ? Math.min((ipr.abuse_score ?? 0), 100) : 0 },
    { axis: 'Threat DB',  value: sb?.flagged ? 100 : 0 },
    { axis: 'IP Grabber', value: u.ip_grabber?.score ?? 0 },
  ];

  const indicators  = heur?.indicators ?? [];
  const chain       = redir?.chain ?? [];
  const heurScore   = heur?.score ?? 0;
  const score       = u.risk_score ?? heurScore;

  return (
    <div className="ov-root">

      {/* ── Header: URL + Risk ── */}
      <div className="ov-card ov-header-card" style={{'--risk-color': riskColor} as React.CSSProperties}>
        <div className="ov-header-left">
          <div className="ov-header-section-title"><Globe size={15}/><span>URL Analysis</span></div>
          <div className="ov-file-grid">
            <div className="ov-file-field ov-file-field-full">
              <span className="ov-field-label">URL</span>
              <span className="ov-field-value ov-mono ov-small">{url}</span>
            </div>
            <div className="ov-file-field">
              <span className="ov-field-label">Hostname</span>
              <span className="ov-field-value ov-mono ov-small">{u.hostname ?? '—'}</span>
            </div>
            <div className="ov-file-field">
              <span className="ov-field-label">Resolved IP</span>
              <span className="ov-field-value ov-mono ov-small">{u.ip ?? 'Unresolved'}</span>
            </div>
            {ipr?.checked && (
              <>
                <div className="ov-file-field">
                  <span className="ov-field-label">Country</span>
                  <span className="ov-field-value">{ipr.country ?? '—'}</span>
                </div>
                <div className="ov-file-field">
                  <span className="ov-field-label">ISP</span>
                  <span className="ov-field-value ov-small">{ipr.isp ?? '—'}</span>
                </div>
              </>
            )}
          </div>
        </div>

        <div className="ov-header-divider"/>

        <div className="ov-header-right">
          <div className="ov-header-section-title"><Shield size={15}/><span>Risk Assessment</span></div>
          <div className="ov-risk-body">
            <div className="ov-risk-ring" style={{borderColor: riskColor}}>
              <span className="ov-risk-num">{score}</span>
              <span className="ov-risk-denom">/100</span>
            </div>
            <div className="ov-risk-details">
              <span className="ov-risk-label" style={{color: riskColor}}>{RISK_LABEL[riskLevel] ?? 'Unknown'}</span>
              <p className="ov-risk-desc">
                {score < 25 && 'URL shows no significant threat indicators.'}
                {score >= 25 && score < 50 && 'URL shows some suspicious characteristics.'}
                {score >= 50 && score < 75 && 'URL shows multiple threat indicators.'}
                {score >= 75 && 'URL is highly suspicious or confirmed malicious.'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ── AI Summary ── */}
      <AiSummaryCard summary={aiSummary} />

      {/* ── Stat cards ── */}
      <div className="ov-stat-grid">

        {/* SSL */}
        <div className="ov-stat-card" style={{'--accent': ssl?.valid ? '#10b981' : '#ef4444'} as React.CSSProperties}>
          <div className="ov-stat-header">
            {ssl?.valid ? <ShieldCheck size={18}/> : <ShieldX size={18}/>}
            <span className="ov-stat-label">SSL Certificate</span>
          </div>
          <span className="ov-stat-big" style={{color: ssl?.valid ? '#10b981' : '#ef4444', fontSize: '1.3rem'}}>
            {ssl?.valid ? 'Valid' : 'Invalid'}
          </span>
          <span className="ov-stat-sub">
            {ssl?.valid
              ? `Expires ${ssl.expiry ?? '—'} · ${ssl.days_remaining ?? '?'} days remaining`
              : ssl?.error ?? 'Certificate check failed'}
          </span>
          {ssl?.valid && ssl.days_remaining !== undefined && ssl.days_remaining < 30 && (
            <div className="ov-exp-item ov-exp-warn" style={{marginTop:'0.5rem'}}>
              <AlertTriangle size={12}/><span className="ov-small">Expiring soon — {ssl.days_remaining} days</span>
            </div>
          )}
        </div>

        {/* Redirects */}
        <div className="ov-stat-card" style={{'--accent': (redir?.redirects ?? 0) > 3 ? '#f97316' : '#10b981'} as React.CSSProperties}>
          <div className="ov-stat-header">
            <ArrowRight size={18}/>
            <span className="ov-stat-label">Redirects</span>
          </div>
          <span className="ov-stat-big" style={{color: (redir?.redirects ?? 0) > 3 ? '#f97316' : 'var(--text-primary)'}}>
            {redir?.redirects ?? 0}
          </span>
          <span className="ov-stat-sub">
            {redir?.error ? redir.error : redir?.final_url ? `Final: ${redir.final_url}` : 'No redirects'}
          </span>
          {chain.length > 1 && (
            <Expandable label="View chain" count={chain.length} accent="#6366f1">
              {chain.map((c, i) => (
                <div key={i} className="url-chain-item">
                  {i > 0 && <ArrowRight size={11} className="ov-muted"/>}
                  <span className="ov-mono ov-small url-chain-url">{c}</span>
                </div>
              ))}
            </Expandable>
          )}
        </div>

        {/* Heuristics */}
        <div className="ov-stat-card" style={{'--accent': sc(heur?.score ?? 0)} as React.CSSProperties}>
          <div className="ov-stat-header">
            <AlertTriangle size={18}/>
            <span className="ov-stat-label">Heuristic Score</span>
            <HoverTip text="A score based on pattern matching against known phishing and malware delivery techniques. Higher values mean more suspicious URL characteristics were found." />
          </div>
          <span className="ov-stat-big" style={{color: sc(heur?.score ?? 0)}}>
            {heur?.score ?? 0}<span className="ov-stat-denom">/100</span>
          </span>
          <span className="ov-stat-sub">{indicators.length} suspicious pattern{indicators.length !== 1 ? 's' : ''} detected</span>
          {indicators.length > 0 && (
            <Expandable label="View patterns" count={indicators.length} accent={sc(heur?.score ?? 0)}>
              {indicators.map((ind, i) => (
                <div key={i} className="ov-exp-item ov-exp-warn">
                  <AlertTriangle size={11}/><span className="ov-small">{ind}</span>
                </div>
              ))}
            </Expandable>
          )}
        </div>

        {/* Safe Browsing */}
        <div className="ov-stat-card" style={{'--accent': sb?.flagged ? '#ef4444' : '#10b981'} as React.CSSProperties}>
          <div className="ov-stat-header">
            <Shield size={18}/>
            <span className="ov-stat-label">Threat Database</span>
          </div>
          <span className="ov-stat-big" style={{color: sb?.flagged ? '#ef4444' : sb?.checked ? '#10b981' : '#9ca3af', fontSize: '1.15rem'}}>
            {!sb?.checked ? 'Not checked' : sb.flagged ? 'Flagged' : 'Clean'}
          </span>
          <span className="ov-stat-sub">
            {!sb?.checked
              ? (sb?.reason ?? 'Google Safe Browsing API key not configured')
              : sb.flagged
              ? `Threats: ${(sb.threats ?? []).join(', ')}`
              : 'Not listed in Google Safe Browsing'}
          </span>
        </div>

        {/* IP Reputation */}
        <div className="ov-stat-card" style={{'--accent': ipr?.checked && (ipr.abuse_score ?? 0) > 50 ? '#ef4444' : '#9ca3af'} as React.CSSProperties}>
          <div className="ov-stat-header">
            <Network size={18}/>
            <span className="ov-stat-label">IP Reputation</span>
            <HoverTip text="Checks the server's IP address against AbuseIPDB, a database of IPs reported for malicious activity. The abuse score is the percentage of reporters who flagged this IP." />
          </div>
          {ipr?.checked ? (
            <>
              <span className="ov-stat-big" style={{color: sc(ipr.abuse_score ?? 0)}}>
                {ipr.abuse_score ?? 0}<span className="ov-stat-denom">%</span>
              </span>
              <span className="ov-stat-sub">
                {ipr.total_reports ?? 0} abuse report{(ipr.total_reports ?? 0) !== 1 ? 's' : ''}
                {ipr.is_tor ? ' · TOR exit node' : ''}
              </span>
            </>
          ) : (
            <>
              <span className="ov-stat-big" style={{color: '#9ca3af', fontSize: '1.15rem'}}>Not checked</span>
              <span className="ov-stat-sub">{ipr?.reason ?? 'AbuseIPDB API key not configured'}</span>
            </>
          )}
        </div>

        {/* IP Grabber Detection */}
        {(() => {
          const g = u.ip_grabber;
          if (!g) {
            return (
              <div className="ov-stat-card" style={{'--accent': '#10b981'} as React.CSSProperties}>
                <div className="ov-stat-header">
                  <Globe size={18}/>
                  <span className="ov-stat-label">IP Grabber</span>
                  <HoverTip text="A service that silently logs the IP address of anyone who visits a link. Often disguised as normal URLs, they are used for tracking or doxxing." />
                </div>
                <span className="ov-stat-big" style={{color: '#10b981', fontSize: '1.15rem'}}>Clean</span>
                <span className="ov-stat-sub">No grabber indicators found</span>
              </div>
            );
          }
          const accentColor =
            g.confidence === 'confirmed' ? '#ef4444' :
            g.confidence === 'likely'    ? '#f97316' :
            g.confidence === 'possible'  ? '#f59e0b' : '#10b981';
          return (
            <div className="ov-stat-card" style={{'--accent': accentColor} as React.CSSProperties}>
              <div className="ov-stat-header">
                <Globe size={18}/>
                <span className="ov-stat-label">IP Grabber</span>
                <HoverTip text="A service that silently logs the IP address of anyone who visits a link. Often disguised as normal URLs, they are used for tracking or doxxing." />
              </div>
              <span className="ov-stat-big" style={{color: accentColor, fontSize: '1.15rem', textTransform: 'capitalize'}}>
                {g.confidence}
              </span>
              <span className="ov-stat-sub">
                {g.detected
                  ? g.matched_domain
                    ? `Known service: ${g.matched_domain}`
                    : `${g.reasons.length} indicator${g.reasons.length !== 1 ? 's' : ''} detected`
                  : 'No IP grabber indicators found'}
              </span>
              {g.reasons.length > 0 && (
                <Expandable label="View reasons" count={g.reasons.length} accent={accentColor}>
                  {g.reasons.map((r, i) => (
                    <div key={i} className="ov-exp-item ov-exp-warn">
                      <AlertTriangle size={11}/><span className="ov-small">{r}</span>
                    </div>
                  ))}
                </Expandable>
              )}
            </div>
          );
        })()}
      </div>

      {/* ── Checks summary card ── */}
      <div className="ov-card">
        <div className="ov-card-header"><ShieldCheck size={16}/><span>Security Checks</span></div>
        <div className="ov-card-body url-checks-grid">
          <CheckRow label="HTTPS Protocol"        ok={url.startsWith('https')}  detail={url.startsWith('https') ? 'Encrypted connection' : 'Plain HTTP — no encryption'} icon={<Lock size={13}/>}/>
          <CheckRow label="SSL Certificate"       ok={ssl?.valid ?? null}        detail={ssl?.valid ? `Valid until ${ssl.expiry}` : ssl?.error} icon={<ShieldCheck size={13}/>}/>
          <CheckRow label="Excessive Redirects"   ok={(redir?.redirects ?? 0) <= 3} detail={`${redir?.redirects ?? 0} redirect${(redir?.redirects ?? 0) !== 1 ? 's' : ''}`} icon={<ArrowRight size={13}/>}/>
          <CheckRow label="Google Safe Browsing"  ok={sb?.checked ? !sb.flagged : null} detail={sb?.checked ? (sb.flagged ? (sb.threats ?? []).join(', ') : 'Not flagged') : 'API key not configured'} icon={<Shield size={13}/>}/>
          <CheckRow label="IP Abuse Score"        ok={ipr?.checked ? (ipr.abuse_score ?? 0) < 50 : null} detail={ipr?.checked ? `${ipr.abuse_score}% confidence` : 'API key not configured'} icon={<Network size={13}/>}/>
          <CheckRow label="TOR Exit Node"         ok={ipr?.checked ? !ipr.is_tor : null} detail={ipr?.is_tor ? 'Traffic routed via TOR' : 'Not a TOR exit node'} icon={<Globe size={13}/>}/>
          <CheckRow label="Heuristic Patterns"    ok={(heur?.indicators.length ?? 0) === 0} detail={`${heur?.indicators.length ?? 0} suspicious pattern${(heur?.indicators.length ?? 0) !== 1 ? 's' : ''} found`} icon={<AlertTriangle size={13}/>}/>
          <CheckRow label="Raw IP as Host"        ok={!/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname ?? '')} detail="Domains are more trustworthy than raw IPs" icon={<Hash size={13}/>}/>
          <CheckRow
            label="IP Grabber / Logger"
            ok={!u.ip_grabber?.detected}
            detail={
              u.ip_grabber?.detected
                ? u.ip_grabber.matched_domain
                  ? `Known grabber: ${u.ip_grabber.matched_domain}`
                  : `Confidence: ${u.ip_grabber.confidence}`
                : 'No grabber signatures detected'
            }
            icon={<Globe size={13}/>}
          />
        </div>
      </div>

      {/* ── Chart: Risk radar ── */}
      <div className="ov-charts-grid">
        <div className="ov-chart-card">
          <h3 className="ov-chart-title">URL Risk Profile</h3>
          <p className="ov-chart-sub">Threat dimensions across all checks</p>
          <ResponsiveContainer width="100%" height={260}>
            <RadarChart data={radarData} margin={{top:10,right:20,bottom:10,left:20}}>
              <PolarGrid stroke="var(--border)"/>
              {React.createElement(PolarAngleAxis as any, { dataKey:'axis', tick:{fontSize:12,fill:'var(--text-secondary)',fontFamily:'inherit'} })}
              {React.createElement(PolarRadiusAxis as any, {domain:[0,100],tick:false,axisLine:false})}
              <Radar name="Score" dataKey="value" stroke={riskColor} fill={riskColor} fillOpacity={0.2} strokeWidth={2}/>
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Redirect chain visual */}
        <div className="ov-chart-card">
          <h3 className="ov-chart-title">Redirect Chain</h3>
          <p className="ov-chart-sub">{chain.length > 0 ? `${redir?.redirects ?? 0} hop${(redir?.redirects ?? 0) !== 1 ? 's' : ''} to final destination` : 'No redirects detected'}</p>
          {chain.length > 0 ? (
            <div className="url-redirect-chain">
              {chain.map((c, i) => (
                <div key={i} className="url-chain-step">
                  <div className={`url-chain-node ${i === 0 ? 'node-start' : i === chain.length - 1 ? 'node-end' : 'node-mid'}`}>
                    {i === 0 ? <Link size={13}/> : i === chain.length - 1 ? <CheckCircle size={13}/> : <ArrowRight size={13}/>}
                    <span>{i === 0 ? 'Origin' : i === chain.length - 1 ? 'Final' : `Hop ${i}`}</span>
                  </div>
                  <span className="url-chain-url ov-mono ov-small">{c}</span>
                  {i < chain.length - 1 && <div className="url-chain-connector"/>}
                </div>
              ))}
            </div>
          ) : (
            <div className="ov-chart-empty url-chain-clean">
              <CheckCircle size={28} color="#10b981"/>
              <span>Direct URL — no redirects</span>
            </div>
          )}
        </div>
      </div>

    </div>
  );
};

//Main component
const DownloadButton: React.FC<{ onDownload: (format: ReportFormat) => Promise<void> }> = ({ onDownload }) => {
  const [loading, setLoading] = React.useState(false);
  const [open,    setOpen]    = React.useState(false);
  const [error,   setError]   = React.useState('');
  const handle = async (fmt: ReportFormat) => {
    setOpen(false); setLoading(true); setError('');
    try { await onDownload(fmt); }
    catch (e: any) { setError(e?.message ?? 'Download failed'); }
    finally { setLoading(false); }
  };
  return (
    <div className="ov-download-wrap">
      <div className="ov-download-split">
        <button
          className="ov-triage-btn ov-download-btn"
          disabled={loading}
          onClick={() => handle('pdf')}
        >
          {loading ? <><span className="ov-spinner" /> Downloading…</> : <><Download size={13} /> Download Report</>}
        </button>
        <button
          className="ov-triage-btn ov-download-chevron"
          disabled={loading}
          onClick={() => setOpen(o => !o)}
          aria-label="Choose format"
        >
          <ChevronDown size={13} />
        </button>
      </div>
      {open && (
        <div className="ov-download-dropdown">
          {(['pdf', 'html', 'json'] as ReportFormat[]).map(fmt => (
            <button key={fmt} className="ov-download-opt" onClick={() => handle(fmt)}>
              {fmt.toUpperCase()}
            </button>
          ))}
        </div>
      )}
      {error && <p className="ov-dl-error">{error}</p>}
    </div>
  );
};

const AnalysisOverview: React.FC<Props> = ({ staticData, dynamicData, dynamicError, filename, fileSize, fileType, fileHash, riskLevel, riskScore, aiSummary, threatIntel, onDownload }) => {

  // ── Early return for URL analysis 
  const triage = dynamicData?.triage ?? null;

  const staticScore   = staticData?.risk_score ?? 0;
  const triageScore   = (triage?.triage_score ?? 0) * 10;
  const combinedScore = riskScore ?? (dynamicData ? Math.round(staticScore * 0.4 + triageScore * 0.6) : staticScore);
  const riskColor     = RISK[riskLevel] ?? RISK.unknown;

  const yaraCount   = staticData?.yara?.rules?.length ?? 0;
  const indicCount  = staticData?.suspicious_indicators?.length ?? 0;
  const importCount = staticData?.imports?.length ?? 0;
  const sigCount    = triage?.signatures?.length ?? 0;
  const netDomains  = triage?.network?.domains?.length ?? 0;
  const netHttp     = triage?.network?.http_requests?.length ?? 0;
  const netDns      = triage?.network?.dns_requests?.length ?? 0;
  const injected    = triage?.processes?.filter(p=>p.injected).length ?? 0;
  const dropped     = triage?.dropped_files?.length ?? 0;

  // File info
  const fi           = staticData?.file_info ?? {};
  const dispFilename = fi.filename  ?? filename  ?? '—';
  const dispSize     = fi.size      ?? fileSize  ?? 0;
  const _rawType     = fi.file_type ?? fileType ?? '';
  const dispType     = (_rawType && _rawType.toLowerCase() !== 'unknown' && _rawType.toLowerCase() !== 'data')
                         ? _rawType : (fileType && fileType !== 'Unknown' ? fileType : '—');
  const dispMd5      = fi.md5       ?? staticData?.md5 ?? '—';
  const dispSha256   = fi.sha256    ?? staticData?.sha256 ?? fileHash ?? '—';

  const sections = staticData?.sections ?? [];
  const imports  = staticData?.imports  ?? [];
  const yara     = staticData?.yara;
  const inds     = staticData?.suspicious_indicators ?? [];
  const sigs     = triage?.signatures    ?? [];
  const net      = triage?.network;
  const procs    = triage?.processes     ?? [];
  const regKeys  = triage?.registry      ?? [];
  const mutexes  = triage?.mutexes       ?? [];
  const dynTags  = triage?.tags          ?? [];
  const hasNetwork = (net?.domains?.length ?? 0) + (net?.http_requests?.length ?? 0) + (net?.dns_requests?.length ?? 0) > 0;


  //Chart data 
  const radarData = useMemo(() => {
    const entropy = staticData?.entropy?.overall ?? 0;
    return [
      { axis:'Entropy',    value: Math.round((entropy/8)*100) },
      { axis:'YARA',       value: Math.min(yaraCount*20,100) },
      { axis:'Indicators', value: Math.min(indicCount*5,100) },
      { axis:'Imports',    value: Math.min(importCount*4,100) },
      { axis:'Dynamic',    value: dynamicData ? triageScore : 0 },
    ];
  }, [staticData, dynamicData, yaraCount, indicCount, importCount, triageScore]);

  const sectionData = useMemo(() =>
    (staticData?.sections ?? []).filter(s=>s.name).slice(0,10)
      .map(s => ({ name: s.name, entropy: s.entropy ?? 0 })),
    [staticData]);

  const importsBarData = useMemo(() =>
    (staticData?.imports ?? [])
      .map(i => ({ name: i.dll.replace(/\.dll$/i,''), count: i.functions.length }))
      .sort((a,b) => b.count - a.count).slice(0,8),
    [staticData]);

  const sigPieData = useMemo(() => {
    if (!triage?.signatures?.length) return [];
    const b = {high:0,medium:0,low:0};
    for (const s of triage.signatures) {
      if (s.score>=7) b.high++; else if (s.score>=4) b.medium++; else b.low++;
    }
    return [
      { name:'High (7-10)',  value:b.high,   color:'#ef4444' },
      { name:'Medium (4-6)', value:b.medium, color:'#f59e0b' },
      { name:'Low (0-3)',    value:b.low,    color:'#10b981' },
    ].filter(d=>d.value>0);
  }, [dynamicData]);

  const indicBarData = useMemo(() => {
    const cats: Record<string,number> = {};
    for (const ind of inds) {
      const k = ind.toLowerCase().includes('import') ? 'Imports'
        : ind.toLowerCase().includes('entropy') ? 'Entropy'
        : ind.toLowerCase().includes('packer') ? 'Packer'
        : ind.toLowerCase().includes('network') ? 'Network'
        : ind.toLowerCase().includes('debug') ? 'Debug'
        : ind.toLowerCase().includes('inject') ? 'Injection'
        : 'Other';
      cats[k] = (cats[k]??0)+1;
    }
    return Object.entries(cats).map(([name,count]) => ({name,count})).sort((a,b)=>b.count-a.count);
  }, [inds]);

  if (fileType === 'URL' && staticData) {
    return <UrlResults u={staticData} riskLevel={riskLevel} url={filename} aiSummary={aiSummary} />;
  }

  return (
    <div className="ov-root">
      <div className="ov-card ov-header-card" style={{'--risk-color': riskColor} as React.CSSProperties}>

        {/* Left: File Information */}
        <div className="ov-header-left">
          <div className="ov-header-section-title">
            <FileCode size={15}/>
            <span>File Information</span>
          </div>
          <div className="ov-file-grid">
            <div className="ov-file-field">
              <span className="ov-field-label">Filename</span>
              <span className="ov-field-value ov-mono">{dispFilename}</span>
            </div>
            <div className="ov-file-field">
              <span className="ov-field-label">Size</span>
              <span className="ov-field-value">{dispSize > 0 ? fmt(dispSize) : '—'}</span>
            </div>
            <div className="ov-file-field">
              <span className="ov-field-label">Type</span>
              <span className="ov-field-value">{dispType || '—'}</span>
            </div>
            <div className="ov-file-field">
              <span className="ov-field-label">MD5</span>
              <span className="ov-field-value ov-mono ov-small">{dispMd5}</span>
            </div>
            <div className="ov-file-field ov-file-field-full">
              <span className="ov-field-label">SHA256</span>
              <span className="ov-field-value ov-mono ov-small">{dispSha256}</span>
            </div>
            {staticData?.signature && (
              <div className="ov-file-field ov-file-field-full">
                <span className="ov-field-label">Signature</span>
                <span className="ov-field-value ov-sig-field">
                  {staticData.signature.valid ? (
                    <span className="ov-sig-badge ov-sig-valid">
                      <CheckCircle size={12}/> Verified
                    </span>
                  ) : staticData.signature.status === 'NotSigned' ? (
                    <span className="ov-sig-badge ov-sig-unsigned">Unsigned</span>
                  ) : (
                    <span className="ov-sig-badge ov-sig-invalid">
                      <Info size={12}/> {staticData.signature.status}
                    </span>
                  )}
                  {staticData.signature.publisher && (
                    <span className="ov-sig-publisher">{staticData.signature.publisher}</span>
                  )}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Divider */}
        <div className="ov-header-divider"/>

        {/* Right: Risk Assessment */}
        <div className="ov-header-right">
          <div className="ov-header-section-title">
            <Shield size={15}/>
            <span>Risk Assessment</span>
          </div>
          <div className="ov-risk-body">
            <div className="ov-risk-ring" style={{borderColor: riskColor}}>
              <span className="ov-risk-num">{combinedScore}</span>
              <span className="ov-risk-denom">/100</span>
            </div>
            <div className="ov-risk-details">
              <span className="ov-risk-label" style={{color: riskColor}}>
                {RISK_LABEL[riskLevel] ?? 'Unknown'}
              </span>
              <p className="ov-risk-desc">
                {combinedScore < 25 && 'File shows minimal suspicious indicators.'}
                {combinedScore >= 25 && combinedScore < 50 && 'File shows some suspicious characteristics.'}
                {combinedScore >= 50 && combinedScore < 75 && 'File shows multiple suspicious indicators.'}
                {combinedScore >= 75 && 'File shows severe malicious indicators.'}
              </p>
              {onDownload && <DownloadButton onDownload={onDownload} />}
            </div>
          </div>
        </div>
      </div>

      {/*MalwareBazaar hit banner  */}
      {threatIntel?.found && (
        <div className="ov-mb-banner">
          <div className="ov-mb-banner-left">
            <ShieldAlert size={18} className="ov-mb-icon" />
            <div>
              <span className="ov-mb-title">Confirmed Malware — MalwareBazaar</span>
              <span className="ov-mb-sub">
                This file is a known malware sample in the abuse.ch database.
                {threatIntel.signature && <> Family: <strong>{threatIntel.signature}</strong>.</>}
                {threatIntel.first_seen && <> First seen: <strong>{threatIntel.first_seen.split(' ')[0]}</strong>.</>}
              </span>
            </div>
          </div>
          <div className="ov-mb-banner-right">
            {threatIntel.tags && threatIntel.tags.length > 0 && (
              <div className="ov-mb-tags">
                {threatIntel.tags.slice(0, 5).map(t => (
                  <span key={t} className="ov-mb-tag">{t}</span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/*AI Summary*/}
      <AiSummaryCard summary={aiSummary} />

      {/* Stat cards */}
      <div className="ov-stat-grid">

        {/* YARA */}
        <div className="ov-stat-card" style={{'--accent': yaraCount > 0 ? '#ef4444' : '#10b981'} as React.CSSProperties}>
          <div className="ov-stat-header">
            <ShieldAlert size={18}/>
            <span className="ov-stat-label">YARA Matches</span>
            <HoverTip text="YARA rules are patterns used to identify malware by matching known code signatures or strings inside a file. A match means the file triggered a known threat signature." />
          </div>
          <span className="ov-stat-big" style={{color: yaraCount > 0 ? '#ef4444' : '#10b981'}}>
            {yaraCount}
          </span>
          <span className="ov-stat-sub">{yaraCount > 0 ? 'Signatures matched' : 'No signatures matched'}</span>
          {yaraCount > 0 && (
            <Expandable label="View matches" count={yaraCount} accent="#ef4444">
              {(yara?.rules ?? []).map((r,i) => (
                <div key={i} className="ov-exp-item ov-exp-danger">
                  <div className="ov-exp-row">
                    <Shield size={12}/>
                    <strong className="ov-mono">{r.rule}</strong>
                    {r.meta?.severity && <SevBadge sev={r.meta.severity}/>}
                  </div>
                  {r.meta?.description && <p className="ov-exp-desc">{r.meta.description}</p>}
                </div>
              ))}
            </Expandable>
          )}
        </div>

        {/* Suspicious Indicators */}
        <div className="ov-stat-card" style={{'--accent': sc(indicCount*5)} as React.CSSProperties}>
          <div className="ov-stat-header">
            <AlertTriangle size={18}/>
            <span className="ov-stat-label">Suspicious Indicators</span>
            <HoverTip text="Properties of the file that are commonly associated with malware — such as unusual imports, obfuscated strings, or missing metadata. More indicators means higher suspicion." />
          </div>
          <span className="ov-stat-big" style={{color: sc(indicCount*5)}}>{indicCount}</span>
          <span className="ov-stat-sub">Static analysis</span>
          {indicCount > 0 && (
            <Expandable label="View indicators" count={indicCount} accent={sc(indicCount*5)}>
              {inds.slice(0,20).map((ind,i) => (
                <div key={i} className="ov-exp-item ov-exp-warn">
                  <AlertTriangle size={11}/>
                  <span className="ov-mono ov-small">{ind}</span>
                </div>
              ))}
              {inds.length > 20 && <p className="ov-exp-more">+{inds.length-20} more</p>}
            </Expandable>
          )}
        </div>

        {/* File Entropy */}
        <div className="ov-stat-card" style={{'--accent': ec(staticData?.entropy?.overall ?? 0)} as React.CSSProperties}>
          <div className="ov-stat-header">
            <Hash size={18}/>
            <span className="ov-stat-label">File Entropy</span>
            <HoverTip text="A measure of randomness in the file's data, scored 0–8. Values above 7.0 suggest the file may be packed, compressed, or encrypted — techniques commonly used by malware to hide itself." />
          </div>
          <span className="ov-stat-big" style={{color: ec(staticData?.entropy?.overall ?? 0)}}>
            {staticData?.entropy?.overall?.toFixed(2) ?? '—'}
          </span>
          <span className="ov-stat-sub">
            {staticData?.entropy?.overall
              ? staticData.entropy.overall > 7 ? 'Likely packed/encrypted' : 'Normal range'
              : 'Not available'}
          </span>
          {staticData?.entropy?.overall !== undefined && (
            <div className="ov-entropy-bar-wrap">
              <div className="ov-entropy-track">
                <div className="ov-entropy-fill" style={{
                  width:`${(staticData.entropy.overall/8)*100}%`,
                  background: ec(staticData.entropy.overall),
                }}/>
              </div>
              <span className="ov-entropy-max">/ 8.0</span>
            </div>
          )}
        </div>

        {/* PE Sections */}
        <div className="ov-stat-card" style={{'--accent':'var(--primary)'} as React.CSSProperties}>
          <div className="ov-stat-header">
            <FileCode size={18}/>
            <span className="ov-stat-label">PE Sections</span>
            <HoverTip text="Segments inside a Windows executable (.exe, .dll). Each section holds different content — code, data, resources. Unusual names or high entropy in a section can indicate tampering or packing." />
          </div>
          <span className="ov-stat-big" style={{color:'var(--primary)'}}>{sections.length}</span>
          <span className="ov-stat-sub">{sections.filter(s=>s.suspicious).length} suspicious</span>
          {sections.length > 0 && (
            <Expandable label="View sections" count={sections.length}>
              <div className="ov-exp-table-wrap">
                <table className="ov-exp-table">
                  <thead><tr><th>Name</th><th>Entropy</th><th>Status</th></tr></thead>
                  <tbody>
                    {sections.map((s,i) => (
                      <tr key={i}>
                        <td className="ov-mono">{s.name}</td>
                        <td>
                          <span className="ov-ent-badge"
                            style={{background:ec(s.entropy)+'18',color:ec(s.entropy)}}>
                            {s.entropy}
                          </span>
                        </td>
                        <td>{s.suspicious
                          ? <span className="ov-suspicious">{s.suspicious}</span>
                          : <CheckCircle size={13} color="#10b981"/>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Expandable>
          )}
        </div>

        {/* Imported DLLs */}
        <div className="ov-stat-card" style={{'--accent':'var(--primary)'} as React.CSSProperties}>
          <div className="ov-stat-header">
            <Cpu size={18}/>
            <span className="ov-stat-label">Imported DLLs</span>
            <HoverTip text="External libraries a program loads when it runs. Imports from network, crypto, or process-manipulation APIs can indicate the file's capabilities — and potential intent." />
          </div>
          <span className="ov-stat-big" style={{color:'var(--primary)'}}>{importCount}</span>
          <span className="ov-stat-sub">
            {imports.reduce((a,i)=>a+i.functions.length,0)} total functions
          </span>
          {imports.length > 0 && (
            <Expandable label="View imports" count={importCount}>
              {imports.slice(0,6).map((imp,i) => (
                <div key={i} className="ov-exp-import">
                  <p className="ov-exp-dll">{imp.dll}</p>
                  <div className="ov-func-wrap">
                    {imp.functions.slice(0,8).map((fn,fi) => (
                      <span key={fi} className="ov-func-chip">{fn}</span>
                    ))}
                    {imp.functions.length > 8 && (
                      <span className="ov-func-chip ov-func-more">+{imp.functions.length-8}</span>
                    )}
                  </div>
                </div>
              ))}
            </Expandable>
          )}
        </div>

        {/* Triage / Dynamic Score */}
        {dynamicData ? (
          <div className="ov-stat-card" style={{'--accent': sc(triageScore)} as React.CSSProperties}>
            <div className="ov-stat-header">
              <Activity size={18}/>
              <span className="ov-stat-label">Triage Score</span>
              <HoverTip text="A behavioural risk score (0–10) from running the file in an isolated sandbox. The file is executed and monitored — this score reflects how malicious the observed behaviour was." />
            </div>
            <span className="ov-stat-big" style={{color:sc(triageScore)}}>
              {triage?.triage_score ?? 0}<span className="ov-stat-denom">/10</span>
            </span>
            <span className="ov-stat-sub">{sigCount} behavioural signature{sigCount!==1?'s':''}</span>
            {sigs.length > 0 && (
              <Expandable label="View signatures" count={sigCount} accent={sc(triageScore)}>
                {sigs.map((sig,i) => (
                  <div key={i} className="ov-exp-item ov-exp-danger">
                    <div className="ov-exp-row">
                      <span className="ov-mono ov-bold ov-small">{sig.name}</span>
                      <span className="ov-sig-score"
                        style={{background:sigc(sig.score)+'20',color:sigc(sig.score)}}>
                        {sig.score}/10
                      </span>
                    </div>
                    {sig.description && <p className="ov-exp-desc">{sig.description}</p>}
                    {sig.tags.length > 0 && (
                      <div className="ov-tag-row">
                        {sig.tags.map((t,ti) => <span key={ti} className="ov-tag">{t}</span>)}
                      </div>
                    )}
                  </div>
                ))}
              </Expandable>
            )}
            {dynTags.length > 0 && (
              <div className="ov-tag-row" style={{marginTop:'0.5rem'}}>
                {dynTags.map((t,i) => <span key={i} className="ov-tag"><Tag size={10}/> {t}</span>)}
              </div>
            )}
          </div>
        ) : null}

        {/* Network Activity */}
        {dynamicData && (
          <div className="ov-stat-card" style={{'--accent': netDomains+netHttp > 0 ? '#f97316' : '#9ca3af'} as React.CSSProperties}>
            <div className="ov-stat-header">
              <Network size={18}/>
              <span className="ov-stat-label">Network Activity</span>
              <HoverTip text="Domains, HTTP requests, and DNS lookups made by the file while running in the sandbox. Unexpected network contact is a common sign of malware communicating with a remote server." />
            </div>
            <span className="ov-stat-big" style={{color: netDomains+netHttp > 0 ? '#f97316' : '#9ca3af'}}>
              {netDomains+netHttp+netDns}
            </span>
            <span className="ov-stat-sub">{netDomains} domains · {netHttp} HTTP · {netDns} DNS</span>
            {hasNetwork && net && (
              <Expandable label="View activity" count={netDomains+netHttp+netDns} accent="#f97316">
                {net.domains.length > 0 && (
                  <>
                    <p className="ov-exp-sub">Domains</p>
                    {net.domains.map((d,i) => (
                      <div key={i} className="ov-exp-item">
                        <Globe size={11}/>
                        <span className="ov-mono ov-small">{d.domain}</span>
                        {d.ip && <span className="ov-muted ov-small">{d.ip}</span>}
                      </div>
                    ))}
                  </>
                )}
                {net.http_requests.length > 0 && (
                  <>
                    <p className="ov-exp-sub">HTTP</p>
                    {net.http_requests.map((r,i) => (
                      <div key={i} className="ov-exp-item">
                        <span className="ov-method">{r.method}</span>
                        <span className="ov-mono ov-small ov-url">{r.url}</span>
                      </div>
                    ))}
                  </>
                )}
              </Expandable>
            )}
          </div>
        )}

        {/* Dropped Files */}
        {dynamicData && (
          <div className="ov-stat-card" style={{'--accent': injected > 0 ? '#ef4444' : dropped > 0 ? '#f59e0b' : '#9ca3af'} as React.CSSProperties}>
            <div className="ov-stat-header">
              <HardDrive size={18}/>
              <span className="ov-stat-label">Dropped Files</span>
              <HoverTip text="Files written to disk by the sample during sandbox execution. Malware often drops additional payloads, scripts, or configuration files as part of an infection chain." />
            </div>
            <span className="ov-stat-big" style={{color: injected>0?'#ef4444':dropped>0?'#f59e0b':'#9ca3af'}}>
              {dropped}
            </span>
            <span className="ov-stat-sub">
              {injected > 0 ? `⚠ ${injected} injected process${injected!==1?'es':''}` : 'No injection detected'}
            </span>
            {procs.length > 0 && (
              <Expandable label="View processes" count={procs.length}
                accent={injected>0?'#ef4444':undefined}>
                <div className="ov-exp-table-wrap">
                  <table className="ov-exp-table">
                    <thead><tr><th>PID</th><th>Name</th><th>Status</th></tr></thead>
                    <tbody>
                      {procs.map((p,i) => (
                        <tr key={i} className={p.injected?'ov-row-danger':''}>
                          <td className="ov-mono">{p.pid}</td>
                          <td className="ov-mono ov-bold">{p.name}</td>
                          <td>{p.injected
                            ? <span className="ov-suspicious">Injected</span>
                            : <CheckCircle size={13} color="#10b981"/>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Expandable>
            )}
          </div>
        )}

        {/* Registry */}
        {regKeys.length > 0 && (
          <div className="ov-stat-card" style={{'--accent':'#a78bfa'} as React.CSSProperties}>
            <div className="ov-stat-header">
              <Key size={18}/>
              <span className="ov-stat-label">Registry Operations</span>
              <HoverTip text="Changes made to the Windows registry during sandbox execution. Malware commonly modifies the registry to run automatically on startup or alter system settings." />
            </div>
            <span className="ov-stat-big" style={{color:'#a78bfa'}}>{regKeys.length}</span>
            <span className="ov-stat-sub">Keys accessed</span>
            <Expandable label="View registry" count={regKeys.length} accent="#a78bfa">
              {regKeys.map((r,i) => (
                <div key={i} className="ov-exp-item">
                  <div className="ov-exp-row">
                    <span className="ov-reg-op">{r.op}</span>
                    <span className="ov-mono ov-small">{r.key}</span>
                  </div>
                </div>
              ))}
            </Expandable>
          </div>
        )}

        {/* Mutexes */}
        {mutexes.length > 0 && (
          <div className="ov-stat-card" style={{'--accent':'#8b5cf6'} as React.CSSProperties}>
            <div className="ov-stat-header">
              <Lock size={18}/>
              <span className="ov-stat-label">Mutexes</span>
              <HoverTip text="Named objects used by programs to prevent multiple copies from running at once. Malware often creates specific mutexes as a marker — seeing one can help identify a known malware family." />
            </div>
            <span className="ov-stat-big" style={{color:'#8b5cf6'}}>{mutexes.length}</span>
            <span className="ov-stat-sub">Named synchronisation objects</span>
            <Expandable label="View mutexes" count={mutexes.length}>
              <div className="ov-func-wrap">
                {mutexes.map((m,i) => <span key={i} className="ov-func-chip ov-mono">{m}</span>)}
              </div>
            </Expandable>
          </div>
        )}
      </div>

      {/*Sandbox unavailable notice*/}
      {!dynamicData && dynamicError && (
        <div className="ov-sandbox-breakdown ov-sandbox-failed">
          <div className="ov-sb-header">
            <div className="ov-sb-title-row">
              <AlertTriangle size={16} color="#f59e0b" />
              <h3 className="ov-sb-title">Sandbox Analysis Unavailable</h3>
            </div>
          </div>
          <p className="ov-sb-empty" style={{textAlign:'left', padding:'0.25rem 0'}}>
            {dynamicError}
          </p>
          <p className="ov-sb-empty" style={{textAlign:'left', padding:'0.25rem 0', fontSize:'0.75rem'}}>
            The risk score above is based on static analysis only.
          </p>
        </div>
      )}

      {/*Sandbox breakdown */}
      {dynamicData && (
        <div className="ov-sandbox-breakdown">
          <div className="ov-sb-header">
            <div className="ov-sb-title-row">
              <Activity size={16} />
              <h3 className="ov-sb-title">Sandbox Score Breakdown</h3>
              <span className="ov-sb-score-badge" style={{color: sc(triageScore)}}>
                Triage {triage?.triage_score ?? 0}/10
              </span>
            </div>
            {triage?.report_url && (
              <a
                href={triage.report_url}
                target="_blank"
                rel="noopener noreferrer"
                className="ov-sb-link"
              >
                View full report on Triage.ge <ArrowRight size={13} />
              </a>
            )}
          </div>

          {sigs.length > 0 ? (
            <div className="ov-sb-table-wrap">
              <table className="ov-sb-table">
                <thead>
                  <tr>
                    <th>Signature</th>
                    <th style={{width:'80px'}}>Score</th>
                    <th>Description</th>
                    <th>Tags</th>
                  </tr>
                </thead>
                <tbody>
                  {sigs.map((sig, i) => (
                    <tr key={i} className={sig.score >= 7 ? 'ov-sb-row-high' : sig.score >= 4 ? 'ov-sb-row-med' : ''}>
                      <td className="ov-mono ov-bold ov-small">{sig.name}</td>
                      <td>
                        <span className="ov-sig-score" style={{background: sigc(sig.score)+'20', color: sigc(sig.score)}}>
                          {sig.score}/10
                        </span>
                      </td>
                      <td className="ov-small ov-muted">{sig.description || '—'}</td>
                      <td>
                        <div className="ov-tag-row">
                          {sig.tags.slice(0,4).map((t,ti) => <span key={ti} className="ov-tag">{t}</span>)}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="ov-sb-empty">No behavioural signatures triggered — sandbox found no malicious activity.</p>
          )}
        </div>
      )}

      {/*Visualisations */}
      <div className="ov-charts-grid">

        {/* Top-left: Risk Radar */}
        <div className="ov-chart-card">
          <h3 className="ov-chart-title">Risk Profile <HoverTip text="A spider chart showing how each analysis dimension contributes to the overall score. The further a point extends from the centre, the more threat indicators were found in that area." /></h3>
          <p className="ov-chart-sub">Normalised threat dimensions</p>
          <ResponsiveContainer width="100%" height={250}>
            <RadarChart data={radarData} margin={{top:10,right:20,bottom:10,left:20}}>
              <PolarGrid stroke="var(--border)"/>
              {React.createElement(PolarAngleAxis as any, {
                dataKey:'axis',
                tick:{fontSize:12,fill:'var(--text-secondary)',fontFamily:'inherit'},
              })}
              {React.createElement(PolarRadiusAxis as any, {domain:[0,100],tick:false,axisLine:false})}
              <Radar name="Score" dataKey="value" stroke={riskColor} fill={riskColor} fillOpacity={0.18} strokeWidth={2}/>
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/*PE Section Entropy */}
        <div className="ov-chart-card">
          <h3 className="ov-chart-title">PE Section Entropy <HoverTip text="Each bar shows how random the data is in that section of the executable. The red line at 7.0 marks the threshold — sections above it are likely packed or encrypted, which is a common malware technique." /></h3>
          <p className="ov-chart-sub">Sections above 7.0 may be packed</p>
          {sectionData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={sectionData} margin={{top:5,right:10,bottom:5,left:-20}}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false}/>
                <XAxis dataKey="name" tick={{fontSize:10,fill:'var(--text-secondary)',fontFamily:"'Courier New',monospace"}}/>
                <YAxis domain={[0,8]} tick={{fontSize:11,fill:'var(--text-secondary)'}}/>
                <Tooltip content={<TTip/>}/>
                <ReferenceLine y={7} stroke="#ef4444" strokeDasharray="4 3" strokeWidth={1.5}
                  label={{value:'7.0',fill:'#ef4444',fontSize:11}}/>
                <Bar dataKey="entropy" radius={[4,4,0,0]}>
                  {sectionData.map((_,i) => <Cell key={i} fill={ec(sectionData[i].entropy)}/>)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="ov-chart-empty">No PE sections found</div>}
        </div>

        {/* Imports by DLL */}
        <div className="ov-chart-card">
          <h3 className="ov-chart-title">Imports by DLL</h3>
          <p className="ov-chart-sub">Top DLLs by imported function count</p>
          {importsBarData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={importsBarData} layout="vertical" margin={{top:5,right:20,bottom:5,left:10}}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false}/>
                <XAxis type="number" allowDecimals={false} tick={{fontSize:11,fill:'var(--text-secondary)'}}/>
                <YAxis type="category" dataKey="name" width={80}
                  tick={{fontSize:10,fill:'var(--text-secondary)',fontFamily:"'Courier New',monospace"}}/>
                <Tooltip content={<ImportTTip/>}/>
                <Bar dataKey="count" radius={[0,4,4,0]} fill="var(--primary)" fillOpacity={0.85}/>
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="ov-chart-empty">No import data available</div>}
        </div>

        {/* Signature Severity */}
        {sigPieData.length > 0 ? (
          <div className="ov-chart-card">
            <h3 className="ov-chart-title">Signature Severity</h3>
            <p className="ov-chart-sub">{sigCount} behavioural signature{sigCount!==1?'s':''} detected</p>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={sigPieData} cx="50%" cy="50%" innerRadius={65} outerRadius={95}
                  paddingAngle={3} dataKey="value" stroke="none">
                  {sigPieData.map((e,i) => <Cell key={i} fill={e.color}/>)}
                </Pie>
                <Tooltip formatter={(v:number|undefined)=>[v??0,'Signatures']}
                  contentStyle={{background:'var(--surface)',border:'1px solid var(--border)',borderRadius:'0.5rem',fontSize:'0.85rem'}}/>
                <Legend iconType="circle" iconSize={8} wrapperStyle={{fontSize:'0.8rem',color:'var(--text-secondary)'}}/>
              </PieChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="ov-chart-card">
            <h3 className="ov-chart-title">Suspicious Indicators</h3>
            <p className="ov-chart-sub">Breakdown by category</p>
            {indicBarData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={indicBarData} margin={{top:5,right:10,bottom:5,left:-20}}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false}/>
                  <XAxis dataKey="name" tick={{fontSize:11,fill:'var(--text-secondary)'}}/>
                  <YAxis allowDecimals={false} tick={{fontSize:11,fill:'var(--text-secondary)'}}/>
                  <Tooltip contentStyle={{background:'var(--surface)',border:'1px solid var(--border)',borderRadius:'0.5rem',fontSize:'0.85rem'}}/>
                  <Bar dataKey="count" radius={[4,4,0,0]} fill="#f97316"/>
                </BarChart>
              </ResponsiveContainer>
            ) : <div className="ov-chart-empty">No indicators detected</div>}
          </div>
        )}
      </div>

    </div>
  );
};

export default AnalysisOverview;