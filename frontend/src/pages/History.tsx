import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  PieChart, Pie, Cell, Tooltip,
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer, CartesianGrid,
} from 'recharts';
import { Link } from 'react-router-dom';
import {
  Clock, File, Globe, Trash2, ChevronLeft, ChevronRight,
  AlertCircle, ShieldOff, RefreshCw, LogIn, Plus,
  Download, Search, X,
} from 'lucide-react';
import './History.css';

interface AnalysisSummary {
  id:           number;
  filename:     string | null;
  url:          string | null;
  file_size:    number;
  file_type:    string;
  file_hash:    string;
  risk_level:   string;
  risk_score:   number;
  status:       string;
  submitted_at: string;
  completed_at: string | null;
}

interface StatCounts {
  total:    number;
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
}

interface HistoryProps {
  isAuthenticated: boolean;
}

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';
const PER_PAGE = 10;

const fmt = (bytes: number): string => {
  if (!bytes) return '—';
  if (bytes < 1024)    return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
};

const relTime = (iso: string): string => {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60)    return 'just now';
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 604800) return `${Math.floor(s / 86400)}d ago`;
  return new Date(iso).toLocaleDateString();
};

const scoreColor = (score: number): string => {
  if (score >= 70) return '#ff2d2d';   // vivid red — critical
  if (score >= 40) return '#f97316';   // bright orange — high (clearly distinct from red)
  if (score >= 20) return '#eab308';   // yellow-amber — medium
  return '#22c55e';                    // green — low
};

const shortType = (fileType: string): string => {
  const t = (fileType || '').toLowerCase();
  if (t.includes('pdf'))                                        return 'PDF';
  if (t.includes('word') || t.includes('docx') || t.includes('doc')) return 'Word Doc';
  if (t.includes('dll'))                                        return 'DLL';
  if (t.includes('exe') || t.includes('pe') || t.includes('windows') || t.includes('executable')) return 'Windows EXE';
  return fileType || 'File';
};

const statusDot = (status: string): string => {
  if (status === 'completed')    return 'status-completed';
  if (status.includes('failed')) return 'status-failed';
  return 'status-processing';
};

const statusLabel = (status: string): string => {
  if (status === 'completed')    return 'Completed';
  if (status === 'processing')   return 'Processing';
  if (status === 'static_complete') return 'Partial';
  if (status.includes('failed')) return 'Failed';
  return status;
};

const RISK_FILTERS = ['all', 'critical', 'high', 'medium', 'low'];

// Page numbers to show 
const pageWindow = (current: number, total: number): (number | '…')[] => {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages: (number | '…')[] = [];
  const left  = Math.max(2, current - 2);
  const right = Math.min(total - 1, current + 2);
  pages.push(1);
  if (left > 2)        pages.push('…');
  for (let p = left; p <= right; p++) pages.push(p);
  if (right < total - 1) pages.push('…');
  pages.push(total);
  return pages;
};

const History: React.FC<HistoryProps> = ({ isAuthenticated }) => {
  const [analyses,   setAnalyses]   = useState<AnalysisSummary[]>([]);
  const [total,      setTotal]      = useState(0);
  const [pages,      setPages]      = useState(1);
  const [page,       setPage]       = useState(1);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState<string | null>(null);
  const [riskFilter,  setRiskFilter]  = useState('all');
  const [search,      setSearch]      = useState('');
  const [deletingId,      setDeletingId]      = useState<number | null>(null);
  const [downloadingId,   setDownloadingId]   = useState<number | null>(null);
  const [confirmDelete,   setConfirmDelete]   = useState<{ id: number; name: string } | null>(null);

  // Debounce: only fire fetchHistory 350ms after the user stops typing
  const searchDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [stats,        setStats]        = useState<StatCounts | null>(null);
  const [statsLoading, setStatsLoading] = useState(false);
  const [chartAnalyses, setChartAnalyses] = useState<AnalysisSummary[]>([]);

  const fetchStats = useCallback(async () => {
    const token = localStorage.getItem('access_token');
    if (!token) return;
    setStatsLoading(true);
    try {
      const levels = ['critical', 'high', 'medium', 'low'];
      const [totalRes, ...levelRes] = await Promise.all([
        fetch(`${API_BASE}/analysis/history?page=1&per_page=1`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
        ...levels.map(lvl =>
          fetch(`${API_BASE}/analysis/history?page=1&per_page=1&risk_level=${lvl}`, {
            headers: { Authorization: `Bearer ${token}` },
          })
        ),
      ]);

      const totalData  = await totalRes.json();
      const levelDatas = await Promise.all(levelRes.map(r => r.json()));

      setStats({
        total:    totalData.total    ?? 0,
        critical: levelDatas[0].total ?? 0,
        high:     levelDatas[1].total ?? 0,
        medium:   levelDatas[2].total ?? 0,
        low:      levelDatas[3].total ?? 0,
      });

      const chartRes = await fetch(`${API_BASE}/analysis/history?page=1&per_page=100`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const chartData = await chartRes.json();
      setChartAnalyses(chartData.analyses ?? []);
    } catch {
    } finally {
      setStatsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated) fetchStats();
    
  }, [isAuthenticated]);

  const fetchHistory = useCallback(async (p: number, risk: string, q: string) => {
    const token = localStorage.getItem('access_token');
    if (!token) return;

    setLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams({
        page:     String(p),
        per_page: String(PER_PAGE),
        ...(risk !== 'all' ? { risk_level: risk } : {}),
        ...(q.trim() ? { search: q.trim() } : {}),
      });

      const res = await fetch(`${API_BASE}/analysis/history?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.msg || `Request failed (${res.status})`);
      }

      const data = await res.json();
      setAnalyses(data.analyses ?? []);
      setTotal(data.total ?? 0);
      setPages(data.pages ?? 1);
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, []);

  // Debounced search effect — resets to page 1 on new query
  useEffect(() => {
    if (!isAuthenticated) return;
    if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current);
    searchDebounceRef.current = setTimeout(() => {
      setPage(1);
      fetchHistory(1, riskFilter, search);
    }, 350);
    return () => {
      if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  useEffect(() => {
    if (isAuthenticated) fetchHistory(page, riskFilter, search);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthenticated, page, riskFilter, fetchHistory]);

  // Refetch when tab becomes visible again
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === 'visible' && isAuthenticated) {
        fetchHistory(page, riskFilter, search);
      }
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => document.removeEventListener('visibilitychange', onVisible);
  }, [isAuthenticated, page, riskFilter, search, fetchHistory]);

  // Poll every 5 s while any row is still processing
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    const hasInProgress = analyses.some(
      a => a.status === 'processing' || a.status === 'static_complete',
    );
    if (hasInProgress && isAuthenticated) {
      pollRef.current = setInterval(() => fetchHistory(page, riskFilter, search), 5000);
    }
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [analyses, isAuthenticated, page, riskFilter, search, fetchHistory]);

  const handleDownload = async (e: React.MouseEvent, id: number, filename: string | null) => {
    e.preventDefault();
    e.stopPropagation();
    const token = localStorage.getItem('access_token');
    if (!token) return;

    setDownloadingId(id);
    try {
      const res = await fetch(`${API_BASE}/analysis/${id}/report.pdf`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `${(filename ?? `analysis-${id}`).replace(/\.[^.]+$/, '')}_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.message ?? 'Download failed');
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDelete = (e: React.MouseEvent, id: number, name: string) => {
    e.preventDefault();
    e.stopPropagation();
    setConfirmDelete({ id, name });
  };

  const confirmAndDelete = async () => {
    if (!confirmDelete) return;
    const { id } = confirmDelete;
    const token = localStorage.getItem('access_token');
    if (!token) return;

    setDeletingId(id);
    setConfirmDelete(null);
    try {
      const res = await fetch(`${API_BASE}/analysis/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.msg || 'Delete failed');
      }
      setAnalyses(prev => prev.filter(a => a.id !== id));
      setTotal(prev => prev - 1);
      setStats(prev => prev ? { ...prev, total: Math.max(0, prev.total - 1) } : prev);
    } catch (e: any) {
      setError(e.message ?? 'Delete failed');
    } finally {
      setDeletingId(null);
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="history-page">
        <div className="history-container">
          <div className="history-upsell">
            <ShieldOff size={48} color="var(--primary, #9333ea)" />
            <h2>Sign in to view your history</h2>
            <p>
              Authenticated users get a private analysis history, the ability to
              re-view past reports, and can delete their data at any time.
            </p>
            <Link to="/login" className="btn-primary">
              <LogIn size={15} /> Sign in
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const pageNums = pageWindow(page, pages);

  const riskData = useMemo(() => {
    if (!stats) return [];
    return [
      { name: 'Critical', value: stats.critical, color: '#ff2d2d' },
      { name: 'High',     value: stats.high,     color: '#f97316' },
      { name: 'Medium',   value: stats.medium,   color: '#eab308' },
      { name: 'Low',      value: stats.low,      color: '#22c55e' },
    ].filter(d => d.value > 0);
  }, [stats]);

  const activityData = useMemo(() => {
    const days = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      const label = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      const count = chartAnalyses.filter(a => a.submitted_at.startsWith(dateStr)).length;
      days.push({ date: label, count });
    }
    return days;
  }, [chartAnalyses]);

  return (
    <div className="history-page">
      <div className="history-container">

        <h1 className="history-page-title">Analysis History</h1>

        <div className="history-stats-bar">
          <div className="hstat-card hstat-total">
            <div className="hstat-label">Total</div>
            <div className="hstat-value">
              {statsLoading ? <span className="hstat-skel" /> : (stats?.total ?? '—')}
            </div>
          </div>
          <div className="hstat-card hstat-critical">
            <div className="hstat-label">Critical</div>
            <div className="hstat-value">
              {statsLoading ? <span className="hstat-skel" /> : (stats?.critical ?? '—')}
            </div>
          </div>
          <div className="hstat-card hstat-high">
            <div className="hstat-label">High</div>
            <div className="hstat-value">
              {statsLoading ? <span className="hstat-skel" /> : (stats?.high ?? '—')}
            </div>
          </div>
          <div className="hstat-card hstat-medium">
            <div className="hstat-label">Medium</div>
            <div className="hstat-value">
              {statsLoading ? <span className="hstat-skel" /> : (stats?.medium ?? '—')}
            </div>
          </div>
          <div className="hstat-card hstat-low">
            <div className="hstat-label">Low</div>
            <div className="hstat-value">
              {statsLoading ? <span className="hstat-skel" /> : (stats?.low ?? '—')}
            </div>
          </div>
        </div>

        {(riskData.length > 0 || activityData.some(d => d.count > 0)) && (
          <div className="history-charts">
            {riskData.length > 0 && (
              <div className="hchart-card">
                <h4 className="hchart-title">Risk Distribution</h4>
                <div className="hchart-donut-wrap">
                  <PieChart width={160} height={160}>
                    <Pie data={riskData} cx={80} cy={80} innerRadius={48} outerRadius={72} dataKey="value" strokeWidth={0}>
                      {riskData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                    </Pie>
                    <Tooltip formatter={(v: any, n: any) => [v, n]} />
                  </PieChart>
                  <div className="hchart-legend">
                    {riskData.map(d => (
                      <span key={d.name} className="hchart-legend-item">
                        <span className="hchart-legend-dot" style={{ background: d.color }} />
                        {d.name}: <strong>{d.value}</strong>
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}
            <div className="hchart-card hchart-card-grow">
              <h4 className="hchart-title">Submissions — Last 14 Days</h4>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={activityData} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                  <XAxis dataKey="date" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} tickLine={false} axisLine={false} interval={1} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} tickLine={false} axisLine={false} />
                  <Tooltip cursor={{ fill: 'rgba(124,58,237,0.08)' }} contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="count" name="Analyses" fill="#7c3aed" radius={[4, 4, 0, 0]} maxBarSize={28} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        <div className="history-toolbar">
          <div className="history-filters">
            {RISK_FILTERS.map(f => (
              <button
                key={f}
                className={`history-filter-btn${riskFilter === f ? ' active' : ''} hfbtn-${f}`}
                onClick={() => { setRiskFilter(f); setPage(1); }}
              >
                {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
          <div className="history-toolbar-right">
            <div className="history-search-wrap">
              <Search size={14} className="history-search-icon" />
              <input
                type="text"
                className="history-search-input"
                placeholder="Search by name or URL…"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
              {search && (
                <button className="history-search-clear" onClick={() => setSearch('')} title="Clear search">
                  <X size={13} />
                </button>
              )}
            </div>
            <button
              className="btn-icon-refresh"
              onClick={() => { fetchHistory(page, riskFilter, search); fetchStats(); }}
              disabled={loading}
              title="Refresh"
            >
              <RefreshCw size={14} className={loading ? 'spin' : ''} />
            </button>
            <Link to="/dashboard" className="btn-primary btn-new-analysis">
              <Plus size={14} /> New Analysis
            </Link>
          </div>
        </div>

        {error && (
          <div className="history-error">
            <AlertCircle size={15} />
            {error}
          </div>
        )}

        <div className="history-table-wrap">

          <div className="htable-header">
            <div className="htable-row htable-head-row">
              <div className="htcol htcol-num">#</div>
              <div className="htcol htcol-name">Name</div>
              <div className="htcol htcol-type">Type</div>
              <div className="htcol htcol-size">Size</div>
              <div className="htcol htcol-submitted">Submitted</div>
              <div className="htcol htcol-completed">Completed</div>
              <div className="htcol htcol-status">Status</div>
              <div className="htcol htcol-risk">Risk</div>
              <div className="htcol htcol-score">Score</div>
              <div className="htcol htcol-actions">Actions</div>
            </div>
          </div>

          {loading && (
            <div className="htable-body">
              {Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="htable-row htable-skeleton-row">
                  <div className="htcol htcol-num">
                    <span className="htskel htskel-sm" />
                  </div>
                  <div className="htcol htcol-name">
                    <span className="htskel htskel-lg" />
                  </div>
                  <div className="htcol htcol-type">
                    <span className="htskel htskel-md" />
                  </div>
                  <div className="htcol htcol-size">
                    <span className="htskel htskel-sm" />
                  </div>
                  <div className="htcol htcol-submitted">
                    <span className="htskel htskel-md" />
                  </div>
                  <div className="htcol htcol-completed">
                    <span className="htskel htskel-md" />
                  </div>
                  <div className="htcol htcol-status">
                    <span className="htskel htskel-md" />
                  </div>
                  <div className="htcol htcol-risk">
                    <span className="htskel htskel-sm" />
                  </div>
                  <div className="htcol htcol-score">
                    <span className="htskel htskel-sm" />
                  </div>
                  <div className="htcol htcol-actions" />
                </div>
              ))}
            </div>
          )}

          {!loading && analyses.length > 0 && (
            <div className="htable-body">
              {analyses.map((a, idx) => {
                const isUrl = a.file_type === 'URL';
                const risk  = (a.risk_level ?? 'unknown').toLowerCase();
                const rowNum = (page - 1) * PER_PAGE + idx + 1;

                return (
                  <Link
                    key={a.id}
                    to={`/results/${a.id}`}
                    className="htable-row htable-data-row"
                  >
                    <div className="htcol htcol-num">
                      <span className="ht-row-num">{rowNum}</span>
                    </div>

                    <div className="htcol htcol-name">
                      <span className={`ht-name-icon ht-icon-${isUrl ? 'url' : 'file'}`}>
                        {isUrl
                          ? <Globe size={13} />
                          : <File size={13} />
                        }
                      </span>
                      <span className="ht-name-text" title={a.filename ?? a.url ?? ''}>
                        {a.filename ?? a.url ?? '—'}
                      </span>
                    </div>

                    <div className="htcol htcol-type">
                      <span className={`ht-type-badge ht-type-${isUrl ? 'url' : 'file'}`}>
                        {isUrl ? 'URL' : shortType(a.file_type)}
                      </span>
                    </div>

                    <div className="htcol htcol-size">
                      <span className="ht-meta-text">
                        {isUrl ? '—' : fmt(a.file_size)}
                      </span>
                    </div>

                    <div className="htcol htcol-submitted">
                      <span className="ht-meta-text">
                        {relTime(a.submitted_at)}
                      </span>
                    </div>

                    <div className="htcol htcol-completed">
                      <span className="ht-meta-text">
                        {a.completed_at ? relTime(a.completed_at) : '—'}
                      </span>
                    </div>

                    <div className="htcol htcol-status">
                      <span className={`ht-status ${statusDot(a.status)}`}>
                        <span className="ht-status-dot" />
                        {statusLabel(a.status)}
                      </span>
                    </div>

                    <div className="htcol htcol-risk">
                      <span className={`hist-risk hist-risk-${risk}`}>
                        {risk}
                      </span>
                    </div>

                    <div className="htcol htcol-score">
                      <span
                        className="ht-score"
                        style={{ color: scoreColor(a.risk_score ?? 0) }}
                      >
                        {a.risk_score ?? '—'}
                      </span>
                    </div>

                    <div className="htcol htcol-actions">
                      {!isUrl
                        ? (
                          <button
                            className="hist-action-btn hist-download-btn"
                            onClick={(e) => handleDownload(e, a.id, a.filename)}
                            disabled={downloadingId === a.id || a.status !== 'completed'}
                            title="Download PDF report"
                          >
                            {downloadingId === a.id
                              ? <span className="hist-dl-spinner" />
                              : <Download size={13} />
                            }
                          </button>
                        )
                        : <span className="hist-action-spacer" />
                      }
                      <button
                        className="hist-action-btn hist-delete-btn"
                        onClick={(e) => handleDelete(e, a.id, a.filename ?? a.url ?? 'this analysis')}
                        disabled={deletingId === a.id}
                        title="Delete analysis"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}

          {!loading && analyses.length === 0 && !error && (
            <div className="history-empty">
              <Clock size={44} />
              <h3>No analyses found</h3>
              <p>
                {riskFilter !== 'all'
                  ? `No ${riskFilter} results found. Try a different filter.`
                  : 'Upload a file or scan a URL to get started.'}
              </p>
              {riskFilter === 'all' && (
                <Link to="/dashboard" className="btn-primary" style={{ marginTop: '1rem' }}>
                  <Plus size={14} /> New Analysis
                </Link>
              )}
            </div>
          )}
        </div>

        {!loading && (
          <div className="history-pagination">
            <span className="hist-page-info">
              Page {page} of {Math.max(1, pages)}
              {total > 0 && <span className="hist-total-count"> · {total} result{total !== 1 ? 's' : ''}</span>}
            </span>
            <div className="hist-page-controls">
              <button
                className="hist-page-btn"
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                title="Previous page"
              >
                <ChevronLeft size={15} />
              </button>

              {pageNums.map((p, i) =>
                p === '…' ? (
                  <span key={`ellipsis-${i}`} className="hist-page-ellipsis">…</span>
                ) : (
                  <button
                    key={p}
                    className={`hist-page-btn${page === p ? ' active' : ''}`}
                    onClick={() => setPage(p as number)}
                  >
                    {p}
                  </button>
                )
              )}

              <button
                className="hist-page-btn"
                onClick={() => setPage(p => Math.min(pages, p + 1))}
                disabled={page === pages || pages <= 1}
                title="Next page"
              >
                <ChevronRight size={15} />
              </button>
            </div>
          </div>
        )}

      </div>

      {confirmDelete && (
        <div className="del-modal-backdrop" onClick={() => setConfirmDelete(null)}>
          <div className="del-modal" onClick={e => e.stopPropagation()}>
            <div className="del-modal-icon-wrap">
              <span className="del-spark del-spark-tl">+</span>
              <span className="del-spark del-spark-tr">+</span>
              <span className="del-spark del-spark-bl">+</span>
              <div className="del-modal-icon">
                <Trash2 size={40} strokeWidth={1.6} />
              </div>
            </div>
            <h3 className="del-modal-title">Delete Analysis?</h3>
            <p className="del-modal-body">
              <strong>{confirmDelete.name}</strong> will be permanently
              deleted and cannot be recovered.
            </p>
            <div className="del-modal-actions">
              <button className="del-modal-cancel" onClick={() => setConfirmDelete(null)}>
                Cancel
              </button>
              <button className="del-modal-confirm" onClick={confirmAndDelete}>
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default History;
