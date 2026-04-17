export type ReportFormat = 'pdf' | 'html' | 'json';

export async function downloadReport(
  analysis: Record<string, any>,
  format: ReportFormat = 'pdf',
): Promise<void> {
  const token   = localStorage.getItem('access_token');
  const id      = analysis.id;
  const baseUrl = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';
  const base    = analysis.file_type === 'URL'
    ? `sandbug-url-report-${id}`
    : `sandbug-${(analysis.filename ?? 'report').replace(/[^a-zA-Z0-9._-]/g, '_')}-${id}`;

  const res = await fetch(`${baseUrl}/analysis/${id}/report.${format}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error ?? `Failed to generate report (${res.status})`);
  }

  // create a temporary object url, trigger a click to open the save dialog, then clean up
  const blob = await res.blob();
  const url  = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href     = url;
  a.download = `${base}.${format}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}