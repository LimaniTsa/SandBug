import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload, File, AlertCircle, CheckCircle2, Loader, Info,
  Globe, Shield, Search, X, Link,
} from 'lucide-react';
import api from '../services/api';
import './Dashboard.css';

interface DashboardProps {
  isAuthenticated: boolean;
  userEmail?: string;
}

interface UploadStatus {
  status: 'idle' | 'uploading' | 'success' | 'error';
  message?: string;
  progress?: number;
}

interface UrlStatus {
  status: 'idle' | 'checking' | 'success' | 'error';
  message?: string;
}

type Tab = 'file' | 'url';

const Dashboard: React.FC<DashboardProps> = ({ isAuthenticated }) => {
  const navigate = useNavigate();

  const [activeTab, setActiveTab]       = useState<Tab>('file');
  const [dragActive, setDragActive]     = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState<UploadStatus>({ status: 'idle' });
  const [urlInput, setUrlInput]         = useState('');
  const [urlStatus, setUrlStatus]       = useState<UrlStatus>({ status: 'idle' });

  const MAX_FILE_SIZE      = 200 * 1024 * 1024;
  const ALLOWED_EXTENSIONS = ['exe', 'dll', 'pdf', 'doc', 'docx'];

  //File

  const validateFile = (file: File): { valid: boolean; error?: string } => {
    if (file.size > MAX_FILE_SIZE)
      return { valid: false, error: `File size exceeds 200MB limit. Your file is ${(file.size / 1024 / 1024).toFixed(2)}MB` };
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (!ext || !ALLOWED_EXTENSIONS.includes(ext))
      return { valid: false, error: `File type not supported. Allowed types: ${ALLOWED_EXTENSIONS.join(', ')}` };
    return { valid: true };
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    setDragActive(e.type === 'dragenter' || e.type === 'dragover');
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files?.[0]) handleFileSelect(e.dataTransfer.files[0]);
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) handleFileSelect(e.target.files[0]);
  };

  const handleFileSelect = (file: File) => {
    const v = validateFile(file);
    if (!v.valid) { setUploadStatus({ status: 'error', message: v.error }); setSelectedFile(null); return; }
    setSelectedFile(file); setUploadStatus({ status: 'idle' });
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setUploadStatus({ status: 'uploading', progress: 0 });
    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      const response = await api.post('/analysis/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (e) => {
          const progress = e.total ? Math.round((e.loaded * 100) / e.total) : 0;
          setUploadStatus({ status: 'uploading', progress });
        },
      });
      setUploadStatus({ status: 'success', message: 'File uploaded successfully! Analysis in progress...' });
      setTimeout(() => navigate(`/results/${response.data.analysis.id}`), 2000);
    } catch (err: any) {
      setUploadStatus({ status: 'error', message: err.response?.data?.error || 'Upload failed. Please try again.' });
    }
  };

  const resetUpload = () => { setSelectedFile(null); setUploadStatus({ status: 'idle' }); };

  //url
  const normaliseUrl = (raw: string): string => {
    const t = raw.trim();
    return /^https?:\/\//i.test(t) ? t : `https://${t}`;
  };

  const validateUrl = (raw: string): { valid: boolean; error?: string } => {
    try { new URL(normaliseUrl(raw)); return { valid: true }; }
    catch { return { valid: false, error: 'Please enter a valid URL (e.g. https://example.com)' }; }
  };

  const handleUrlCheck = async () => {
    const v = validateUrl(urlInput);
    if (!v.valid) { setUrlStatus({ status: 'error', message: v.error }); return; }
    setUrlStatus({ status: 'checking' });
    try {
      const response = await api.post('/analysis/url', { url: normaliseUrl(urlInput) });
      setUrlStatus({ status: 'success', message: 'Analysis complete! Redirecting to results…' });
      setTimeout(() => navigate(`/results/${response.data.analysis_id}`), 1500);
    } catch (err: any) {
      setUrlStatus({ status: 'error', message: err.response?.data?.error || 'URL check failed. Please try again.' });
    }
  };

  return (
    <div className="dashboard">
      <div className="dashboard-container">

        {/* Tabs */}
        <div className="tab-switcher">
          <button className={`tab-btn${activeTab === 'file' ? ' tab-btn-active' : ''}`} onClick={() => setActiveTab('file')}>
            <Upload size={17} /> File Analysis
          </button>
          <button className={`tab-btn${activeTab === 'url' ? ' tab-btn-active' : ''}`} onClick={() => setActiveTab('url')}>
            <Globe size={17} /> URL Check
          </button>
        </div>

        {/* Guest notice */}
        {!isAuthenticated && (
          <div className="guest-notice">
            <Info size={14} />
            <p>Results won't be saved. <a href="/register">Create an account</a> to track your analyses.</p>
          </div>
        )}

        {/* files*/}
        {activeTab === 'file' && (
          <>
            <div
              className={`upload-area${dragActive ? ' drag-active' : ''}${selectedFile ? ' has-file' : ''}`}
              onDragEnter={handleDrag} onDragLeave={handleDrag} onDragOver={handleDrag} onDrop={handleDrop}
            >
              {!selectedFile ? (
                <>
                  <Upload size={48} className="upload-icon" />
                  <h3>Drag and drop your file here</h3>
                  <p>or</p>
                  <label htmlFor="file-input" className="btn-upload">Browse Files</label>
                  <input id="file-input" type="file" onChange={handleFileInput}
                    accept={ALLOWED_EXTENSIONS.map(e => `.${e}`).join(',')} style={{ display: 'none' }} />
                  <p className="upload-info">
                    Maximum file size: 200MB<br />
                    Supported formats: {ALLOWED_EXTENSIONS.join(', ')}
                  </p>
                </>
              ) : (
                <div className="file-selected">
                  <File size={48} className="file-icon" />
                  <div className="file-info">
                    <h3>{selectedFile.name}</h3>
                    <p>{(selectedFile.size / 1024).toFixed(2)} KB</p>
                  </div>
                  {uploadStatus.status === 'idle' && (
                    <div className="file-actions">
                      <button onClick={handleUpload} className="btn-analyze">Analyse File</button>
                      <button onClick={resetUpload} className="btn-cancel">Cancel</button>
                    </div>
                  )}
                </div>
              )}
            </div>

            {uploadStatus.status !== 'idle' && (
              <div className={`status-message status-${uploadStatus.status}`}>
                {uploadStatus.status === 'uploading' && (
                  <>
                    <Loader size={20} className="spinning" />
                    <div className="status-content">
                      <span>Uploading... {uploadStatus.progress}%</span>
                      <div className="progress-bar">
                        <div className="progress-fill" style={{ width: `${uploadStatus.progress}%` }} />
                      </div>
                    </div>
                  </>
                )}
                {uploadStatus.status === 'success' && <><CheckCircle2 size={20} /><span>{uploadStatus.message}</span></>}
                {uploadStatus.status === 'error'   && <><AlertCircle size={20} /><span>{uploadStatus.message}</span></>}
              </div>
            )}
          </>
        )}

        {/*urls */}
        {activeTab === 'url' && (
          <div className="url-panel">
            <div className="url-panel-hero">
              <div className="url-hero-icon"><Shield size={26} /></div>
              <div>
                <h3>URL Threat Check</h3>
                <p>Detect phishing, malware, and malicious redirects before you visit.</p>
              </div>
            </div>

            <div className={`url-input-row${urlStatus.status === 'error' ? ' url-input-row-error' : ''}`}>
              <Link size={17} className="url-input-icon" />
              <input
                type="text"
                className="url-input"
                placeholder="https://example.com"
                value={urlInput}
                onChange={e => { setUrlInput(e.target.value); setUrlStatus({ status: 'idle' }); }}
                onKeyDown={e => e.key === 'Enter' && handleUrlCheck()}
                disabled={urlStatus.status === 'checking'}
                autoFocus
              />
              {urlInput && urlStatus.status !== 'checking' && (
                <button className="url-clear" onClick={() => { setUrlInput(''); setUrlStatus({ status: 'idle' }); }}>
                  <X size={14} />
                </button>
              )}
              <button
                className={`btn-url-check${urlStatus.status === 'checking' ? ' loading' : ''}`}
                onClick={handleUrlCheck}
                disabled={!urlInput.trim() || urlStatus.status === 'checking'}
              >
                {urlStatus.status === 'checking'
                  ? <><Loader size={15} className="spinning" /> Analysing…</>
                  : <><Search size={15} /> Check URL</>
                }
              </button>
            </div>

            {urlStatus.status === 'error' && (
              <p className="url-status-msg url-status-error"><AlertCircle size={13} /> {urlStatus.message}</p>
            )}
            {urlStatus.status === 'success' && (
              <p className="url-status-msg url-status-success"><CheckCircle2 size={13} /> {urlStatus.message}</p>
            )}

            <div className="url-checks">
              {[
                { icon: <Shield size={13} />, label: 'Domain reputation & threat intel' },
                { icon: <Globe size={13} />,  label: 'SSL certificate validation' },
                { icon: <Search size={13} />, label: 'Phishing & malware indicators' },
                { icon: <Link size={13} />,   label: 'Redirect chain analysis' },
              ].map(({ icon, label }) => (
                <div key={label} className="url-check-chip">{icon}<span>{label}</span></div>
              ))}
            </div>
          </div>
        )}

        {/* Info cards */}
        <div className="info-cards">
          <div className="info-card">
            <h4>What happens next?</h4>
            <ol>
              <li>{activeTab === 'file' ? 'Your file is uploaded securely' : 'The URL is submitted without being visited'}</li>
              <li>{activeTab === 'file' ? 'Static analysis examines file structure' : 'Domain & certificate are inspected'}</li>
              <li>{activeTab === 'file' ? 'Dynamic analysis runs in isolated environment' : 'Threat intel databases are queried'}</li>
              <li>AI generates a comprehensive report</li>
            </ol>
          </div>
          <div className="info-card">
            <h4>Privacy & Security</h4>
            <ul>
              <li>{activeTab === 'file' ? 'Files run in isolated containers' : 'URLs are checked without being visited'}</li>
              <li>All data is encrypted in transit</li>
              <li>{isAuthenticated ? 'Your analysis history is private' : 'Guest analyses are not stored permanently'}</li>
              <li>{isAuthenticated ? 'You can delete your analyses anytime' : 'Create an account to manage your history'}</li>
            </ul>
          </div>
        </div>

      </div>
    </div>
  );
};

export default Dashboard;