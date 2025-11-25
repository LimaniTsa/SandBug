import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, File, AlertCircle, CheckCircle2, Loader, Info } from 'lucide-react';
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

const Dashboard: React.FC<DashboardProps> = ({ isAuthenticated, userEmail }) => {
  const navigate = useNavigate();
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState<UploadStatus>({ status: 'idle' });

  const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
  const ALLOWED_EXTENSIONS = ['exe', 'dll', 'pdf', 'doc', 'docx'];

  const getUserName = () => {
    if (!userEmail) return 'Guest';
    return userEmail.split('@')[0];
  };

  const validateFile = (file: File): { valid: boolean; error?: string } => {
    //check file size
    if (file.size > MAX_FILE_SIZE) {
      return {
        valid: false,
        error: `File size exceeds 50MB limit. Your file is ${(file.size / 1024 / 1024).toFixed(2)}MB`
      };
    }

    //check file extension
    const extension = file.name.split('.').pop()?.toLowerCase();
    if (!extension || !ALLOWED_EXTENSIONS.includes(extension)) {
      return {
        valid: false,
        error: `File type not supported. Allowed types: ${ALLOWED_EXTENSIONS.join(', ')}`
      };
    }

    return { valid: true };
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelect(e.target.files[0]);
    }
  };

  const handleFileSelect = (file: File) => {
    const validation = validateFile(file);
    
    if (!validation.valid) {
      setUploadStatus({
        status: 'error',
        message: validation.error
      });
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
    setUploadStatus({ status: 'idle' });
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    setUploadStatus({ status: 'uploading', progress: 0 });

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await api.post('/analysis/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          const progress = progressEvent.total
            ? Math.round((progressEvent.loaded * 100) / progressEvent.total)
            : 0;
          setUploadStatus({ status: 'uploading', progress });
        },
      });

      setUploadStatus({
        status: 'success',
        message: 'File uploaded successfully! Analysis in progress...'
      });

      //redirect to results page after 2 seconds
      setTimeout(() => {
        navigate(`/results/${response.data.analysis.id}`);
      }, 2000);

    } catch (error: any) {
      setUploadStatus({
        status: 'error',
        message: error.response?.data?.error || 'Upload failed. Please try again.'
      });
    }
  };

  const resetUpload = () => {
    setSelectedFile(null);
    setUploadStatus({ status: 'idle' });
  };

  return (
    <div className="dashboard">
      <div className="dashboard-container">
        {/* welcome banner */}
        <div className={`welcome-banner ${isAuthenticated ? 'authenticated' : 'guest'}`}>
          <div className="welcome-content">
            <h1>
              {isAuthenticated 
                ? `Welcome back, ${getUserName()}!` 
                : 'Welcome to SandBug'}
            </h1>
            <p>
              {isAuthenticated
                ? 'Upload a suspicious file to begin analysis. Your results will be saved to your history.'
                : 'Upload a suspicious file to begin analysis. Create an account to save your results.'}
            </p>
          </div>
          {!isAuthenticated && (
            <div className="guest-notice">
              <Info size={20} />
              <div>
                <strong>Guest Mode</strong>
                <p>Results won't be saved. <a href="/register">Create an account</a> to track your analyses.</p>
              </div>
            </div>
          )}
        </div>

        {/* upload area */}
        <div
          className={`upload-area ${dragActive ? 'drag-active' : ''} ${selectedFile ? 'has-file' : ''}`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          {!selectedFile ? (
            <>
              <Upload size={48} className="upload-icon" />
              <h3>Drag and drop your file here</h3>
              <p>or</p>
              <label htmlFor="file-input" className="btn-upload">
                Browse Files
              </label>
              <input
                id="file-input"
                type="file"
                onChange={handleFileInput}
                accept={ALLOWED_EXTENSIONS.map(ext => `.${ext}`).join(',')}
                style={{ display: 'none' }}
              />
              <p className="upload-info">
                Maximum file size: 50MB<br />
                Supported formats: {ALLOWED_EXTENSIONS.join(', ').toUpperCase()}
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
                  <button onClick={handleUpload} className="btn-analyze">
                    Analyse File
                  </button>
                  <button onClick={resetUpload} className="btn-cancel">
                    Cancel
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* upload status */}
        {uploadStatus.status !== 'idle' && (
          <div className={`status-message status-${uploadStatus.status}`}>
            {uploadStatus.status === 'uploading' && (
              <>
                <Loader size={20} className="spinning" />
                <div className="status-content">
                  <span>Uploading... {uploadStatus.progress}%</span>
                  <div className="progress-bar">
                    <div 
                      className="progress-fill" 
                      style={{ width: `${uploadStatus.progress}%` }}
                    />
                  </div>
                </div>
              </>
            )}
            {uploadStatus.status === 'success' && (
              <>
                <CheckCircle2 size={20} />
                <span>{uploadStatus.message}</span>
              </>
            )}
            {uploadStatus.status === 'error' && (
              <>
                <AlertCircle size={20} />
                <span>{uploadStatus.message}</span>
              </>
            )}
          </div>
        )}

        {/* info cards */}
        <div className="info-cards">
          <div className="info-card">
            <h4>What happens next?</h4>
            <ol>
              <li>Your file is uploaded securely</li>
              <li>Static analysis examines file structure</li>
              <li>Dynamic analysis runs in isolated environment</li>
              <li>AI generates comprehensive report</li>
            </ol>
          </div>
          <div className="info-card">
            <h4>Privacy & Security</h4>
            <ul>
              <li>Files are analysed in isolated containers</li>
              <li>All data is encrypted in transit</li>
              <li>{isAuthenticated ? 'Your analysis history is private' : 'Guest uploads are not stored permanently'}</li>
              <li>{isAuthenticated ? 'You can delete your analyses anytime' : 'Create an account to manage your history'}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;