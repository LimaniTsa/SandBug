import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  FileCode,
  Shield,
  AlertTriangle,
  CheckCircle,
  ChevronDown, 
  ChevronUp,
  Info
} from 'lucide-react';
import './StaticResults.css';

interface StaticResultsProps {
  analysisId: number;
}

interface FileInfo {
  filename: string;
  size: number;
  md5: string;
  sha1: string;
  sha256: string;
  file_type: string;
}

interface EntropyData {
  overall: number;
  interpretation: string;
}

interface Section {
  name: string;
  virtual_address: string;
  virtual_size: number;
  raw_size: number;
  characteristics: string;
  entropy: number;
  suspicious?: string;
}

interface Import {
  dll: string;
  functions: string[];
}

interface StaticAnalysisResults {
  file_info: FileInfo;
  pe_headers: any;
  sections: Section[];
  imports: Import[];
  exports: any[];
  entropy: EntropyData;
  strings: {
    ascii: string[];
    unicode: string[];
  };
  suspicious_indicators: string[];
  risk_score: number;
}

interface AnalysisResponse {
  analysis_id: number;
  status: string;
  risk_score: number;
  risk_level: string;
  results: StaticAnalysisResults;
}

const StaticResults: React.FC<StaticResultsProps> = ({ analysisId }) => {
  const [results, setResults] = useState<StaticAnalysisResults | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['overview']));
  const [fileName, setFileName] = useState<string>('');

  useEffect(() => {
    fetchResults();
  }, [analysisId]);

  const fetchResults = async () => {
    try {
      setLoading(true);
      setError(null);

      const token = localStorage.getItem('token');
      
      const config = token ? {
        headers: { Authorization: `Bearer ${token}` }
      } : {};

      console.log(`Fetching analysis results for ID: ${analysisId}`);

      //get the analysis record
      const analysisResponse = await axios.get<{ analysis: any }>(
        `http://localhost:5000/api/analysis/${analysisId}`,
        config
      );

      console.log('Analysis response:', analysisResponse.data);

      const analysis = analysisResponse.data.analysis;

      setFileName(
        analysis.filename ||
        analysis.static_analysis?.file_info?.filename ||
        'File'
      );

      //check if static analysis exists
      if (!analysis.static_analysis) {
        setError('Static analysis not yet performed or failed');
        setLoading(false);
        return;
      }

      const raw = analysis.static_analysis;

      const file_info = {
        filename: analysis.filename ?? raw.filename ?? "Unknown",
        size: analysis.file_size ?? raw.size ?? 0,
      file_type: analysis.file_type ?? raw.file_type ?? "Unknown",
      md5: raw.md5 ?? analysis.md5 ?? "N/A",
      sha1: raw.sha1 ?? analysis.sha1 ?? "N/A",
      sha256: raw.sha256 ?? analysis.sha256 ?? analysis.file_hash ?? "N/A"
    };

    const normalized = {
      ...raw,
      file_info,
      };

      setResults(normalized);
      setError(null);
    } catch (err: any) {
      console.error('Error fetching results:', err);
      
      if (err.response?.status === 404) {
        setError('Analysis not found');
      } else if (err.response?.status === 403) {
        setError('Access denied');
      } else if (err.response?.data?.error) {
        setError(err.response.data.error);
      } else {
        setError('Failed to load static analysis results');
      }
    } finally {
      setLoading(false);
    }
  };

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(section)) {
        newSet.delete(section);
      } else {
        newSet.add(section);
      }
      return newSet;
    });
  };

  const getRiskColor = (score: number): string => {
    if (score < 25) return '#10b981';
    if (score < 50) return '#f59e0b'; 
    if (score < 75) return '#f97316'; 
    return '#ef4444';
  };

  const getRiskLabel = (score: number): string => {
    if (score < 25) return 'Low Risk';
    if (score < 50) return 'Medium Risk';
    if (score < 75) return 'High Risk';
    return 'Critical Risk';
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / 1048576).toFixed(2)} MB`;
  };

  if (loading) {
    return (
      <div className="static-results-container">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Analysing file structure...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="static-results-container">
        <div className="error-message">
          <AlertTriangle size={24} />
          <p>{error}</p>
          <button onClick={fetchResults} className="retry-button">
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!results) return null;

  return (
    <div className="static-results-container">
      <div className="results-header">
        <FileCode size={50} />
        <h2>{fileName ? `${fileName} Results` : 'Analysis Results'}</h2>
      </div>

      <section className="result-section overview-section">
        <div className="section-header">
          <div className="section-title">
            <Shield size={20} />
            <h3>Risk Assessment</h3>
          </div>

          <div className="chevron-icon"></div>
        </div>

        <div className="section-content">
          <div className="risk-score-display">
          <div
              className="risk-score-circle"
            style={{ borderColor: getRiskColor(results.risk_score) }}
          >
              <span className="risk-score-value">{results.risk_score}</span>
              <span className="risk-score-max">/100</span>
          </div>

            <div className="risk-details">
              <h4 style={{ color: getRiskColor(results.risk_score) }}>
              {getRiskLabel(results.risk_score)}
              </h4>

              <p className="risk-description">
                {results.risk_score < 25 && 'File shows minimal suspicious indicators'}
                {results.risk_score >= 25 && results.risk_score < 50 && 'File shows some suspicious characteristics'}
                {results.risk_score >= 50 && results.risk_score < 75 && 'File shows multiple suspicious indicators'}
                {results.risk_score >= 75 && 'File shows severe malicious indicators'}
            </p>
          </div>
        </div>
      </div>
      </section>

      <section className="result-section">
        <div className="section-header" onClick={() => toggleSection('fileinfo')}>
          <div className="section-title">
          <Info size={20} />
            <h3>File Information</h3>
          </div>
          {expandedSections.has('fileinfo') ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
        </div>

        {expandedSections.has('fileinfo') && (
          <div className="section-content">
        <div className="info-grid">
          <div className="info-item">
            <span className="info-label">Filename:</span>
            <span className="info-value">{results.file_info.filename}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Size:</span>
                <span className="info-value">{formatFileSize(results.file_info.size)}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Type:</span>
            <span className="info-value">{results.file_info.file_type}</span>
          </div>
              <div className="info-item">
            <span className="info-label">MD5:</span>
                <span className="info-value hash">{results.file_info.md5}</span>
          </div>
              <div className="info-item">
            <span className="info-label">SHA256:</span>
                <span className="info-value hash">{results.file_info.sha256}</span>
          </div>
        </div>
      </div>
        )}
      </section>

      <section className="result-section">
        <div className="section-header" onClick={() => toggleSection('entropy')}>
          <div className="section-title">
            <h3>Entropy Analysis</h3>
          </div>
          {expandedSections.has('entropy') ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
        </div>

        {expandedSections.has('entropy') && (
          <div className="section-content">
            <div className="entropy-display">
          <div className="entropy-bar-container">
            <div
              className="entropy-bar"
              style={{
                width: `${(results.entropy.overall / 8) * 100}%`,
                    backgroundColor: results.entropy.overall > 7 ? '#ef4444' : '#10b981'
              }}
            />
          </div>
              <div className="entropy-info">
                <span className="entropy-value">{results.entropy.overall} / 8.0</span>
                <span className="entropy-interpretation">{results.entropy.interpretation}</span>
          </div>
        </div>
      </div>
        )}
      </section>

      {results.suspicious_indicators.length > 0 && (
        <section className="result-section">
          <div className="section-header" onClick={() => toggleSection('indicators')}>
            <div className="section-title">
            <AlertTriangle size={20} />
              <h3>Suspicious Indicators ({results.suspicious_indicators.length})</h3>
            </div>
            {expandedSections.has('indicators') ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
          </div>

          {expandedSections.has('indicators') && (
            <div className="section-content">
          <ul className="indicators-list">
                {results.suspicious_indicators.slice(0, 20).map((indicator, index) => (
                  <li key={index} className="indicator-item">
                <AlertTriangle size={16} className="indicator-icon" />
                {indicator}
              </li>
            ))}
          </ul>
        </div>
      )}
        </section>
      )}

      {results.sections.length > 0 && (
        <section className="result-section">
          <div className="section-header" onClick={() => toggleSection('sections')}>
            <div className="section-title">
              <h3>PE Sections ({results.sections.length})</h3>
            </div>
            {expandedSections.has('sections') ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
          </div>
          
          {expandedSections.has('sections') && (
            <div className="section-content">
              <div className="table-container">
                <table className="sections-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Virtual Size</th>
                      <th>Raw Size</th>
                      <th>Entropy</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.sections.map((section, index) => (
                      <tr key={index}>
                        <td className="section-name">{section.name}</td>
                        <td>{section.virtual_size}</td>
                        <td>{section.raw_size}</td>
                        <td>
                          <span 
                            className="entropy-badge"
                            style={{ 
                              backgroundColor: section.entropy > 7 ? '#fef3c7' : '#d1fae5',
                              color: section.entropy > 7 ? '#92400e' : '#065f46'
                            }}
                          >
                            {section.entropy}
                          </span>
                        </td>
                        <td>
                          {section.suspicious ? (
                            <span className="suspicious-badge">{section.suspicious}</span>
                          ) : (
                            <CheckCircle size={16} color="#10b981" />
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      )}

      {results.imports.length > 0 && (
        <section className="result-section">
          <div className="section-header" onClick={() => toggleSection('imports')}>
            <div className="section-title">
              <h3>Imported Libraries ({results.imports.length})</h3>
            </div>
            {expandedSections.has('imports') ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
          </div>
          
          {expandedSections.has('imports') && (
            <div className="section-content">
              {results.imports.slice(0, 10).map((imp, index) => (
                <div key={index} className="import-item">
                  <h4>{imp.dll}</h4>
                  <ul className="functions-list">
                    {imp.functions.slice(0, 10).map((func, fIndex) => (
                      <li key={fIndex}>{func}</li>
                    ))}
                    {imp.functions.length > 10 && (
                      <li className="more-indicator">... and {imp.functions.length - 10} more</li>
                    )}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
};

export default StaticResults;