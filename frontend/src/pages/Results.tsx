import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { AlertCircle } from 'lucide-react';
import AnalysisOverview from '../components/common/AnalysisOverview';
import AnalysisProgress from '../components/common/AnalysisProgress';
import { useAnalysisPoller } from '../hooks/useAnalysisPoller';
import { downloadReport, ReportFormat } from '../utils/generateReport';
import './Results.css';

const Results: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const analysisId = parseInt(id || '0');

  const { status, stage, analysis, isComplete, error } = useAnalysisPoller(analysisId);

  const handleDownload = async (format: ReportFormat) => {
    if (analysis) return downloadReport(analysis, format);
  };

  if (error && !analysis) {
    return (
      <div className="results-page">
        <div className="results-page-error">
          <AlertCircle size={32} />
          <p>{error}</p>
        </div>
      </div>
    );
  }

  if (!isComplete) {
    return (
      <div className="results-page">
        <AnalysisProgress
          status={status}
          label={stage.label}
          sub={stage.sub}
          progress={stage.progress}
          filename={analysis?.filename}
        />
      </div>
    );
  }

  const riskLabel    = analysis?.risk_level ?? 'unknown';
  const dynAnalysis  = analysis?.dynamic_analysis as { triage?: unknown; hybrid_analysis?: unknown; error?: string } | null | undefined;
  const hasDynamic   = !!dynAnalysis && (!!dynAnalysis.triage || !!dynAnalysis.hybrid_analysis);
  const dynamicError = !hasDynamic ? (dynAnalysis?.error ?? null) : null;

  return (
    <div className="results-page">
      <AnalysisOverview
        staticData={analysis?.static_analysis  ?? null}
        dynamicData={hasDynamic ? (analysis?.dynamic_analysis as any) : null}
        dynamicError={dynamicError}
        filename={analysis?.filename   ?? ''}
        fileSize={analysis?.file_size  ?? 0}
        fileType={analysis?.file_type  ?? ''}
        fileHash={analysis?.file_hash  ?? ''}
        riskLevel={riskLabel}
        riskScore={analysis?.risk_score ?? 0}
        aiSummary={analysis?.ai_summary ?? null}
        onDownload={handleDownload}
      />
    </div>
  );
};

export default Results;