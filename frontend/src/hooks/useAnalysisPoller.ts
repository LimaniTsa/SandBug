import { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

// How often to poll while analysis is in progress
const POLL_INTERVAL_MS = 4000;

interface StageInfo {
  label: string;
  sub: string;
  progress: number;
}

// Maps backend status strings to UI labels and progress percentages
const STATUS_MAP: Record<string, StageInfo> = {
  processing: {
    label: 'Preparing analysis',
    sub:   'Reading file and extracting metadata…',
    progress: 10,
  },
  static_complete: {
    label: 'Static analysis complete',
    sub:   'Submitting to sandbox - usually under 3 minutes…',
    progress: 30,
  },
  static_failed: {
    label: 'Static analysis failed',
    sub:   'Running sandbox anyway…',
    progress: 25,
  },
  dynamic_queued: {
    label: 'Queued for sandbox',
    sub:   'Waiting for a Triage slot…',
    progress: 45,
  },
  sandbox_running: {
    label: 'Sandbox running',
    sub:   'Executing in Triage isolated VM, please wait…',
    progress: 65,
  },
  completed: {
    label: 'Analysis complete',
    sub:   'All results are ready.',
    progress: 100,
  },
  dynamic_failed: {
    label: 'Analysis complete (static only)',
    sub:   'Dynamic analysis encountered an error.',
    progress: 100,
  },
  failed: {
    label: 'Analysis failed',
    sub:   'Something went wrong. Please try again.',
    progress: 100,
  },
};

// Statuses that stop polling
const TERMINAL_STATUSES = new Set(['completed', 'dynamic_failed', 'failed']);

export interface PollerResult {
  status:     string;
  stage:      StageInfo;
  analysis:   Record<string, any> | null;
  isComplete: boolean;
  isFailed:   boolean;
  isRunning:  boolean;
  error:      string | null;
}

// After reaching a terminal status, poll a few more times waiting for ai_summary
const AI_SUMMARY_RETRIES = 5;
const AI_SUMMARY_INTERVAL_MS = 3000;

// polls the analysis endpoint until a terminal status is reached, then waits briefly for the ai summary
export function useAnalysisPoller(analysisId: number): PollerResult {
  const [status,   setStatus]   = useState('processing');
  const [analysis, setAnalysis] = useState<Record<string, any> | null>(null);
  const [error,    setError]    = useState<string | null>(null);
  const timerRef      = useRef<ReturnType<typeof setTimeout> | null>(null);
  const summaryTriesRef = useRef(0);

  const poll = useCallback(async () => {
    try {
      const token = localStorage.getItem('access_token');
      const config = token
        ? { headers: { Authorization: `Bearer ${token}` } }
        : {};

      const resp = await axios.get<{ analysis: any }>(
        `${API_BASE}/analysis/${analysisId}`,
        config
      );

      const a = resp.data.analysis;
      setStatus(a.status ?? 'processing');
      setAnalysis(a);
      setError(null);

      if (!TERMINAL_STATUSES.has(a.status)) {
        // Keep polling until a terminal status is reached
        timerRef.current = setTimeout(poll, POLL_INTERVAL_MS);
      } else if (!a.ai_summary && summaryTriesRef.current < AI_SUMMARY_RETRIES) {
        // Terminal but no AI summary yet — keep polling briefly for it
        summaryTriesRef.current += 1;
        timerRef.current = setTimeout(poll, AI_SUMMARY_INTERVAL_MS);
      }
    } catch (err: any) {
      const msg = err.response?.data?.error ?? 'Failed to fetch analysis status.';
      setError(msg);
      // Back off on error before retrying
      timerRef.current = setTimeout(poll, POLL_INTERVAL_MS * 2);
    }
  }, [analysisId]);

  useEffect(() => {
    if (!analysisId) return;
    poll();
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [poll, analysisId]);

  const stage      = STATUS_MAP[status] ?? STATUS_MAP['processing'];
  const isComplete = TERMINAL_STATUSES.has(status);
  const isFailed   = status === 'failed';
  const isRunning  = !isComplete;

  return { status, stage, analysis, isComplete, isFailed, isRunning, error };
}
