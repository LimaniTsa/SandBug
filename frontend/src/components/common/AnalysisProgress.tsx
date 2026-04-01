/**
 * AnalysisProgress.tsx
 *
 * Shown on the Results page while analysis is still running.
 * Replaces the blank loading state with a live progress bar,
 * stage label, and animated indicators.
 *
 * Drop into src/components/common/
 */

import React from 'react';
import { CheckCircle, AlertTriangle, Clock, Activity } from 'lucide-react';
import './AnalysisProgress.css';

interface AnalysisProgressProps {
  status:    string;
  label:     string;
  sub:       string;
  progress:  number;   // 0-100
  filename?: string;
}

// ── Stage timeline ────────────────────────────────────────────────────────────

interface Step {
  id:       string;
  label:    string;
  statuses: string[];   // backend statuses that map to this step being "active"
  done:     string[];   // statuses where this step is fully complete
}

const STEPS: Step[] = [
  {
    id:       'upload',
    label:    'File received',
    statuses: ['processing'],
    done:     ['static_complete', 'static_failed', 'dynamic_queued',
               'sandbox_running', 'completed', 'dynamic_failed', 'failed'],
  },
  {
    id:       'static',
    label:    'Static analysis',
    statuses: ['processing'],
    done:     ['static_complete', 'static_failed', 'dynamic_queued',
               'sandbox_running', 'completed', 'dynamic_failed', 'failed'],
  },
  {
    id:       'dynamic',
    label:    'Triage sandbox',
    statuses: ['static_complete', 'static_failed', 'dynamic_queued', 'sandbox_running'],
    done:     ['completed', 'dynamic_failed'],
  },
  {
    id:       'done',
    label:    'Results ready',
    statuses: [],
    done:     ['completed', 'dynamic_failed'],
  },
];

const stepState = (step: Step, status: string): 'done' | 'active' | 'pending' => {
  if (step.done.includes(status))     return 'done';
  if (step.statuses.includes(status)) return 'active';
  return 'pending';
};

// ── Component ─────────────────────────────────────────────────────────────────

const AnalysisProgress: React.FC<AnalysisProgressProps> = ({
  status,
  label,
  sub,
  progress,
  filename,
}) => {
  const isFailed = status === 'failed';

  return (
    <div className="ap-root">

      {/* Header */}
      <div className="ap-header">
        <div className={`ap-icon-wrap ${isFailed ? 'ap-icon-fail' : 'ap-icon-running'}`}>
          {isFailed
            ? <AlertTriangle size={22} />
            : <Activity size={22} />
          }
        </div>
        <div>
          <h2 className="ap-title">{filename ?? label}</h2>
          <p className="ap-sub">{sub}</p>
        </div>
      </div>

      {/* Progress bar */}
      {!isFailed && (
        <div className="ap-bar-wrap">
          <div
            className="ap-bar-fill"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {/* Step timeline */}
      <div className="ap-steps">
        {STEPS.map((step, i) => {
          const state = stepState(step, status);
          return (
            <div key={step.id} className={`ap-step ap-step-${state}`}>
              <div className="ap-step-indicator">
                {state === 'done'   && <CheckCircle size={16} />}
                {state === 'active' && <span className="ap-step-spinner" />}
                {state === 'pending'&& <span className="ap-step-dot" />}
              </div>
              <span className="ap-step-label">{step.label}</span>
              {i < STEPS.length - 1 && <div className={`ap-step-line ${state === 'done' ? 'ap-line-done' : ''}`} />}
            </div>
          );
        })}
      </div>

      {/* Time estimate */}
      {!isFailed && (
        <div className="ap-estimate">
          <Clock size={13} />
          <span>
            {progress < 35
              ? 'Usually completes within 5 minutes'
              : progress < 75
              ? 'Sandbox running, almost there…'
              : 'Finishing up…'
            }
          </span>
        </div>
      )}
    </div>
  );
};

export default AnalysisProgress;