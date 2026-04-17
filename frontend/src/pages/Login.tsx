import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Mail, Lock, AlertCircle, AlertTriangle, ShieldOff } from 'lucide-react';
import { login } from '../services/api';
import './Auth.css';

interface LoginProps {
  onLoginSuccess: (email: string, name?: string) => void;
}

const Login: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const navigate  = useNavigate();
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [error,    setError]    = useState('');
  const [warning,  setWarning]  = useState('');
  const [locked,   setLocked]   = useState(false);
  const [countdown, setCountdown] = useState(0);
  const [loading,  setLoading]  = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Countdown ticker when locked
  useEffect(() => {
    if (locked && countdown > 0) {
      timerRef.current = setInterval(() => {
        setCountdown(s => {
          if (s <= 1) {
            clearInterval(timerRef.current!);
            setLocked(false);
            setError('');
            return 0;
          }
          return s - 1;
        });
      }, 1000);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [locked, countdown]);

  const fmtCountdown = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    if (!locked) { setError(''); setWarning(''); }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (locked) return;
    setError('');
    setWarning('');
    setLoading(true);

    try {
      const response = await login(formData.email, formData.password);
      // store credentials so the axios interceptor can attach them to future requests
      localStorage.setItem('access_token', response.access_token);
      localStorage.setItem('user', JSON.stringify(response.user));
      onLoginSuccess(response.user.email, response.user.name);
      navigate('/dashboard');
    } catch (err: any) {
      const data = err.response?.data ?? {};
      if (data.locked) {
        // server returned 429 — start the lockout countdown from retry_after seconds
        setLocked(true);
        setCountdown(data.retry_after ?? 900);
        setError(data.error || 'Too many failed attempts. Account temporarily locked.');
      } else {
        setError(data.error || 'Login failed. Please try again.');
        if (data.warning) setWarning(data.warning);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h1>Welcome Back</h1>
          <p>Sign in to your SandBug account</p>
        </div>

        {locked && (
          <div className="login-lockout-banner">
            <ShieldOff size={18} />
            <div>
              <strong>Account temporarily locked</strong>
              <span>{error}</span>
              {countdown > 0 && (
                <span className="login-countdown">Unlocks in {fmtCountdown(countdown)}</span>
              )}
            </div>
          </div>
        )}

        {error && !locked && (
          <div className="error-banner">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        {warning && !locked && (
          <div className="login-warning-banner">
            <AlertTriangle size={18} />
            <span>{warning}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="form-group">
            <label htmlFor="email">
              <Mail size={18} />
              Email Address
            </label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="you@example.com"
              required
              autoComplete="email"
              disabled={locked}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">
              <Lock size={18} />
              Password
            </label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="Enter your password"
              required
              autoComplete="current-password"
              disabled={locked}
            />
          </div>

          <button type="submit" className="btn-auth" disabled={loading || locked}>
            {locked
              ? `Locked — ${fmtCountdown(countdown)}`
              : loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>

        <div className="auth-footer">
          <p>
            Don't have an account?{' '}
            <Link to="/register" className="auth-link">Create one</Link>
          </p>
          <p>
            Or{' '}
            <Link to="/dashboard" className="auth-link">continue as guest</Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
