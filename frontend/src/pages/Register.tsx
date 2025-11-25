import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Mail, Lock, AlertCircle, CheckCircle2 } from 'lucide-react';
import { register } from '../services/api';
import './Auth.css';

interface RegisterProps {
  onRegisterSuccess: (email: string) => void;
}

const Register: React.FC<RegisterProps> = ({ onRegisterSuccess }) => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState({
    hasLength: false,
    hasUpper: false,
    hasLower: false,
    hasNumber: false,
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
    setError('');

    //password strength
    if (name === 'password') {
      setPasswordStrength({
        hasLength: value.length >= 8,
        hasUpper: /[A-Z]/.test(value),
        hasLower: /[a-z]/.test(value),
        hasNumber: /\d/.test(value),
      });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    //validate passwords match
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    //validate password strength
    if (!Object.values(passwordStrength).every(Boolean)) {
      setError('Password does not meet requirements');
      return;
    }

    setLoading(true);

    try {
      const response = await register(formData.email, formData.password);
      
      //store token and user data
       localStorage.setItem('access_token', response.access_token);
      localStorage.setItem('user', JSON.stringify(response.user));
      
      //call parent callback
      onRegisterSuccess(response.user.email);
      
      //redirect to dashboard
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h1>Create Account</h1>
          <p>Start analysing malware with SandBug</p>
        </div>

        {error && (
          <div className="error-banner">
            <AlertCircle size={20} />
            <span>{error}</span>
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
              placeholder="Create a strong password"
              required
              autoComplete="new-password"
            />
          </div>

          <div className="form-group">
            <label htmlFor="confirmPassword">
              <Lock size={18} />
              Confirm Password
            </label>
            <input
              type="password"
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleChange}
              placeholder="Confirm your password"
              required
              autoComplete="new-password"
            />
          </div>

          {/*password strength indicator */}
          {formData.password && (
            <div className="password-strength">
              <p className="strength-title">Password Requirements:</p>
              <div className="strength-checks">
                <div className={`strength-check ${passwordStrength.hasLength ? 'valid' : ''}`}>
                  {passwordStrength.hasLength ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
                  <span>At least 8 characters</span>
                </div>
                <div className={`strength-check ${passwordStrength.hasUpper ? 'valid' : ''}`}>
                  {passwordStrength.hasUpper ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
                  <span>One uppercase letter</span>
                </div>
                <div className={`strength-check ${passwordStrength.hasLower ? 'valid' : ''}`}>
                  {passwordStrength.hasLower ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
                  <span>One lowercase letter</span>
                </div>
                <div className={`strength-check ${passwordStrength.hasNumber ? 'valid' : ''}`}>
                  {passwordStrength.hasNumber ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
                  <span>One number</span>
                </div>
              </div>
            </div>
          )}

          <button type="submit" className="btn-auth" disabled={loading}>
            {loading ? 'Creating Account...' : 'Create Account'}
          </button>
        </form>

        <div className="auth-footer">
          <p>
            Already have an account?{' '}
            <Link to="/login" className="auth-link">
              Sign in
            </Link>
          </p>
          <p>
            Or{' '}
            <Link to="/dashboard" className="auth-link">
              continue as guest
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;
