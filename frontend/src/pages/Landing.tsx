import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileSearch, Activity, Brain, Shield, History, Download } from 'lucide-react';

import FeatureCard from '../components/common/FeatureCard';
import { getFeatures } from '../services/api';
import { Feature } from '../types';

import './Landing.css';
import Iridescence from '../components/common/Iridescence';

const iconMap: { [key: string]: any } = {
  FileSearch,
  Activity,
  Brain,
  Shield,
  History,
  Download,
};

interface LandingProps {
  isAuthenticated: boolean;
  userEmail?: string;
}

const Landing: React.FC<LandingProps> = ({ isAuthenticated, userEmail }) => {
  const navigate = useNavigate();

  const [features, setFeatures] = useState<Feature[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchFeatures = async () => {
      try {
        const data = await getFeatures();
        setFeatures(data);
      } catch (error) {
        console.error('Failed to fetch features:', error);
        setError('Failed to load features. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    fetchFeatures();
  }, []);

  const getUserName = () => {
    if (!userEmail) return '';
    return userEmail.split('@')[0];
  };

  return (
    <div className="landing">
      <section className="hero">
        <Iridescence
          className="hero-liquid-bg"
          color={[0.7, 0.3, 1.0]}
          speed={0.6}
          amplitude={0.22}
          mouseReact={true}
        />

        <div className="hero-content">
          {isAuthenticated ? (
            <>
              <h1 className="hero-title">
                Hello, <span className="gradient-text">{getUserName()}</span>
              </h1>

              <p className="hero-subtitle">
                Ready to analyse suspicious files? Access your dashboard or review your previous analyses.
              </p>

              <div className="hero-actions">
                <button onClick={() => navigate('/dashboard')} className="btn-primary">
                  Go to Dashboard
                </button>
                <button onClick={() => navigate('/history')} className="btn-secondary">
                  View History
                </button>
              </div>
            </>
          ) : (
            <>
              <h1 className="hero-title">
                SandBug: Malware Analysis <span className="gradient-text">Made Simple</span>
              </h1>

              <p className="hero-subtitle">
                SandBug lets you safely analyse suspicious files with just one click in a secure, isolated environment.
              </p>

              <div className="hero-actions">
                <button onClick={() => navigate('/dashboard')} className="btn-primary">
                  Continue as Guest
                </button>
                <button onClick={() => navigate('/register')} className="btn-secondary">
                  Create Account
                </button>
              </div>
            </>
          )}
        </div>
      </section>

      <section className="features">
        <div className="features-container">
          <h2 className="section-title">SandBug Features</h2>
          {loading ? (
            <div className="loading">
              <div className="loading-spinner"></div>
              <p>Loading features...</p>
            </div>
          ) : error ? (
            <div className="error-message">
              <p>{error}</p>
            </div>
          ) : (
            <div className="features-grid">
              {features.map((feature) => {
                const IconComponent = iconMap[feature.icon] || Shield;
                return (
                  <FeatureCard
                    key={feature.id}
                    icon={IconComponent}
                    title={feature.title}
                    description={feature.description}
                  />
                );
              })}
            </div>
          )}
        </div>
      </section>

      <section className="how-it-works">
        <div className="how-it-works-container">
          <h2 className="section-title">How It Works</h2>

          <div className="steps">
            <div className="step">
              <div className="step-number">1</div>
              <h3>Upload File</h3>
              <p>Drop your suspicious file or select it from your computer.</p>
            </div>

            <div className="step">
              <div className="step-number">2</div>
              <h3>Automated Analysis</h3>
              <p>The system performs both static and dynamic analysis.</p>
            </div>

            <div className="step">
              <div className="step-number">3</div>
              <h3>Get Results</h3>
              <p>Receive AI-powered reports with actionable insights.</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Landing;
