import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileSearch, Activity, Brain, Shield, History, Download, Globe } from 'lucide-react';

import FeatureCard from '../components/common/FeatureCard';
import { getFeatures } from '../services/api';
import { Feature } from '../types';

import './Landing.css';
import Iridescence from '../components/common/Iridescence';
import LiquidEther from '../components/common/LiquidEther';

const iconMap: { [key: string]: any } = {
  FileSearch,
  Activity,
  Brain,
  Shield,
  History,
  Download,
  Globe,
};

interface LandingProps {
  isAuthenticated: boolean;
  userEmail?: string;
  userName?: string;
  darkMode?: boolean;
}

const Landing: React.FC<LandingProps> = ({ isAuthenticated, userEmail, userName, darkMode }) => {
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
    if (userName) return userName;
    if (!userEmail) return '';
    return userEmail.split('@')[0];
  };

  return (
    <div className="landing">
      <section className="hero">
        {darkMode ? (
          <LiquidEther
            style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', zIndex: 0 }}
            colors={['#5227FF', '#FF9FFC', '#B19EEF']}
            mouseForce={20}
            cursorSize={100}
            isViscous
            viscous={26}
            iterationsViscous={32}
            iterationsPoisson={32}
            resolution={0.5}
            isBounce = {false}
            autoDemo
            autoSpeed={0.5}
            autoIntensity={2.2}
            takeoverDuration={0.25}
            autoResumeDelay={3000}
            autoRampDuration={0.6}
            color0="#5227FF"
            color1="#FF9FFC"
            color2="#B19EEF"
          />
        ) : (
          <Iridescence
            className="hero-liquid-bg"
            color={[0.7, 0.3, 1.0]}
            speed={0.6}
            amplitude={0.22}
            mouseReact={true}
          />
        )}

        <div className="hero-content">
          {isAuthenticated ? (
            <>
              <h1 className="hero-title">
                Welcome back, <span className="gradient-text">{getUserName()}</span>
              </h1>

              <p className="hero-subtitle">
                Submit a file or URL for analysis, or review your previous threat reports.
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
                Analyse <span className="gradient-text">Files & URLs</span>
              </h1>

              <p className="hero-subtitle">
                Upload suspicious files or scan URLs for malware, IP grabbers, and threats. Static signatures, dynamic sandboxing, and AI-generated summaries. No setup required.
              </p>

              <div className="hero-actions">
                <button onClick={() => navigate('/dashboard')} className="btn-primary">
                  Start Scanning
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
              <h3>Submit a File or URL</h3>
              <p>Upload a suspicious file or paste a URL. Executables, scripts, documents, and links are all supported.</p>
            </div>

            <div className="step">
              <div className="step-number">2</div>
              <h3>Multi-Layer Analysis</h3>
              <p>YARA signature matching, entropy analysis, dynamic sandboxing, heuristic checks, and IP reputation lookups run automatically.</p>
            </div>

            <div className="step">
              <div className="step-number">3</div>
              <h3>AI Threat Report</h3>
              <p>Get a risk score, indicators of compromise, redirect chains, and a plain-English AI summary you can export as a PDF report.</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Landing;
