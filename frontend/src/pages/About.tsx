import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Brain, FileSearch, Activity, Globe, Github, Code, Zap } from 'lucide-react';
import './About.css';

const About: React.FC = () => {
  const navigate = useNavigate();

  const techStack = [
    { label: 'Frontend', value: 'React 19 + TypeScript' },
    { label: 'Backend', value: 'Flask + Python' },
    { label: 'Database', value: 'PostgreSQL' },
    { label: 'Queue', value: 'Redis + RQ' },
    { label: 'AI Engine', value: 'Claude API' },
    { label: 'Sandboxing', value: 'Dynamic analysis pipeline' },
    { label: 'Threat Intel', value: 'MalwareBazaar' },
    { label: 'Reports', value: 'fpdf2 for PDF generation' },
  ];

  const capabilities = [
    {
      icon: FileSearch,
      title: 'Static Analysis',
      description: 'YARA signature matching, entropy analysis, and file structure inspection to detect embedded threats without executing the file.',
    },
    {
      icon: Activity,
      title: 'Dynamic Sandboxing',
      description: 'Files are executed in an isolated environment and monitored for suspicious behaviour, network calls, and system modifications.',
    },
    {
      icon: Globe,
      title: 'URL Intelligence',
      description: 'URL scanning with redirect chain tracing, IP reputation lookups, and detection of phishing pages or IP grabbers.',
    },
    {
      icon: Brain,
      title: 'AI-Powered Reports',
      description: 'Claude generates a plain-English threat summary with risk scoring and indicators of compromise, readable by anyone.',
    },
    {
      icon: Shield,
      title: 'Threat Intel Lookup',
      description: 'File hashes are checked against MalwareBazaar to surface known malware families and prior sightings instantly.',
    },
    {
      icon: Zap,
      title: 'PDF Export',
      description: 'Download a full threat report as a formatted PDF, useful for documentation, incident response, or sharing with a team.',
    },
  ];

  return (
    <div className="about">

      {/* Hero */}
      <section className="about-hero">
        <div className="about-hero-content">
          <div className="about-badge">
            <Code size={14} />
            Final Year Project · 2026
          </div>
          <h1 className="about-hero-title">
            About <span className="about-gradient-text">SandBug</span>
          </h1>
          <p className="about-hero-subtitle">
            SandBug is an AI-assisted malware and URL threat analysis platform built as a final
            year university project. It was designed to make threat analysis approachable for
            people with no security background, without watering down the results for those who do.
          </p>
          <div className="about-hero-actions">
            <button onClick={() => navigate('/dashboard')} className="about-btn-primary">
              Try it out
            </button>
            <a
              href="https://github.com/LimaniTsa/SandBug.git"
              target="_blank"
              rel="noopener noreferrer"
              className="about-btn-secondary"
            >
              <Github size={18} />
              View on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* What it does */}
      <section className="about-capabilities">
        <div className="about-container">
          <h2 className="about-section-title">What SandBug Does</h2>
          <p className="about-section-subtitle">
            A multi-layer analysis pipeline that runs automatically on every submission.
          </p>
          <div className="about-capabilities-grid">
            {capabilities.map(({ icon: Icon, title, description }) => (
              <div key={title} className="about-capability-card">
                <div className="about-capability-icon">
                  <Icon size={24} />
                </div>
                <h3>{title}</h3>
                <p>{description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Why it was built */}
      <section className="about-mission">
        <div className="about-container about-mission-inner">
          <div className="about-mission-text">
            <h2 className="about-section-title left">Why It Was Built</h2>
            <p>
              SandBug is my final year university project, built with a simple goal: make malware
              analysis less intimidating. Most existing tools assume you already know what a YARA
              rule is, what entropy means, or how to read a sandbox report. For anyone outside
              of security, that is a hard wall to hit.
            </p>
            <p>
              SandBug was built to lower that barrier. The analysis pipeline runs the same
              checks a security analyst would run, but the results are translated into plain
              English by AI. You get a risk level, a summary of what was found, and a clear
              explanation of why it matters, without needing any prior knowledge.
            </p>
            <p>
              It is equally useful for someone who just wants to know if a file is safe, and for
              someone who wants the full technical breakdown. No setup, no API keys, no security
              background required.
            </p>
          </div>
          <div className="about-mission-cta">
            <h3>Ready to analyse something?</h3>
            <p>Submit a file or URL and get results in under a minute.</p>
            <button onClick={() => navigate('/dashboard')} className="about-btn-primary">
              Go to Dashboard
            </button>
          </div>
        </div>
      </section>

      {/* Tech stack */}
      <section className="about-tech">
        <div className="about-container">
          <h2 className="about-section-title">Tech Stack</h2>
          <p className="about-section-subtitle">
            Built with modern tools across the full stack.
          </p>
          <div className="about-tech-grid">
            {techStack.map(({ label, value }) => (
              <div key={label} className="about-tech-card">
                <span className="about-tech-label">{label}</span>
                <span className="about-tech-value">{value}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer credit */}
      <section className="about-credit">
        <div className="about-container about-credit-inner">
          <p>Built by <strong>Liman T.</strong> · 2026</p>
          <a
            href="https://github.com/LimaniTsa/SandBug.git"
            target="_blank"
            rel="noopener noreferrer"
            className="about-github-link"
          >
            <Github size={16} />
            LimaniTsa/SandBug
          </a>
        </div>
      </section>

    </div>
  );
};

export default About;
