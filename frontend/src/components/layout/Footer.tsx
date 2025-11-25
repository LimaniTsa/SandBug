import React from 'react';
import { Github, Mail } from 'lucide-react';
import './Footer.css';

const Footer: React.FC = () => {
  return (
    <footer className="footer">
      <div className="footer-container">
        <div className="footer-content">
          <div className="footer-section">
            <h3>SandBug</h3>
            <p>AI-Assisted Malware Analysis Sandbox</p>
            <p className="footer-copyright">© 2025 Liman Tsatiashvili. All rights reserved.</p>
          </div>
          
          <div className="footer-section">
            <h4>Quick Links</h4>
            <ul>
              <li><a href="/">Home</a></li>
              <li><a href="/about">About</a></li>
              <li><a href="/documentation">Documentation</a></li>
            </ul>
          </div>
          
          <div className="footer-section">
            <h4>Contact</h4>
            <div className="footer-links">
              <a href="mailto:c22334951@mytudublin.ie" className="footer-link">
                <Mail size={18} />
                Email
              </a>
              <a href="https://github.com/LimaniTsa/SandBug.git" className="footer-link" target="_blank" rel="noopener noreferrer">
                <Github size={18} />
                GitHub
              </a>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;