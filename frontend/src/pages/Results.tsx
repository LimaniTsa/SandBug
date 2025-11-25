import React from 'react';
import { useParams } from 'react-router-dom';
import './Results.css';

const Results: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  return (
    <div className="results">
      <div className="results-container">
        <h1>Analysis Results</h1>
        <p style={{ color: 'var(--text-secondary)', marginTop: '1rem' }}>
          Analysis ID: {id}
        </p>
        <div className="placeholder-message">
          <p>Results page will be implemented in future sprints.</p>
          <p>This will display:</p>
          <ul>
            <li>Static analysis results</li>
            <li>Dynamic behaviour analysis</li>
            <li>AI-generated summary</li>
            <li>Risk assessment</li>
            <li>Indicators of compromise</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Results;