import React from 'react';
import { useParams } from 'react-router-dom';
import StaticResults from '../components/common/StaticResults';

const Results: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  return (
    <div className="results-page">
      <StaticResults analysisId={parseInt(id || '0')} />
    </div>
  );
};

export default Results;
