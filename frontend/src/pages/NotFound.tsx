import React from 'react';
import { useNavigate } from 'react-router-dom';
import './NotFound.css';

const NotFound: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="notfound">
      <div className="notfound-content">
        <span className="notfound-code">404</span>
        <h1>Page not found</h1>
        <p>The URL you visited does not exist.</p>
        <button onClick={() => navigate('/')} className="notfound-btn">
          Go home
        </button>
      </div>
    </div>
  );
};

export default NotFound;
