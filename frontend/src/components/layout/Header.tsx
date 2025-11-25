import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Bug, LogOut, User, Home } from 'lucide-react';
import './Header.css';

interface HeaderProps {
  isAuthenticated: boolean;
  userEmail?: string;
  onLogout: () => void;
}

const Header: React.FC<HeaderProps> = ({ isAuthenticated, userEmail }) => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    window.location.href = '/';
  };

  //get first name from email
  const getUserName = () => {
    if (!userEmail) return '';
    return userEmail.split('@')[0];
  };

  return (
    <header className="header">
      <div className="header-container">
        <Link to="/" className="logo">
          <Bug size={36} />
          <span>SandBug</span>
        </Link>
        
        <nav className="nav">
          <Link to="/" className="nav-link">
            <Home size={18} />
            Home
          </Link>
          
          {isAuthenticated ? (
            <>
              <Link to="/dashboard" className="nav-link">Dashboard</Link>
              <Link to="/history" className="nav-link">History</Link>
              <div className="user-menu">
                <div className="user-avatar">
                  <User size={18} />
                </div>
                <div className="user-info">
                  <span className="user-greeting">Hello, {getUserName()}</span>
                  <span className="user-email">{userEmail}</span>
                </div>
                <button onClick={handleLogout} className="logout-btn">
                  <LogOut size={18} />
                  Logout
                </button>
              </div>
            </>
          ) : (
            <>
              <Link to="/login" className="nav-link">Login</Link>
              <Link to="/register" className="nav-link-primary">Get Started</Link>
            </>
          )}
        </nav>
      </div>
    </header>
  );
};

export default Header;