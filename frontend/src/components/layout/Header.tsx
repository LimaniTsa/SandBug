import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Bug, LogOut, User, Home } from 'lucide-react';
import './Header.css';

interface HeaderProps {
  isAuthenticated: boolean;
  userEmail?: string;
  onLogout: () => void;
}

const Header: React.FC<HeaderProps> = ({ isAuthenticated, userEmail }) => {
  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    window.location.href = '/';
  };

  const getUserName = () => {
    if (!userEmail) return '';
    return userEmail.split('@')[0];
  };

  // Add scroll detection for glass opacity
  useEffect(() => {
    const onScroll = () => {
      const nav = document.querySelector('.navbar');
      if (!nav) return;

      if (window.scrollY > 10) {
        nav.classList.add('nav-scrolled');
      } else {
        nav.classList.remove('nav-scrolled');
      }
    };

    window.addEventListener('scroll', onScroll);
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <header className="navbar">
      <div className="navbar-container">

        <Link to="/" className="logo">
          <Bug size={32} />
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
