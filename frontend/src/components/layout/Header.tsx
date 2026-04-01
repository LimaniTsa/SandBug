import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bug, LogOut, User, Sun, Moon, Menu, X } from 'lucide-react';
import './Header.css';

interface HeaderProps {
  isAuthenticated: boolean;
  userEmail?: string;
  onLogout: () => void;
  darkMode: boolean;
  onToggleDarkMode: () => void;
}

const Header: React.FC<HeaderProps> = ({ isAuthenticated, userEmail, darkMode, onToggleDarkMode }) => {
  const [menuOpen, setMenuOpen] = useState(false);

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    window.location.href = '/';
  };

  const getUserName = () => {
    if (!userEmail) return '';
    return userEmail.split('@')[0];
  };

  const closeMenu = () => setMenuOpen(false);

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

  // Close menu when viewport resizes back to desktop
  useEffect(() => {
    const onResize = () => {
      if (window.innerWidth > 640) setMenuOpen(false);
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  return (
    <header className="navbar">
      <div className="navbar-container">

        <Link to="/" className="logo" onClick={closeMenu}>
          <Bug size={32} />
          <span>SandBug</span>
        </Link>

        {/* Desktop nav */}
        <nav className="nav nav-desktop">
          <Link to="/" className="nav-link">Home</Link>

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
              <Link to="/register" className="nav-link-primary">Create Account</Link>
            </>
          )}

          <button
            className="dark-mode-toggle"
            onClick={onToggleDarkMode}
            aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {darkMode ? <Sun size={20} /> : <Moon size={20} />}
          </button>
        </nav>

        {/* Mobile right side: dark mode + hamburger */}
        <div className="nav-mobile-controls">
          <button
            className="dark-mode-toggle"
            onClick={onToggleDarkMode}
            aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {darkMode ? <Sun size={20} /> : <Moon size={20} />}
          </button>
          <button
            className="hamburger-btn"
            onClick={() => setMenuOpen(o => !o)}
            aria-label="Toggle menu"
          >
            {menuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>

      </div>

      {/* Mobile dropdown menu */}
      {menuOpen && (
        <nav className="nav-mobile-menu">
          <Link to="/" className="mobile-nav-link" onClick={closeMenu}>Home</Link>

          {isAuthenticated ? (
            <>
              <Link to="/dashboard" className="mobile-nav-link" onClick={closeMenu}>Dashboard</Link>
              <Link to="/history" className="mobile-nav-link" onClick={closeMenu}>History</Link>
              <div className="mobile-nav-divider" />
              <div className="mobile-user-row">
                <div className="user-avatar"><User size={16} /></div>
                <span className="mobile-user-name">{getUserName()}</span>
              </div>
              <button className="mobile-nav-link mobile-logout" onClick={() => { handleLogout(); closeMenu(); }}>
                <LogOut size={16} /> Logout
              </button>
            </>
          ) : (
            <>
              <Link to="/login" className="mobile-nav-link" onClick={closeMenu}>Login</Link>
              <Link to="/register" className="mobile-nav-link mobile-nav-primary" onClick={closeMenu}>Create Account</Link>
            </>
          )}
        </nav>
      )}
    </header>
  );
};

export default Header;
