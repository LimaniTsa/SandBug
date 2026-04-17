import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Header from './components/layout/Header';
import Footer from './components/layout/Footer';
import Landing from './pages/Landing';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Results from './pages/Results';
import History from './pages/History';
import About from './pages/About';
import NotFound from './pages/NotFound';
import { logout } from './services/api';
import './styles/globals.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userEmail, setUserEmail] = useState<string | undefined>(undefined);
  const [userName, setUserName] = useState<string | undefined>(undefined);
  // default to dark mode if no preference is stored
  const [darkMode, setDarkMode] = useState(() => {
    const stored = localStorage.getItem('theme');
    return stored ? stored === 'dark' : true;
  });

  // apply the theme attribute to the root element so css variables respond to it
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', darkMode ? 'dark' : 'light');
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  useEffect(() => {
    //check if user is logged in on app load
    const token = localStorage.getItem('access_token');
    const user = localStorage.getItem('user');

    if (token && user) {
      setIsAuthenticated(true);
      const userData = JSON.parse(user);
      setUserEmail(userData.email);
      setUserName(userData.name || undefined);
    }
  }, []);

  const handleLogout = () => {
    logout();
    setIsAuthenticated(false);
    setUserEmail(undefined);
    setUserName(undefined);
  };

  const handleAuthSuccess = (email: string, name?: string) => {
    setIsAuthenticated(true);
    setUserEmail(email);
    setUserName(name || undefined);
  };

  return (
    <Router>
      <div className="app">
        <Header
          isAuthenticated={isAuthenticated}
          userEmail={userEmail}
          onLogout={handleLogout}
          darkMode={darkMode}
          onToggleDarkMode={() => setDarkMode(prev => !prev)}
        />
        <main className="main-content">
          <Routes>
            <Route
              path="/"
              element={
                <Landing
                  isAuthenticated={isAuthenticated}
                  userEmail={userEmail}
                  userName={userName}
                  darkMode={darkMode}
                />
              }
            />
            <Route 
              path="/login" 
              element={<Login onLoginSuccess={handleAuthSuccess} />} 
            />
            <Route 
              path="/register" 
              element={<Register onRegisterSuccess={handleAuthSuccess} />} 
            />
            <Route 
              path="/dashboard" 
              element={
                <Dashboard 
                  isAuthenticated={isAuthenticated} 
                  userEmail={userEmail} 
                />
              } 
            />
            <Route path="/about" element={<About />} />
            <Route path="/results/:id" element={<Results />} />
            <Route
              path="/history"
              element={<History isAuthenticated={isAuthenticated} />}
            />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </Router>
  );
}

export default App;