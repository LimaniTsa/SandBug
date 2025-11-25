import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Header from './components/layout/Header';
import Footer from './components/layout/Footer';
import Landing from './pages/Landing';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Results from './pages/Results';
import { logout } from './services/api';
import './styles/globals.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userEmail, setUserEmail] = useState<string | undefined>(undefined);

  useEffect(() => {
    //check if user is logged in on app load
    const token = localStorage.getItem('access_token');
    const user = localStorage.getItem('user');
    
    if (token && user) {
      setIsAuthenticated(true);
      const userData = JSON.parse(user);
      setUserEmail(userData.email);
    }
  }, []);

  const handleLogout = () => {
    logout();
    setIsAuthenticated(false);
    setUserEmail(undefined);
  };

  const handleAuthSuccess = (email: string) => {
    setIsAuthenticated(true);
    setUserEmail(email);
  };

  return (
    <Router>
      <div className="app">
        <Header 
          isAuthenticated={isAuthenticated} 
          userEmail={userEmail}
          onLogout={handleLogout}
        />
        <main className="main-content">
          <Routes>
            <Route 
              path="/" 
              element={
                <Landing 
                  isAuthenticated={isAuthenticated} 
                  userEmail={userEmail} 
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
            <Route path="/results/:id" element={<Results />} />
            <Route 
              path="/history" 
              element={
                <div style={{ padding: '4rem 2rem', textAlign: 'center' }}>
                  <h1>Analysis History</h1>
                  <p style={{ color: 'var(--text-secondary)' }}>
                    History functionality coming in Sprint 11!
                  </p>
                </div>
              } 
            />
          </Routes>
        </main>
        <Footer />
      </div>
    </Router>
  );
}

export default App;