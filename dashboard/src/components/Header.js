import React, { useState, useEffect } from 'react';
import './Header.css';

function Header() {
  const [darkMode, setDarkMode] = useState(true);

  useEffect(() => {
    document.body.setAttribute('data-theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  return (
    <header className="header">
      <div className="header-content">
        <div className="header-left">
          <div className="logo">
            <span className="logo-icon">🛡️</span>
            <div>
              <h1 className="logo-text">SupplyChainGuard</h1>
              <p className="logo-subtitle">
                Real-Time Supply Chain Threat Detection
              </p>
            </div>
          </div>
        </div>

        <div className="header-right">
          <button
            className="theme-toggle"
            onClick={() => setDarkMode(!darkMode)}
            title={darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          >
            {darkMode ? '☀️' : '🌙'}
          </button>
          <div className="header-badge">
            <span className="badge-dot"></span>
            System Active
          </div>
        </div>
      </div>
    </header>
  );
}

export default Header;