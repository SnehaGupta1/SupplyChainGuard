import React from 'react';
import './LoadingScreen.css';

function LoadingScreen() {
  const steps = [
    'Fetching package metadata...',
    'Running typosquatting detection...',
    'Querying vulnerability databases...',
    'Performing static code analysis...',
    'Building behavioral profile...',
    'Analyzing dependency graph...',
    'Calculating risk score...'
  ];

  return (
    <div className="loading-container">
      <div className="loading-card">
        <div className="loading-spinner"></div>
        <h3 className="loading-title">Scanning Supply Chain</h3>
        <div className="loading-steps">
          {steps.map((step, i) => (
            <div
              key={i}
              className="loading-step"
              style={{ animationDelay: `${i * 0.8}s` }}
            >
              <span className="step-icon">⟳</span>
              {step}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default LoadingScreen;