import React from 'react';
import './ErrorMessage.css';

function ErrorMessage({ message, onDismiss }) {
  return (
    <div className="error-container">
      <div className="error-card">
        <span className="error-icon">⚠️</span>
        <div className="error-content">
          <h4>Scan Error</h4>
          <p>{message}</p>
        </div>
        <button className="error-dismiss" onClick={onDismiss}>✕</button>
      </div>
    </div>
  );
}

export default ErrorMessage;