import React, { useState } from 'react';
import axios from 'axios';
import './FileUploader.css';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5000';

function FileUploader() {
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [dragOver, setDragOver] = useState(false);

  const handleFileUpload = async (file) => {
    if (!file) return;

    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const content = await file.text();

      let fileType = "requirements.txt";
      if (file.name.includes("package.json")) {
        fileType = "package.json";
      } else if (file.name.includes("Pipfile")) {
        fileType = "Pipfile";
      }

      const response = await axios.post(
        `${API_BASE}/api/webhook/scan-requirements`,
        {
          content: content,
          file_type: fileType
        }
      );

      setResults(response.data);
    } catch (err) {
      setError(
        err.response?.data?.error || "Failed to scan file"
      );
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    handleFileUpload(file);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const handleInputChange = (e) => {
    const file = e.target.files[0];
    handleFileUpload(file);
  };

  const getRiskColor = (level) => {
    const colors = {
      CRITICAL: '#ef4444',
      HIGH: '#f97316',
      MEDIUM: '#eab308',
      LOW: '#22c55e'
    };
    return colors[level] || '#94a3b8';
  };

  return (
    <div className="file-uploader-section">
      <h3 className="section-title">📁 Scan Dependency File</h3>
      <p className="section-subtitle">
        Upload requirements.txt or package.json to scan all dependencies
      </p>

      <div
        className={`drop-zone ${dragOver ? 'drag-over' : ''}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => document.getElementById('file-input').click()}
      >
        <input
          id="file-input"
          type="file"
          accept=".txt,.json,.toml,.lock"
          onChange={handleInputChange}
          style={{ display: 'none' }}
        />
        <div className="drop-icon">📦</div>
        <p className="drop-text">
          {loading
            ? 'Scanning...'
            : 'Drop requirements.txt or package.json here'}
        </p>
        <p className="drop-hint">or click to browse</p>
      </div>

      {error && (
        <div className="upload-error">
          ⚠️ {error}
        </div>
      )}

      {loading && (
        <div className="upload-loading">
          <div className="spinner"></div>
          <span>Scanning all dependencies...</span>
        </div>
      )}

      {results && (
        <div className="upload-results">
          {/* Summary */}
          <div className="upload-summary">
            <div className="summary-stat">
              <span className="summary-num">{results.total_scanned}</span>
              <span className="summary-label">Scanned</span>
            </div>
            <div className="summary-stat">
              <span className="summary-num" style={{ color: '#ef4444' }}>
                {results.critical || 0}
              </span>
              <span className="summary-label">Critical</span>
            </div>
            <div className="summary-stat">
              <span className="summary-num" style={{ color: '#f97316' }}>
                {results.high || 0}
              </span>
              <span className="summary-label">High</span>
            </div>
            <div className="summary-stat">
              <span className="summary-num" style={{ color: '#eab308' }}>
                {results.medium || 0}
              </span>
              <span className="summary-label">Medium</span>
            </div>
            <div className="summary-stat">
              <span className="summary-num" style={{ color: '#22c55e' }}>
                {results.low || 0}
              </span>
              <span className="summary-label">Low</span>
            </div>
          </div>

          {/* Package Results */}
          <div className="upload-packages">
            {results.results?.map((pkg, i) => (
              <div key={i} className="upload-pkg-row">
                <span className="pkg-name">{pkg.package}</span>
                <span className="pkg-version">{pkg.version || ''}</span>
                {pkg.error ? (
                  <span className="pkg-error">Error: {pkg.error}</span>
                ) : (
                  <>
                    <span
                      className="pkg-risk-badge"
                      style={{
                        background: getRiskColor(pkg.risk_level) + '20',
                        color: getRiskColor(pkg.risk_level)
                      }}
                    >
                      {pkg.risk_level} ({pkg.risk_score})
                    </span>
                    {pkg.vulnerabilities > 0 && (
                      <span className="pkg-vuln-count">
                        🛡️ {pkg.vulnerabilities} CVE(s)
                      </span>
                    )}
                    {pkg.typosquat_suspect && (
                      <span className="pkg-typo-alert">🚨 Typosquat!</span>
                    )}
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default FileUploader;