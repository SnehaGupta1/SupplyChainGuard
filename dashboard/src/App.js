import React, { useState, useEffect} from 'react';
import './App.css';
import Header from './components/Header';
import SearchBar from './components/SearchBar';
import ScanResults from './components/ScanResults';
import LoadingScreen from './components/LoadingScreen';
import ErrorMessage from './components/ErrorMessage';
import axios from 'axios';
import FileUploader from './components/FileUploader';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5000';


function App() {
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanHistory, setScanHistory] = useState(() => {
  try {
    const saved = localStorage.getItem('scanHistory');
    return saved ? JSON.parse(saved) : [];
  } catch {
    return [];
  }
});

  React.useEffect(() => {
  localStorage.setItem('scanHistory', JSON.stringify(scanHistory));
}, [scanHistory]);

  const handleScan = async (packageName, ecosystem) => {
    setLoading(true);
    setError(null);
    setScanResult(null);

    try {
      const response = await axios.post(`${API_BASE}/api/scan`, {
        package_name: packageName,
        ecosystem: ecosystem,
        scan_dependencies: true,
        max_dependency_depth: 2
      });

      if (response.data.success) {
        setScanResult(response.data);

        // Add to history
        setScanHistory(prev => [{
          package_name: packageName,
          ecosystem: ecosystem,
          risk_score: response.data.risk_score,
          risk_level: response.data.risk_level,
          timestamp: new Date().toISOString()
        }, ...prev].slice(0, 10));
      } else {
        setError(response.data.error || 'Scan failed');
      }
    } catch (err) {
      if (err.response && err.response.data) {
        setError(err.response.data.error || 'Failed to connect to scanner');
      } else {
        setError('Failed to connect to SupplyChainGuard API. Is the server running?');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <Header />

      <main className="main-content">
        <SearchBar onScan={handleScan} disabled={loading} />
        <FileUploader />
        {loading && <LoadingScreen />}
        {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
        {scanResult && <ScanResults data={scanResult} />}

        {/* Scan History */}
        {scanHistory.length > 0 && !scanResult && !loading && (
          <div className="scan-history">
            <h3 className="section-title">Recent Scans</h3>
            <div className="history-grid">
              {scanHistory.map((item, index) => (
                <div
                  key={index}
                  className="history-card"
                  onClick={() => handleScan(item.package_name, item.ecosystem)}
                >
                  <div className="history-name">{item.package_name}</div>
                  <div className="history-meta">
                    <span className="history-ecosystem">{item.ecosystem}</span>
                    <span
                      className="history-risk"
                      style={{ color: getRiskColor(item.risk_level) }}
                    >
                      {item.risk_level} ({item.risk_score})
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function getRiskColor(level) {
  const colors = {
    CRITICAL: '#ef4444',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#22c55e'
  };
  return colors[level] || '#94a3b8';
}

export default App;