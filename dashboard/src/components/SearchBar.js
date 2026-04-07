import React, { useState } from 'react';
import './SearchBar.css';

function SearchBar({ onScan, disabled }) {
  const [packageName, setPackageName] = useState('');
  const [ecosystem, setEcosystem] = useState('npm');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (packageName.trim()) {
      onScan(packageName.trim(), ecosystem);
    }
  };

  const quickScans = [
    { name: 'express', eco: 'npm' },
    { name: 'lodash', eco: 'npm' },
    { name: 'requests', eco: 'pypi' },
    { name: 'flask', eco: 'pypi' },
    { name: 'axios', eco: 'npm' },
    { name: 'numpy', eco: 'pypi' }
  ];

  return (
    <div className="search-section">
      <form className="search-form" onSubmit={handleSubmit}>
        <div className="search-input-group">
          <select
            className="ecosystem-select"
            value={ecosystem}
            onChange={(e) => setEcosystem(e.target.value)}
            disabled={disabled}
          >
            <option value="npm">npm</option>
            <option value="pypi">PyPI</option>
          </select>

          <input
            type="text"
            className="search-input"
            placeholder="Enter package name (e.g. express, requests)"
            value={packageName}
            onChange={(e) => setPackageName(e.target.value)}
            disabled={disabled}
          />

          <button
            type="submit"
            className="scan-button"
            disabled={disabled || !packageName.trim()}
          >
            {disabled ? (
              <span className="button-loading">Scanning...</span>
            ) : (
              <>🔍 Scan Package</>
            )}
          </button>
        </div>
      </form>

      <div className="quick-scans">
        <span className="quick-label">Quick scan:</span>
        {quickScans.map((pkg, i) => (
          <button
            key={i}
            className="quick-btn"
            onClick={() => {
              setPackageName(pkg.name);
              setEcosystem(pkg.eco);
              onScan(pkg.name, pkg.eco);
            }}
            disabled={disabled}
          >
            {pkg.name}
            <span className="quick-eco">{pkg.eco}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

export default SearchBar;