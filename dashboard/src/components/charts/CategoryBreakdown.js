import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell
} from 'recharts';
import './Charts.css';

function CategoryBreakdown({ breakdown }) {
  if (!breakdown) return <p className="no-data">No data available</p>;

  const data = Object.entries(breakdown).map(([key, value]) => ({
    category: key.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase()),
    raw: value.normalized || 0,
    weighted: value.weighted_score || 0,
    weight: ((value.weight || 0) * 100).toFixed(0) + '%'
  }));

  const getBarColor = (value) => {
    if (value >= 60) return '#ef4444';
    if (value >= 35) return '#f97316';
    if (value >= 15) return '#eab308';
    return '#22c55e';
  };

  // Detect theme
  const isDark = document.body.getAttribute('data-theme') !== 'light';
  const textColor = isDark ? '#94a3b8' : '#475569';
  const gridColor = isDark ? 'rgba(71,85,105,0.2)' : 'rgba(203,213,225,0.5)';
  const tooltipBg = isDark ? '#1e293b' : '#ffffff';
  const tooltipBorder = isDark ? '#334155' : '#e2e8f0';
  const tooltipText = isDark ? '#e2e8f0' : '#1e293b';

  return (
    <div className="chart-wrapper">
      <ResponsiveContainer width="100%" height={250}>
        <BarChart data={data} layout="vertical" margin={{ left: 20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
          <XAxis
            type="number"
            domain={[0, 100]}
            tick={{ fill: textColor, fontSize: 12 }}
          />
          <YAxis
            type="category"
            dataKey="category"
            width={130}
            tick={{ fill: textColor, fontSize: 12 }}
          />
          <Tooltip
            contentStyle={{
              background: tooltipBg,
              border: `1px solid ${tooltipBorder}`,
              borderRadius: '8px',
              color: tooltipText
            }}
            formatter={(value, name) => [
              `${value.toFixed(1)}`,
              name === 'raw' ? 'Raw Score' : 'Weighted Score'
            ]}
          />
          <Bar dataKey="raw" radius={[0, 6, 6, 0]} barSize={20}>
            {data.map((entry, index) => (
              <Cell key={index} fill={getBarColor(entry.raw)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      <div className="weight-labels">
        {data.map((item, i) => (
          <div key={i} className="weight-label">
            <span>{item.category}</span>
            <span className="weight-value">Weight: {item.weight}</span>
            <span className="weighted-value">
              Contribution: {item.weighted.toFixed(1)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default CategoryBreakdown;