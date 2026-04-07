import React from 'react';
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  PolarRadiusAxis, ResponsiveContainer, Tooltip
} from 'recharts';
import './Charts.css';

function BehavioralRadar({ behavioral }) {
  if (!behavioral || !behavioral.fingerprint) {
    return <p className="no-data">No behavioral data available</p>;
  }

  const fingerprint = behavioral.fingerprint;

  const data = Object.entries(fingerprint).map(([key, value]) => ({
    category: key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
    value: Math.min(value * 10, 100),
    raw: value
  }));

  if (data.every(d => d.value === 0)) {
    return (
      <div className="no-vuln-container">
        <div className="no-vuln-icon">✅</div>
        <p>No behavioral indicators detected</p>
      </div>
    );
  }

  const isDark = document.body.getAttribute('data-theme') !== 'light';
  const textColor = isDark ? '#94a3b8' : '#475569';
  const gridColor = isDark ? 'rgba(71, 85, 105, 0.3)' : 'rgba(203, 213, 225, 0.5)';
  const tooltipBg = isDark ? '#1e293b' : '#ffffff';
  const tooltipBorder = isDark ? '#334155' : '#e2e8f0';
  const tooltipText = isDark ? '#e2e8f0' : '#1e293b';

  return (
    <div className="chart-wrapper">
      <ResponsiveContainer width="100%" height={300}>
        <RadarChart data={data} cx="50%" cy="50%" outerRadius="70%">
          <PolarGrid stroke={gridColor} />
          <PolarAngleAxis
            dataKey="category"
            tick={{ fill: textColor, fontSize: 11 }}
          />
          <PolarRadiusAxis
            angle={30}
            domain={[0, 100]}
            tick={{ fill: textColor, fontSize: 10 }}
          />
          <Radar
            name="Behavioral Score"
            dataKey="value"
            stroke="#a78bfa"
            fill="#a78bfa"
            fillOpacity={0.2}
            strokeWidth={2}
          />
          <Tooltip
            contentStyle={{
              background: tooltipBg,
              border: `1px solid ${tooltipBorder}`,
              borderRadius: '8px',
              color: tooltipText
            }}
            formatter={(value, name, props) => [
              `${props.payload.raw} detections`,
              props.payload.category
            ]}
          />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default BehavioralRadar;