import React, { useEffect, useState } from 'react';
import './Charts.css';

function RiskGauge({ score, level, color }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let current = 0;
    const increment = score / 60;
    const timer = setInterval(() => {
      current += increment;
      if (current >= score) {
        setAnimatedScore(score);
        clearInterval(timer);
      } else {
        setAnimatedScore(Math.round(current));
      }
    }, 16);
    return () => clearInterval(timer);
  }, [score]);

  const circumference = 2 * Math.PI * 80;
  const offset = circumference - (animatedScore / 100) * circumference;

  const isDark = document.body.getAttribute('data-theme') !== 'light';
  const bgStroke = isDark ? 'rgba(71, 85, 105, 0.2)' : 'rgba(203, 213, 225, 0.5)';
  const subTextColor = isDark ? '#64748b' : '#94a3b8';

  return (
    <div className="gauge-container">
      <svg width="200" height="200" viewBox="0 0 200 200">
        <circle
          cx="100" cy="100" r="80"
          fill="none"
          stroke={bgStroke}
          strokeWidth="12"
        />
        <circle
          cx="100" cy="100" r="80"
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 100 100)"
          style={{ transition: 'stroke-dashoffset 0.5s ease' }}
        />
        <text
          x="100" y="90"
          textAnchor="middle"
          fill={color}
          fontSize="36"
          fontWeight="800"
        >
          {animatedScore}
        </text>
        <text
          x="100" y="115"
          textAnchor="middle"
          fill={subTextColor}
          fontSize="14"
        >
          /100
        </text>
        <text
          x="100" y="140"
          textAnchor="middle"
          fill={color}
          fontSize="14"
          fontWeight="700"
          letterSpacing="2"
        >
          {level}
        </text>
      </svg>
    </div>
  );
}

export default RiskGauge;