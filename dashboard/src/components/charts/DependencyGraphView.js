import React from 'react';
import './Charts.css';

function DependencyGraphView({ graphData }) {
  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    return <p className="no-data">No dependency graph data available</p>;
  }

  const nodes = graphData.nodes;
  const edges = graphData.edges;

  const width = 800;
  const height = Math.max(400, nodes.length * 40);

  // Group nodes by depth
  const depthGroups = {};
  nodes.forEach(node => {
    const depth = node.depth || 0;
    if (!depthGroups[depth]) depthGroups[depth] = [];
    depthGroups[depth].push(node);
  });

  const maxDepth = Math.max(...Object.keys(depthGroups).map(Number), 0);
  const levelHeight = height / (maxDepth + 2);

  // Calculate positions
  const nodePositions = {};
  Object.entries(depthGroups).forEach(([depth, group]) => {
    const d = parseInt(depth);
    const spacing = width / (group.length + 1);
    group.forEach((node, i) => {
      nodePositions[node.id] = {
        x: spacing * (i + 1),
        y: levelHeight * (d + 1)
      };
    });
  });

  const getNodeColor = (depth) => {
    const colors = ['#3b82f6', '#22c55e', '#eab308', '#f97316', '#ef4444', '#a855f7'];
    return colors[depth % colors.length];
  };

  return (
    <div className="graph-container">
      <div className="graph-legend">
        <span className="graph-info">
          {nodes.length} packages · {edges.length} relationships
        </span>
      </div>

      <svg width="100%" viewBox={`0 0 ${width} ${height}`}>
        <defs>
          <marker
            id="arrowhead"
            markerWidth="10"
            markerHeight="7"
            refX="10"
            refY="3.5"
            orient="auto"
          >
            <polygon
              points="0 0, 10 3.5, 0 7"
              fill="rgba(100, 116, 139, 0.5)"
            />
          </marker>
        </defs>

        {/* Edges */}
        {edges.map((edge, i) => {
          const source = nodePositions[edge.source];
          const target = nodePositions[edge.target];
          if (!source || !target) return null;

          return (
            <line
              key={`edge-${i}`}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke="rgba(100, 116, 139, 0.3)"
              strokeWidth="1.5"
              markerEnd="url(#arrowhead)"
            />
          );
        })}

        {/* Nodes */}
        {nodes.map((node, i) => {
          const pos = nodePositions[node.id];
          if (!pos) return null;

          const depth = node.depth || 0;
          const color = getNodeColor(depth);
          const isRoot = depth === 0;
          const radius = isRoot ? 22 : 16;

          return (
            <g key={`node-${i}`}>
              {/* Node glow effect */}
              <circle
                cx={pos.x}
                cy={pos.y}
                r={radius + 4}
                fill={color}
                opacity={0.15}
              />

              {/* Node circle */}
              <circle
                cx={pos.x}
                cy={pos.y}
                r={radius}
                fill={`${color}30`}
                stroke={color}
                strokeWidth={isRoot ? 3 : 2}
              />

              {/* Node label */}
              <text
                x={pos.x}
                y={pos.y + radius + 16}
                textAnchor="middle"
                fill="#94a3b8"
                fontSize={isRoot ? 13 : 11}
                fontWeight={isRoot ? 600 : 400}
              >
                {node.label.length > 15
                  ? node.label.substring(0, 15) + '...'
                  : node.label}
              </text>

              {/* Depth indicator inside node */}
              <text
                x={pos.x}
                y={pos.y + 4}
                textAnchor="middle"
                fill={color}
                fontSize={isRoot ? 12 : 10}
                fontWeight="700"
              >
                {isRoot ? '★' : depth}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export default DependencyGraphView;