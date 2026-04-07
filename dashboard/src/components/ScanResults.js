import React, { useState } from 'react';
import './ScanResults.css';
import RiskGauge from './charts/RiskGauge';
import CategoryBreakdown from './charts/CategoryBreakdown';
import VulnerabilityChart from './charts/VulnerabilityChart';
import BehavioralRadar from './charts/BehavioralRadar';
import DependencyGraphView from './charts/DependencyGraphView';

function ScanResults({ data }) {
  const [activeTab, setActiveTab] = useState('overview');

  const tabs = [
    { id: 'overview', label: '📊 Overview' },
    { id: 'metadata', label: '📋 Metadata' },
    { id: 'vulnerabilities', label: '🛡️ Vulnerabilities' },
    { id: 'code', label: '🔍 Code Analysis' },
    { id: 'behavioral', label: '🧠 Behavioral' },
    { id: 'dependencies', label: '🌳 Dependencies' },
    { id: 'evidence', label: '📑 Evidence' },
    { id: 'recommendations', label: '✅ Actions' }
  ];

  return (
    <div className="results-container">
      {/* ── TOP SUMMARY BAR ── */}
      <div className="results-header">
        <div className="results-header-left">
          <h2 className="package-title">
            {data.package_name}
            <span className="package-version">@{data.version || 'latest'}</span>
          </h2>
          <span className="ecosystem-tag">{data.ecosystem}</span>
        </div>

        <div className="results-header-right">
          <div
            className="risk-badge-large"
            style={{ background: data.risk_color + '20', borderColor: data.risk_color }}
          >
            <span className="risk-score-number" style={{ color: data.risk_color }}>
              {data.risk_score}
            </span>
            <span className="risk-score-max">/100</span>
            <div className="risk-level-text" style={{ color: data.risk_color }}>
              {data.risk_level}
            </div>
          </div>
        </div>
      </div>

      {/* ── ACTION BANNER ── */}
      <div
        className="action-banner"
        style={{ borderLeftColor: data.risk_color }}
      >
        <span className="action-icon">
          {data.risk_level === 'CRITICAL' ? '🚫' :
           data.risk_level === 'HIGH' ? '⚠️' :
           data.risk_level === 'MEDIUM' ? '⚡' : '✅'}
        </span>
        <span>{data.recommended_action}</span>
      </div>

      {/* ── QUICK STATS ── */}
      <div className="stats-grid">
        <StatCard
          title="Metadata Issues"
          value={data.metadata?.factors?.length || 0}
          color={data.metadata?.risk_score > 30 ? '#f97316' : '#22c55e'}
          icon="📋"
        />
        <StatCard
          title="Vulnerabilities"
          value={data.vulnerabilities?.total || 0}
          color={data.vulnerabilities?.total > 0 ? '#ef4444' : '#22c55e'}
          icon="🛡️"
        />
        <StatCard
          title="Code Issues"
          value={data.code_analysis?.total_issues || 0}
          color={data.code_analysis?.risk_score > 30 ? '#f97316' : '#22c55e'}
          icon="🔍"
        />
        <StatCard
          title="Dependencies"
          value={data.dependency_graph?.total_dependencies || 0}
          color="#3b82f6"
          icon="🌳"
        />
        <StatCard
          title="Typosquatting"
          value={data.typosquatting?.is_suspect ? 'SUSPECT' : 'CLEAR'}
          color={data.typosquatting?.is_suspect ? '#ef4444' : '#22c55e'}
          icon="🔤"
        />
        <StatCard
          title="Behavioral Risk"
          value={data.behavioral?.risk_score || 0}
          color={data.behavioral?.risk_score > 30 ? '#f97316' : '#22c55e'}
          icon="🧠"
        />
      </div>

      {/* ── TABS ── */}
      <div className="tabs-container">
        <div className="tabs-header">
          {tabs.map(tab => (
            <button
              key={tab.id}
              className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="tab-content">
          {activeTab === 'overview' && <OverviewTab data={data} />}
          {activeTab === 'metadata' && <MetadataTab data={data} />}
          {activeTab === 'vulnerabilities' && <VulnerabilitiesTab data={data} />}
          {activeTab === 'code' && <CodeAnalysisTab data={data} />}
          {activeTab === 'behavioral' && <BehavioralTab data={data} />}
          {activeTab === 'dependencies' && <DependenciesTab data={data} />}
          {activeTab === 'evidence' && <EvidenceTab data={data} />}
          {activeTab === 'recommendations' && <RecommendationsTab data={data} />}
        </div>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════
   STAT CARD COMPONENT
   ════════════════════════════════════════════ */

function StatCard({ title, value, color, icon }) {
  return (
    <div className="stat-card">
      <div className="stat-icon">{icon}</div>
      <div className="stat-value" style={{ color }}>{value}</div>
      <div className="stat-title">{title}</div>
    </div>
  );
}

/* ════════════════════════════════════════════
   OVERVIEW TAB
   ════════════════════════════════════════════ */

function OverviewTab({ data }) {
  return (
    <div className="tab-panel">
      <div className="overview-grid">
        {/* Risk Gauge */}
        <div className="panel-card">
          <h3 className="card-title">Risk Score</h3>
          <RiskGauge
            score={data.risk_score}
            level={data.risk_level}
            color={data.risk_color}
          />
        </div>

        {/* Category Breakdown */}
        <div className="panel-card">
          <h3 className="card-title">Risk Category Breakdown</h3>
          <CategoryBreakdown breakdown={data.category_breakdown} />
        </div>

        {/* Vulnerability Summary */}
        <div className="panel-card">
          <h3 className="card-title">Vulnerability Summary</h3>
          <VulnerabilityChart vulnerabilities={data.vulnerabilities} />
        </div>

        {/* Behavioral Radar */}
        <div className="panel-card">
          <h3 className="card-title">Behavioral Profile</h3>
          <BehavioralRadar behavioral={data.behavioral} />
        </div>
      </div>

      {/* Typosquatting Alert */}
      {data.typosquatting?.is_suspect && (
        <div className="alert-card critical">
          <span className="alert-icon">🚨</span>
          <div>
            <strong>Typosquatting Alert!</strong>
            <p>
              This package name is suspiciously similar to
              <strong> "{data.typosquatting.closest_match}"</strong>.
              Detection techniques: {data.typosquatting.techniques?.join(', ')}.
              Please verify you have the correct package.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════
   METADATA TAB
   ════════════════════════════════════════════ */

function MetadataTab({ data }) {
  const info = data.metadata?.package_info || {};
  const checks = data.metadata?.checks || [];

  return (
    <div className="tab-panel">
      {/* Package Info Grid */}
      <div className="panel-card">
        <h3 className="card-title">Package Information</h3>
        <div className="info-grid">
          <InfoRow label="Name" value={info.name} />
          <InfoRow label="Version" value={info.version} />
          <InfoRow label="Author" value={
            typeof info.author === 'object'
              ? info.author?.name || JSON.stringify(info.author)
              : info.author || 'N/A'
          } />
          <InfoRow label="License" value={info.license || 'N/A'} />
          <InfoRow label="Maintainers" value={info.maintainers?.join(', ') || 'N/A'} />
          <InfoRow label="Versions Published" value={info.version_count} />
          <InfoRow label="Dependencies" value={info.dependency_count} />
          <InfoRow label="Has Repository" value={info.has_repository ? '✅ Yes' : '❌ No'} />
          <InfoRow label="Published" value={info.publish_time || 'N/A'} />
        </div>
      </div>

      {/* Metadata Checks */}
      <div className="panel-card">
        <h3 className="card-title">
          Metadata Checks ({checks.length})
        </h3>
        <div className="checks-list">
          {checks.map((check, i) => (
            <div
              key={i}
              className={`check-item ${check.flagged ? 'flagged' : 'passed'}`}
            >
              <span className="check-icon">
                {check.flagged ? '⚠️' : '✅'}
              </span>
              <div className="check-content">
                <div className="check-name">{check.name}</div>
                <div className="check-desc">{check.description}</div>
              </div>
              {check.flagged && (
                <span className={`severity-badge ${check.severity}`}>
                  {check.severity}
                </span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div className="info-row">
      <span className="info-label">{label}</span>
      <span className="info-value">{value ?? 'N/A'}</span>
    </div>
  );
}

/* ════════════════════════════════════════════
   VULNERABILITIES TAB
   ════════════════════════════════════════════ */

function VulnerabilitiesTab({ data }) {
  const vulns = data.vulnerabilities || {};

  return (
    <div className="tab-panel">
      {/* Summary */}
      <div className="panel-card">
        <h3 className="card-title">Vulnerability Summary</h3>
        <div className="vuln-summary-grid">
          <div className="vuln-stat critical-bg">
            <div className="vuln-stat-num">{vulns.critical || 0}</div>
            <div className="vuln-stat-label">Critical</div>
          </div>
          <div className="vuln-stat high-bg">
            <div className="vuln-stat-num">{vulns.high || 0}</div>
            <div className="vuln-stat-label">High</div>
          </div>
          <div className="vuln-stat medium-bg">
            <div className="vuln-stat-num">{vulns.medium || 0}</div>
            <div className="vuln-stat-label">Medium</div>
          </div>
          <div className="vuln-stat low-bg">
            <div className="vuln-stat-num">{vulns.low || 0}</div>
            <div className="vuln-stat-label">Low</div>
          </div>
        </div>
        <p className="sources-text">
          Sources checked: {vulns.sources_checked?.join(', ') || 'None'}
        </p>
      </div>

      {/* Vulnerability Details */}
      {vulns.details && vulns.details.length > 0 && (
        <div className="panel-card">
          <h3 className="card-title">
            Vulnerability Details ({vulns.details.length})
          </h3>
          <div className="vuln-list">
            {vulns.details.map((vuln, i) => (
              <div key={i} className="vuln-item">
                <div className="vuln-header">
                  <span className={`severity-badge ${vuln.severity?.toLowerCase()}`}>
                    {vuln.severity}
                  </span>
                  <span className="vuln-id">{vuln.id}</span>
                  <span className="vuln-source">via {vuln.source}</span>
                </div>
                <p className="vuln-summary">{vuln.summary}</p>
                {vuln.references && vuln.references.length > 0 && (
                  <div className="vuln-refs">
                    {vuln.references.slice(0, 2).map((ref, j) => (
                      <a
                        key={j}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="vuln-ref-link"
                      >
                        Reference {j + 1} ↗
                      </a>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {(!vulns.details || vulns.details.length === 0) && (
        <div className="panel-card empty-state">
          <span className="empty-icon">✅</span>
          <h4>No Known Vulnerabilities Found</h4>
          <p>No CVEs or advisories were found for this package version.</p>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════
   CODE ANALYSIS TAB
   ════════════════════════════════════════════ */

function CodeAnalysisTab({ data }) {
  const code = data.code_analysis || {};

  return (
    <div className="tab-panel">
      <div className="panel-card">
        <h3 className="card-title">Static Analysis Summary</h3>
        <div className="code-stats">
          <div className="code-stat">
            <span className="code-stat-label">Risk Score</span>
            <span className="code-stat-value">{code.risk_score || 0}/100</span>
          </div>
          <div className="code-stat">
            <span className="code-stat-label">Issues Found</span>
            <span className="code-stat-value">{code.total_issues || 0}</span>
          </div>
          <div className="code-stat">
            <span className="code-stat-label">Entropy Score</span>
            <span className="code-stat-value">
              {code.entropy_score?.toFixed(2) || '0.00'}
            </span>
          </div>
          <div className="code-stat">
            <span className="code-stat-label">Obfuscation</span>
            <span className="code-stat-value">
              {code.obfuscation_detected ? '⚠️ Detected' : '✅ None'}
            </span>
          </div>
        </div>
      </div>

      {/* Issues List */}
      {code.issues && code.issues.length > 0 && (
        <div className="panel-card">
          <h3 className="card-title">Issues ({code.issues.length})</h3>
          <div className="issues-list">
            {code.issues.map((issue, i) => (
              <div key={i} className={`issue-item ${issue.severity}`}>
                <span className={`severity-badge ${issue.severity}`}>
                  {issue.severity}
                </span>
                <span className="issue-type">[{issue.type}]</span>
                <span className="issue-desc">{issue.description}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Encoded Payloads */}
      {code.encoded_payloads && code.encoded_payloads.length > 0 && (
        <div className="panel-card">
          <h3 className="card-title">⚠️ Encoded Payloads Detected</h3>
          {code.encoded_payloads.map((payload, i) => (
            <div key={i} className="payload-item">
              <span className="payload-type">{payload.type}</span>
              <code className="payload-preview">{payload.value_preview}</code>
              <span className="payload-length">Length: {payload.length}</span>
            </div>
          ))}
        </div>
      )}

      {/* Suspicious URLs */}
      {code.suspicious_urls && code.suspicious_urls.length > 0 && (
        <div className="panel-card">
          <h3 className="card-title">🔗 Suspicious URLs</h3>
          {code.suspicious_urls.map((url, i) => (
            <div key={i} className="url-item">
              <code>{url.url}</code>
              <span className="url-reason">{url.reason}</span>
            </div>
          ))}
        </div>
      )}

      {(!code.issues || code.issues.length === 0) && (
        <div className="panel-card empty-state">
          <span className="empty-icon">✅</span>
          <h4>No Code Issues Detected</h4>
          <p>Static analysis found no suspicious patterns in available code.</p>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════
   BEHAVIORAL TAB
   ════════════════════════════════════════════ */

function BehavioralTab({ data }) {
  const behavioral = data.behavioral || {};

  return (
    <div className="tab-panel">
      <div className="panel-card">
        <h3 className="card-title">Behavioral Profile</h3>
        <div className="behavioral-header">
          <div className="behavioral-score">
            <span>Risk Score: </span>
            <strong>{behavioral.risk_score || 0}/100</strong>
          </div>
          {behavioral.dominant_behavior && (
            <div className="dominant-behavior">
              Dominant: <strong>{behavioral.dominant_behavior}</strong>
            </div>
          )}
        </div>
        <p className="behavioral-assessment">{behavioral.assessment}</p>
      </div>

      {/* Behavioral Radar */}
      <div className="panel-card">
        <h3 className="card-title">Behavior Radar</h3>
        <BehavioralRadar behavioral={behavioral} />
      </div>

      {/* Behavior Summary */}
      {behavioral.summary && behavioral.summary.length > 0 && (
        <div className="panel-card">
          <h3 className="card-title">Behavior Breakdown</h3>
          <div className="behavior-list">
            {behavioral.summary.map((item, i) => (
              <div key={i} className="behavior-item">
                <div className="behavior-name">{item.category}</div>
                <div className="behavior-desc">{item.description}</div>
                <div className="behavior-bar-container">
                  <div
                    className="behavior-bar"
                    style={{
                      width: `${Math.min(item.weighted_score * 5, 100)}%`,
                      background: item.weighted_score > 10 ? '#ef4444' :
                                  item.weighted_score > 5 ? '#f97316' : '#3b82f6'
                    }}
                  />
                </div>
                <span className="behavior-count">{item.count} detections</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Fingerprint Vector */}
      {behavioral.fingerprint && Object.keys(behavioral.fingerprint).length > 0 && (
        <div className="panel-card">
          <h3 className="card-title">Fingerprint Vector</h3>
          <div className="fingerprint-grid">
            {Object.entries(behavioral.fingerprint).map(([key, value]) => (
              <div key={key} className="fingerprint-item">
                <span className="fp-key">{key}</span>
                <span className="fp-value">{value}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════
   DEPENDENCIES TAB
   ════════════════════════════════════════════ */

function DependenciesTab({ data }) {
  const graph = data.dependency_graph || {};

  return (
    <div className="tab-panel">
      <div className="panel-card">
        <h3 className="card-title">Dependency Graph Overview</h3>
        <div className="dep-stats">
          <div className="dep-stat">
            <span className="dep-stat-num">{graph.total_dependencies || 0}</span>
            <span className="dep-stat-label">Total Dependencies</span>
          </div>
          <div className="dep-stat">
            <span className="dep-stat-num">{graph.critical_nodes?.length || 0}</span>
            <span className="dep-stat-label">Critical Nodes</span>
          </div>
          <div className="dep-stat">
            <span className="dep-stat-num">
              {graph.blast_radius?.percentage?.toFixed(1) || 0}%
            </span>
            <span className="dep-stat-label">Blast Radius</span>
          </div>
        </div>
      </div>

      {/* Graph Visualization */}
      {graph.graph_data && graph.graph_data.nodes?.length > 0 && (
        <div className="panel-card">
          <h3 className="card-title">Dependency Tree</h3>
          <DependencyGraphView graphData={graph.graph_data} />
        </div>
      )}

      {/* Critical Nodes */}
      {graph.critical_nodes && graph.critical_nodes.length > 0 && (
        <div className="panel-card">
          <h3 className="card-title">⚠️ Critical Nodes</h3>
          <p className="card-subtitle">
            These packages are single points of failure in your dependency tree.
          </p>
          <div className="critical-nodes-list">
            {graph.critical_nodes.map((node, i) => (
              <div key={i} className="critical-node-item">
                <span className="node-name">{node.package}</span>
                <span className="node-score">
                  Centrality: {node.centrality || node.dependent_count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Risk Factors */}
      {graph.risk_factors && graph.risk_factors.length > 0 && (
        <div className="panel-card">
          <h3 className="card-title">Risk Factors</h3>
          {graph.risk_factors.map((factor, i) => (
            <div key={i} className="risk-factor-item">
              <span>⚠️</span> {factor}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════
   EVIDENCE TAB
   ════════════════════════════════════════════ */

function EvidenceTab({ data }) {
  const evidence = data.evidence || [];

  return (
    <div className="tab-panel">
      <div className="panel-card">
        <h3 className="card-title">Evidence Trail ({evidence.length} items)</h3>
        <p className="card-subtitle">
          Complete audit trail of all detection signals.
        </p>

        {evidence.length > 0 ? (
          <div className="evidence-list">
            <div className="evidence-header-row">
              <span>Source</span>
              <span>Description</span>
              <span>Severity</span>
              <span>Score</span>
            </div>
            {evidence.map((item, i) => (
              <div key={i} className="evidence-row">
                <span className="evidence-source">{item.source}</span>
                <span className="evidence-desc">{item.description}</span>
                <span className={`severity-badge ${item.severity}`}>
                  {item.severity}
                </span>
                <span className="evidence-score">{item.score}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <span className="empty-icon">✅</span>
            <h4>No Evidence Collected</h4>
            <p>No suspicious signals were detected during the scan.</p>
          </div>
        )}
      </div>

      {/* Category Breakdown */}
      <div className="panel-card">
        <h3 className="card-title">Score Breakdown</h3>
        <CategoryBreakdown breakdown={data.category_breakdown} />
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════
   RECOMMENDATIONS TAB
   ════════════════════════════════════════════ */

function RecommendationsTab({ data }) {
  const recommendations = data.recommendations || [];

  const priorityColors = {
    CRITICAL: '#ef4444',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#22c55e',
    INFO: '#3b82f6'
  };

  return (
    <div className="tab-panel">
            {/* Export Buttons */}
      <div className="panel-card">
        <h3 className="card-title">📥 Export</h3>
        <div className="export-buttons">
          <button
            className="export-btn"
            onClick={() => {
              const blob = new Blob(
                [JSON.stringify(data.report, null, 2)],
                { type: 'application/json' }
              );
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `scan_report_${data.package_name}_${Date.now()}.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            📄 Download Full Report (JSON)
          </button>

          <button
            className="export-btn"
            onClick={() => {
              const text = generateTextReport(data);
              const blob = new Blob([text], { type: 'text/plain' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `scan_report_${data.package_name}_${Date.now()}.txt`;
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            📝 Download Summary (TXT)
          </button>
        </div>
      </div>

      {/* SBOM Summary */}
      {data.sbom_summary && (
        <div className="panel-card">
          <h3 className="card-title">📦 SBOM Summary</h3>
          <div className="info-grid">
            <InfoRow label="Total Components" value={data.sbom_summary.total_components} />
            <InfoRow label="Total Vulnerabilities" value={data.sbom_summary.total_vulnerabilities} />
            <InfoRow label="High Risk Components" value={data.sbom_summary.high_risk_components} />
            <InfoRow label="Generated At" value={data.sbom_summary.generated_at} />
          </div>
        </div>
      )}
    </div>
  );
}
function generateTextReport(data) {
  let lines = [];
  lines.push('='.repeat(60));
  lines.push('  SUPPLY CHAIN GUARD - SECURITY SCAN REPORT');
  lines.push('='.repeat(60));
  lines.push(`  Package: ${data.package_name}`);
  lines.push(`  Version: ${data.version || 'latest'}`);
  lines.push(`  Ecosystem: ${data.ecosystem}`);
  lines.push(`  Risk Score: ${data.risk_score}/100`);
  lines.push(`  Risk Level: ${data.risk_level}`);
  lines.push(`  Action: ${data.recommended_action}`);
  lines.push('');
  lines.push('-'.repeat(60));
  lines.push('  VULNERABILITIES');
  lines.push(`  Total: ${data.vulnerabilities?.total || 0}`);
  lines.push(`  Critical: ${data.vulnerabilities?.critical || 0}`);
  lines.push(`  High: ${data.vulnerabilities?.high || 0}`);
  lines.push('');
  lines.push('-'.repeat(60));
  lines.push('  RECOMMENDATIONS');
  data.recommendations?.forEach(rec => {
    lines.push(`  [${rec.priority}] ${rec.action}`);
  });
  lines.push('');
  lines.push('='.repeat(60));
  return lines.join('\n');
}
export default ScanResults;