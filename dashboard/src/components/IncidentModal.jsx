import React, { useState } from "react";
import {
  X,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Copy,
  Check,
  Ban,
  Clock,
  Server,
  Terminal,
} from "lucide-react";

export function IncidentModal({ incident, onClose, onStatusUpdate, onIPOverride }) {
  const [copied, setCopied] = useState(false);
  const [analystNotes, setAnalystNotes] = useState(incident?.analyst_notes || "");
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);

  if (!incident) return null;

  function handleCopyPayload() {
    if (incident.raw_payload) {
      navigator.clipboard.writeText(incident.raw_payload);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  async function handleStatusChange(newStatus) {
    try {
      setActionLoading(true);
      await onStatusUpdate(incident.id, newStatus, analystNotes);
      setActionMessage(`Status updated to ${newStatus}`);
      setTimeout(() => setActionMessage(null), 3000);
    } catch (err) {
      setActionMessage(`Error: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  }

  async function handleIPAction(action) {
    try {
      setActionLoading(true);
      await onIPOverride(incident.client_ip, action, `Analyst action from incident ${incident.id}`);
      setActionMessage(`IP ${incident.client_ip} set to ${action}`);
      setTimeout(() => setActionMessage(null), 3000);
    } catch (err) {
      setActionMessage(`Error: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  }

  const riskScore = incident.risk_score || 0;
  const components = incident.risk_components || {};
  const mlContrib = components.ml ?? (incident.attack_type !== "benign" ? (incident.confidence * 70).toFixed(1) : 0);
  const threatContrib = components.threat_intel ?? 0;
  const behaviorContrib = components.behavior ?? 0;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header">
          <div className="modal-title-group">
            <ShieldAlert className="modal-title-icon" size={24} />
            <div>
              <h3>Security Incident Forensics</h3>
              <div className="incident-id-tag">ID: <code>{incident.id}</code></div>
            </div>
          </div>
          <button type="button" className="modal-close-btn" onClick={onClose}>
            <X size={20} />
          </button>
        </div>

        {/* Action feedback banner */}
        {actionMessage && <div className="modal-banner">{actionMessage}</div>}

        <div className="modal-body">
          {/* Top meta tags */}
          <div className="modal-meta-row">
            <span className={`badge verdict-${(incident.verdict || "allow").toLowerCase()}`}>
              Verdict: {incident.verdict}
            </span>
            <span className="badge badge-attack">
              Attack: {incident.attack_type?.toUpperCase()}
            </span>
            <span className={`badge status-${(incident.status || "open").toLowerCase()}`}>
              Status: {incident.status || "OPEN"}
            </span>
            <span className="badge badge-time">
              <Clock size={12} style={{ marginRight: 4 }} />
              {new Date(incident.timestamp * 1000).toLocaleString()}
            </span>
          </div>

          <div className="modal-grid">
            {/* Left Column: Request Details */}
            <div className="modal-column">
              <h4>Request Ingress Attributes</h4>
              <div className="detail-item">
                <span className="detail-label">Client IP:</span>
                <span className="detail-value">
                  <code>{incident.client_ip}</code>
                </span>
              </div>
              <div className="detail-item">
                <span className="detail-label">HTTP Method:</span>
                <span className="detail-value"><code>{incident.method || "GET"}</code></span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Request URI:</span>
                <span className="detail-value"><code>{incident.path || "/"}</code></span>
              </div>
              <div className="detail-item">
                <span className="detail-label">ML Confidence:</span>
                <span className="detail-value">{(incident.confidence * 100).toFixed(1)}%</span>
              </div>

              {/* Payload viewer */}
              <div className="payload-box-container">
                <div className="payload-header">
                  <span>Inspectable Payload</span>
                  <button
                    type="button"
                    className="btn-copy"
                    onClick={handleCopyPayload}
                    title="Copy payload"
                  >
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                    <span>{copied ? "Copied" : "Copy"}</span>
                  </button>
                </div>
                <pre className="payload-code">{incident.raw_payload || "(empty payload)"}</pre>
              </div>
            </div>

            {/* Right Column: Risk Decomposition */}
            <div className="modal-column">
              <h4>Multi-Factor Risk Breakdown</h4>
              <div className="risk-gauge-container">
                <div className="risk-gauge-header">
                  <span>Total Cumulative Risk</span>
                  <strong>{riskScore} / 100</strong>
                </div>
                <div className="progress-bar-bg">
                  <div
                    className={`progress-bar-fill ${
                      riskScore >= 80 ? "fill-critical" : riskScore >= 40 ? "fill-medium" : "fill-low"
                    }`}
                    style={{ width: `${Math.min(riskScore, 100)}%` }}
                  />
                </div>
              </div>

              <div className="component-list">
                <div className="component-row">
                  <div className="component-meta">
                    <span>ML Deep Learning (CNN+BiLSTM)</span>
                    <span className="component-weight">Weight: 70%</span>
                  </div>
                  <div className="component-value">{mlContrib} pts</div>
                </div>

                <div className="component-row">
                  <div className="component-meta">
                    <span>Threat Intelligence (IP Reputation)</span>
                    <span className="component-weight">Weight: 15%</span>
                  </div>
                  <div className="component-value">{threatContrib} pts</div>
                </div>

                <div className="component-row">
                  <div className="component-meta">
                    <span>Behavioral Velocity & Anomaly</span>
                    <span className="component-weight">Weight: 15%</span>
                  </div>
                  <div className="component-value">{behaviorContrib} pts</div>
                </div>
              </div>

              {/* Analyst Action Center */}
              <div className="analyst-center">
                <h4>SOC Analyst Action Center</h4>
                <div className="analyst-notes-container">
                  <input
                    type="text"
                    className="notes-input"
                    placeholder="Add triage notes or rationale..."
                    value={analystNotes}
                    onChange={(e) => setAnalystNotes(e.target.value)}
                  />
                </div>

                <div className="action-buttons-group">
                  <button
                    type="button"
                    className="btn-action btn-true-pos"
                    disabled={actionLoading}
                    onClick={() => handleStatusChange("TRUE_POSITIVE")}
                  >
                    <ShieldAlert size={14} /> True Positive
                  </button>
                  <button
                    type="button"
                    className="btn-action btn-false-pos"
                    disabled={actionLoading}
                    onClick={() => handleStatusChange("FALSE_POSITIVE")}
                  >
                    <ShieldCheck size={14} /> False Positive
                  </button>
                  <button
                    type="button"
                    className="btn-action btn-resolve"
                    disabled={actionLoading}
                    onClick={() => handleStatusChange("RESOLVED")}
                  >
                    <Check size={14} /> Resolve
                  </button>
                </div>

                <div className="firewall-override-group">
                  <button
                    type="button"
                    className="btn-action btn-block-ip"
                    disabled={actionLoading}
                    onClick={() => handleIPAction("BLACKLIST")}
                  >
                    <Ban size={14} /> Blacklist IP
                  </button>
                  <button
                    type="button"
                    className="btn-action btn-whitelist-ip"
                    disabled={actionLoading}
                    onClick={() => handleIPAction("WHITELIST")}
                  >
                    <ShieldCheck size={14} /> Whitelist IP
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default IncidentModal;
