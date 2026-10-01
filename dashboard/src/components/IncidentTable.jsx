import React from "react";

export function IncidentTable({ incidents = [], onSelectIncident }) {
  if (!incidents.length) {
    return (
      <div className="empty-state">
        <p>No incidents detected yet.</p>
      </div>
    );
  }

  return (
    <div className="table-container">
      <table className="incident-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Client IP</th>
            <th>Type</th>
            <th>Confidence</th>
            <th>Risk Score</th>
            <th>Verdict</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((inc) => (
            <tr key={inc.id} className={`verdict-${inc.verdict.toLowerCase()}`}>
              <td>{new Date(inc.timestamp * 1000).toLocaleTimeString()}</td>
              <td><code>{inc.client_ip}</code></td>
              <td><span className="badge badge-attack">{inc.attack_type.toUpperCase()}</span></td>
              <td>{(inc.confidence * 100).toFixed(1)}%</td>
              <td><strong>{inc.risk_score}</strong>/100</td>
              <td>
                <span className={`badge verdict-${inc.verdict.toLowerCase()}`}>
                  {inc.verdict}
                </span>
              </td>
              <td>
                <button
                  type="button"
                  className="btn-sm"
                  onClick={() => onSelectIncident?.(inc)}
                >
                  Review
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default IncidentTable;
