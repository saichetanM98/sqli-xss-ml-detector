import React, { useState } from "react";
import { Search, Filter, Eye, AlertOctagon, ShieldCheck, Activity } from "lucide-react";

export function IncidentTable({ incidents = [], onSelectIncident, filters, onFilterChange }) {
  const [searchTerm, setSearchTerm] = useState(filters?.search || "");

  function handleSearchSubmit(e) {
    e.preventDefault();
    onFilterChange?.({ ...filters, search: searchTerm });
  }

  return (
    <div className="incident-table-wrapper">
      {/* Table Filters Bar */}
      <div className="table-controls-bar">
        <form className="search-form" onSubmit={handleSearchSubmit}>
          <Search size={16} className="search-icon" />
          <input
            type="text"
            className="search-input"
            placeholder="Search IP, path, or payload..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          <button type="submit" className="btn-search">Search</button>
        </form>

        <div className="filters-group">
          {/* Verdict Filter */}
          <select
            className="select-filter"
            value={filters?.verdict || "ALL"}
            onChange={(e) => onFilterChange?.({ ...filters, verdict: e.target.value })}
          >
            <option value="ALL">All Verdicts</option>
            <option value="BLOCK">BLOCK</option>
            <option value="MONITOR">MONITOR</option>
            <option value="RATE_LIMIT">RATE_LIMIT</option>
            <option value="ALLOW">ALLOW</option>
          </select>

          {/* Attack Type Filter */}
          <select
            className="select-filter"
            value={filters?.attack_type || "ALL"}
            onChange={(e) => onFilterChange?.({ ...filters, attack_type: e.target.value })}
          >
            <option value="ALL">All Attack Types</option>
            <option value="sqli">SQL Injection</option>
            <option value="xss">Cross-Site Scripting</option>
            <option value="benign">Benign</option>
          </select>

          {/* Status Filter */}
          <select
            className="select-filter"
            value={filters?.status || "ALL"}
            onChange={(e) => onFilterChange?.({ ...filters, status: e.target.value })}
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="TRUE_POSITIVE">TRUE POSITIVE</option>
            <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
            <option value="RESOLVED">RESOLVED</option>
          </select>
        </div>
      </div>

      {/* Main Table */}
      {!incidents.length ? (
        <div className="empty-state">
          <ShieldCheck size={36} className="empty-icon" />
          <p>No incidents found matching the selected criteria.</p>
        </div>
      ) : (
        <div className="table-container">
          <table className="incident-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Client IP</th>
                <th>Method & Path</th>
                <th>Attack Vector</th>
                <th>Confidence</th>
                <th>Risk Score</th>
                <th>Verdict</th>
                <th>Status</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((inc) => {
                const verdictClass = `verdict-${(inc.verdict || "allow").toLowerCase()}`;
                const riskClass =
                  inc.risk_score >= 80 ? "risk-critical" : inc.risk_score >= 40 ? "risk-medium" : "risk-low";

                return (
                  <tr key={inc.id} className="incident-row">
                    <td className="cell-time">
                      {new Date(inc.timestamp * 1000).toLocaleTimeString()}
                    </td>
                    <td className="cell-ip">
                      <code>{inc.client_ip}</code>
                    </td>
                    <td className="cell-path">
                      <span className="badge-method">{inc.method || "POST"}</span>
                      <span className="path-text" title={inc.path}>{inc.path || "/"}</span>
                    </td>
                    <td>
                      <span className={`badge badge-attack attack-${inc.attack_type}`}>
                        {inc.attack_type?.toUpperCase()}
                      </span>
                    </td>
                    <td>{(inc.confidence * 100).toFixed(1)}%</td>
                    <td>
                      <span className={`badge-risk ${riskClass}`}>
                        {inc.risk_score}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${verdictClass}`}>
                        {inc.verdict}
                      </span>
                    </td>
                    <td>
                      <span className={`badge status-${(inc.status || "open").toLowerCase()}`}>
                        {inc.status || "OPEN"}
                      </span>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn-inspect"
                        onClick={() => onSelectIncident?.(inc)}
                        title="Inspect Forensics"
                      >
                        <Eye size={14} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default IncidentTable;
