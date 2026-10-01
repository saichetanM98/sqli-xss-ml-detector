import React, { useEffect, useState } from "react";
import IncidentTable from "../components/IncidentTable";
import { fetchIncidents, fetchAnalyticsSummary } from "../api/client";

export function Dashboard() {
  const [incidents, setIncidents] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [incRes, anaRes] = await Promise.all([
          fetchIncidents(),
          fetchAnalyticsSummary(),
        ]);
        setIncidents(incRes.data || []);
        setAnalytics(anaRes.data || null);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  return (
    <div className="soc-dashboard">
      <header className="dashboard-header">
        <h1>AI-Based Adaptive Security Gateway — SOC Dashboard</h1>
        <p>Real-time threat monitoring and incident analysis</p>
      </header>

      {error && <div className="alert-banner">{error}</div>}

      {analytics && (
        <div className="metrics-grid">
          <div className="metric-card">
            <h3>Total Incidents</h3>
            <p className="metric-value">{analytics.total_incidents}</p>
          </div>
          <div className="metric-card">
            <h3>Blocked Requests</h3>
            <p className="metric-value">{analytics.verdict_distribution?.BLOCK || 0}</p>
          </div>
          <div className="metric-card">
            <h3>Monitored Requests</h3>
            <p className="metric-value">{analytics.verdict_distribution?.MONITOR || 0}</p>
          </div>
        </div>
      )}

      <main className="dashboard-main">
        <h2>Live Incidents</h2>
        {loading ? (
          <div className="loading-spinner">Loading incident feeds...</div>
        ) : (
          <IncidentTable incidents={incidents} />
        )}
      </main>
    </div>
  );
}

export default Dashboard;
