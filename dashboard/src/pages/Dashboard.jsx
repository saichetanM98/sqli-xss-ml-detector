import React, { useEffect, useState, useCallback, useRef } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Activity,
  Play,
  Pause,
  RefreshCw,
  Ban,
  UserX,
  TrendingUp,
} from "lucide-react";
import IncidentTable from "../components/IncidentTable";
import IncidentModal from "../components/IncidentModal";
import {
  fetchIncidents,
  fetchAnalyticsSummary,
  fetchTopOffenders,
  updateIncidentStatus,
  setIPOverride,
} from "../api/client";

export function Dashboard() {
  const [incidents, setIncidents] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [topOffenders, setTopOffenders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [isPolling, setIsPolling] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  const [filters, setFilters] = useState({
    verdict: "ALL",
    attack_type: "ALL",
    status: "ALL",
    search: "",
  });

  const loadData = useCallback(async () => {
    try {
      const [incRes, anaRes, offRes] = await Promise.all([
        fetchIncidents({
          verdict: filters.verdict !== "ALL" ? filters.verdict : undefined,
          attack_type: filters.attack_type !== "ALL" ? filters.attack_type : undefined,
          status: filters.status !== "ALL" ? filters.status : undefined,
          search: filters.search || undefined,
          limit: 50,
        }),
        fetchAnalyticsSummary(),
        fetchTopOffenders(5),
      ]);

      const items = incRes?.data?.items || incRes?.data || [];
      setIncidents(items);
      setAnalytics(anaRes?.data || null);
      setTopOffenders(offRes?.data || []);
      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Real-time polling loop
  useEffect(() => {
    if (!isPolling) return;
    const interval = setInterval(() => {
      loadData();
    }, 3000);
    return () => clearInterval(interval);
  }, [isPolling, loadData]);

  // Handler for updating triage status from Modal
  async function handleStatusUpdate(incidentId, newStatus, notes) {
    const updated = await updateIncidentStatus(incidentId, { status: newStatus, notes });
    // Update local state
    setIncidents((prev) =>
      prev.map((i) => (i.id === incidentId ? { ...i, status: newStatus, analyst_notes: notes } : i))
    );
    if (selectedIncident && selectedIncident.id === incidentId) {
      setSelectedIncident((prev) => ({ ...prev, status: newStatus, analyst_notes: notes }));
    }
    fetchAnalyticsSummary().then((res) => setAnalytics(res.data));
    return updated;
  }

  // Handler for IP block/whitelist from Modal
  async function handleIPOverride(ip, action, reason) {
    const res = await setIPOverride({ ip, action, reason });
    fetchAnalyticsSummary().then((r) => setAnalytics(r.data));
    return res;
  }

  const blockedCount = analytics?.blocked_count ?? (analytics?.verdict_distribution?.BLOCK || 0);
  const monitoredCount = analytics?.monitored_count ?? (analytics?.verdict_distribution?.MONITOR || 0);
  const rateLimitedCount = analytics?.rate_limited_count ?? (analytics?.verdict_distribution?.RATE_LIMIT || 0);
  const sqliCount = analytics?.attack_distribution?.sqli || 0;
  const xssCount = analytics?.attack_distribution?.xss || 0;
  const totalIncidents = analytics?.total_incidents || incidents.length;
  const blockRate = analytics?.block_rate_percentage ?? (totalIncidents > 0 ? ((blockedCount / totalIncidents) * 100).toFixed(1) : 0);

  return (
    <div className="soc-dashboard">
      {/* Header & Feed Control Bar */}
      <header className="dashboard-header">
        <div>
          <h1>Security Operations Center (SOC) Command Feed</h1>
          <p className="subtitle">Real-time deep learning anomaly detection & automated policy enforcement</p>
        </div>

        <div className="feed-controls">
          <div className="live-indicator">
            <span className={`pulse-dot ${isPolling ? "dot-active" : "dot-paused"}`} />
            <span>{isPolling ? "LIVE FEED (3s)" : "FEED PAUSED"}</span>
          </div>

          <button
            type="button"
            className={`btn-toggle-feed ${isPolling ? "btn-feed-pause" : "btn-feed-resume"}`}
            onClick={() => setIsPolling(!isPolling)}
          >
            {isPolling ? <Pause size={14} /> : <Play size={14} />}
            <span>{isPolling ? "Pause" : "Resume"}</span>
          </button>

          <button
            type="button"
            className="btn-refresh-feed"
            onClick={loadData}
            title="Refresh now"
          >
            <RefreshCw size={14} />
            <span>Refresh</span>
          </button>

          <span className="last-sync-time">
            Updated: {lastUpdated.toLocaleTimeString()}
          </span>
        </div>
      </header>

      {error && <div className="alert-banner">Error communicating with gateway: {error}</div>}

      {/* KPI Metrics Cards */}
      <div className="metrics-grid">
        <div className="metric-card metric-total">
          <div className="metric-header">
            <span>Total Incidents</span>
            <Activity size={18} className="metric-icon" />
          </div>
          <p className="metric-value">{totalIncidents}</p>
          <span className="metric-foot">Cumulative telemetry logs</span>
        </div>

        <div className="metric-card metric-blocked">
          <div className="metric-header">
            <span>Critical Blocks</span>
            <Ban size={18} className="metric-icon icon-blocked" />
          </div>
          <p className="metric-value">{blockedCount}</p>
          <span className="metric-foot">{blockRate}% zero-tolerance block rate</span>
        </div>

        <div className="metric-card metric-monitored">
          <div className="metric-header">
            <span>Monitored Anomalies</span>
            <AlertTriangle size={18} className="metric-icon icon-monitored" />
          </div>
          <p className="metric-value">{monitoredCount}</p>
          <span className="metric-foot">Elevated risk scores (40–79)</span>
        </div>

        <div className="metric-card metric-ratelimit">
          <div className="metric-header">
            <span>Rate Limit Violations</span>
            <Flame size={18} className="metric-icon icon-rate" />
          </div>
          <p className="metric-value">{rateLimitedCount}</p>
          <span className="metric-foot">Sliding burst limit exceeded</span>
        </div>

        <div className="metric-card metric-sqli">
          <div className="metric-header">
            <span>SQLi Detected</span>
            <ShieldAlert size={18} className="metric-icon icon-sqli" />
          </div>
          <p className="metric-value">{sqliCount}</p>
          <span className="metric-foot">Deep learning SQLi matches</span>
        </div>

        <div className="metric-card metric-xss">
          <div className="metric-header">
            <span>XSS Detected</span>
            <ShieldAlert size={18} className="metric-icon icon-xss" />
          </div>
          <p className="metric-value">{xssCount}</p>
          <span className="metric-foot">Deep learning XSS matches</span>
        </div>
      </div>

      {/* Top Offenders Bar */}
      {topOffenders.length > 0 && (
        <div className="offenders-strip">
          <div className="offenders-label">
            <UserX size={16} />
            <span>Top Adversary IPs:</span>
          </div>
          <div className="offenders-list">
            {topOffenders.map((offender) => (
              <div key={offender.ip} className="offender-chip">
                <code>{offender.ip}</code>
                <span className="offender-count">{offender.incident_count} hits</span>
                <span className="offender-risk">Peak Risk: {offender.highest_risk}</span>
                <button
                  type="button"
                  className="btn-chip-action"
                  onClick={() => handleIPOverride(offender.ip, "BLACKLIST", "One-click block from top offender bar")}
                  title="Quick Blacklist"
                >
                  Block
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Main Incident Feed */}
      <main className="dashboard-main">
        <div className="feed-title-bar">
          <h2>Live Security Incident Log</h2>
          <span className="feed-counter">Showing {incidents.length} recorded entries</span>
        </div>

        {loading && incidents.length === 0 ? (
          <div className="loading-spinner">Loading incident feed from gateway...</div>
        ) : (
          <IncidentTable
            incidents={incidents}
            onSelectIncident={setSelectedIncident}
            filters={filters}
            onFilterChange={setFilters}
          />
        )}
      </main>

      {/* Forensic Drill-Down Modal */}
      {selectedIncident && (
        <IncidentModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onStatusUpdate={handleStatusUpdate}
          onIPOverride={handleIPOverride}
        />
      )}
    </div>
  );
}

export default Dashboard;
