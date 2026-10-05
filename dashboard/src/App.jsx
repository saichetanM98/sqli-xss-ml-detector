import React, { useEffect, useState } from "react";
import { Shield, ShieldAlert, Cpu, Database, Activity, RefreshCw } from "lucide-react";
import Dashboard from "./pages/Dashboard";
import { fetchHealth } from "./api/client";

export function App() {
  const [health, setHealth] = useState(null);
  const [healthLoading, setHealthLoading] = useState(true);

  async function checkGatewayHealth() {
    try {
      setHealthLoading(true);
      const data = await fetchHealth();
      setHealth(data);
    } catch {
      setHealth({ status: "offline", service: "gateway-unreachable" });
    } finally {
      setHealthLoading(false);
    }
  }

  useEffect(() => {
    checkGatewayHealth();
    const interval = setInterval(checkGatewayHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const isOnline = health?.status === "healthy";

  return (
    <div className="soc-shell">
      <nav className="soc-navbar">
        <div className="soc-nav-brand">
          <Shield className="brand-icon" size={28} />
          <div>
            <div className="brand-title">ADAPTIVE SECURITY GATEWAY</div>
            <div className="brand-subtitle">AI ML-Driven SQLi & XSS Detection</div>
          </div>
        </div>

        <div className="soc-nav-status">
          <div className={`status-pill ${isOnline ? "status-online" : "status-offline"}`}>
            <Activity size={14} className={isOnline ? "spin-pulse" : ""} />
            <span>Gateway: {isOnline ? "ONLINE" : "DISCONNECTED"}</span>
          </div>

          {health?.cuda_available && (
            <div className="status-pill status-gpu">
              <Cpu size={14} />
              <span>RTX 3050 GPU (CUDA)</span>
            </div>
          )}

          <div className="status-pill status-db">
            <Database size={14} />
            <span>DB: {health?.database?.type?.toUpperCase() || "IN-MEMORY"}</span>
          </div>

          <button
            type="button"
            className="btn-refresh"
            onClick={checkGatewayHealth}
            title="Refresh status"
            disabled={healthLoading}
          >
            <RefreshCw size={14} className={healthLoading ? "spin-slow" : ""} />
          </button>
        </div>
      </nav>

      <div className="soc-content">
        <Dashboard gatewayHealth={health} />
      </div>
    </div>
  );
}

export default App;
