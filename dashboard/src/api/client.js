/**
 * API client functions for connecting dashboard to Flask gateway.
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

export async function fetchHealth() {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) {
    throw new Error(`Failed to fetch health: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchIncidents(params = {}) {
  const url = new URL(`${API_BASE_URL}/api/incidents`);
  Object.entries(params).forEach(([key, val]) => {
    if (val !== undefined && val !== null && val !== "") {
      url.searchParams.append(key, val);
    }
  });

  const response = await fetch(url.toString());
  if (!response.ok) {
    throw new Error(`Failed to fetch incidents: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchIncidentById(id) {
  const response = await fetch(`${API_BASE_URL}/api/incidents/${id}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch incident ${id}: ${response.statusText}`);
  }
  return response.json();
}

export async function updateIncidentStatus(id, { status, notes = "" }) {
  const response = await fetch(`${API_BASE_URL}/api/incidents/${id}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status, notes }),
  });
  if (!response.ok) {
    throw new Error(`Failed to update status: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchAnalyticsSummary() {
  const response = await fetch(`${API_BASE_URL}/api/analytics/summary`);
  if (!response.ok) {
    throw new Error(`Failed to fetch analytics: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchAnalyticsTrends(limit = 12) {
  const response = await fetch(`${API_BASE_URL}/api/analytics/trends?limit=${limit}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch trends: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchTopOffenders(limit = 5) {
  const response = await fetch(`${API_BASE_URL}/api/analytics/top-ips?limit=${limit}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch top offenders: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchIPOverrides() {
  const response = await fetch(`${API_BASE_URL}/api/policy/override-ip`);
  if (!response.ok) {
    throw new Error(`Failed to fetch IP overrides: ${response.statusText}`);
  }
  return response.json();
}

export async function setIPOverride({ ip, action, reason = "" }) {
  const response = await fetch(`${API_BASE_URL}/api/policy/override-ip`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, action, reason }),
  });
  if (!response.ok) {
    throw new Error(`Failed to set IP override: ${response.statusText}`);
  }
  return response.json();
}
