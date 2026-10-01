/**
 * API client functions for connecting dashboard to Flask gateway.
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

export async function fetchIncidents() {
  const response = await fetch(`${API_BASE_URL}/incidents`);
  if (!response.ok) {
    throw new Error(`Failed to fetch incidents: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchAnalyticsSummary() {
  const response = await fetch(`${API_BASE_URL}/analytics/summary`);
  if (!response.ok) {
    throw new Error(`Failed to fetch analytics: ${response.statusText}`);
  }
  return response.json();
}
