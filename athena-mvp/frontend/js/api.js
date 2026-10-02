// Single API client. Base URL comes from js/config.js.
const API = (window.ATHENA_API_URL || "http://localhost:5000").replace(/\/$/, "");
let token = localStorage.getItem("athena_token");
const setToken = (t) => { token = t; t ? localStorage.setItem("athena_token", t) : localStorage.removeItem("athena_token"); };

async function req(path, method = "GET", body, raw = false) {
  let res;
  try {
    res = await fetch(API + path, { method, body: body ? JSON.stringify(body) : undefined,
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}) } });
  } catch { throw new Error("Cannot reach the ATHENA API at " + API + ". Check that the backend is running."); }
  if (res.status === 401 && path !== "/api/login") { setToken(null); window.dispatchEvent(new Event("athena-logout")); }
  if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.error || "Request failed (" + res.status + ")"); }
  return raw ? res : res.json();
}
const api = {
  login: (username, password) => req("/api/login", "POST", { username, password }),
  dashboard: () => req("/api/dashboard"), alerts: () => req("/api/alerts"), events: () => req("/api/network-events"),
  reports: () => req("/api/reports"), models: () => req("/api/model-status"), admin: () => req("/api/admin/status"),
  setStatus: (id, status) => req("/api/alerts/" + id, "PATCH", { status }), clearAlerts: () => req("/api/alerts", "DELETE"),
  analyze: (d) => req("/api/analyze", "POST", d), genAlert: () => req("/api/generate-alert", "POST"),
  toggleEngine: (enabled) => req("/api/admin/engine", "POST", { enabled }), refreshModels: () => req("/api/admin/refresh-models", "POST"),
  async download(id) {
    const r = await req("/api/reports/" + id + "/download", "GET", null, true);
    const a = document.createElement("a"); a.href = URL.createObjectURL(await r.blob()); a.download = id + "-report.txt"; a.click(); URL.revokeObjectURL(a.href);
  },
};
