const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const NAV = ["Overview", "Live Alerts", "Detection Analysis", "Network Activity", "Reports", "Admin", "Settings"];
const COL = { Critical: "#f43f5e", High: "#f59e0b", Medium: "#60a5fa", Low: "#2dd4bf" };
const ORDER = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const S = { user: null, page: "Overview", search: "", sev: "All", st: "All", sort: "time", last: null, alerts: [], sel: null };
const tone = (s) => (s >= 85 ? "crit" : s >= 55 ? "warn" : "ok");
const when = (t) => new Date(t).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
const badge = (l, t) => `<span class="badge b-${l}">${t || l}</span>`;
const errBox = (m) => `<div class="errbox" role="alert"><span>${esc(m)}</span><button class="btn ghost" data-a="reload">Try again</button></div>`;
const card = (t, b, c = "") => `<section class="card ${c}">${t ? `<h3>${t}</h3>` : ""}${b}</section>`;
const stat = (l, v, c) => `<div class="card stat"><span class="muted small">${l}</span><b class="${c}">${v}</b></div>`;

function toast(m) { const t = $("#toast"); t.textContent = m; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 4500); }
function showApp(user) {
  S.user = user; $("#login").hidden = true; $("#app").hidden = false;
  $("#uname").textContent = user.name; $("#urole").textContent = user.role + " · Sign out"; go("Overview");
}
function logout() { setToken(null); localStorage.removeItem("athena_user"); S.user = null; $("#app").hidden = true; $("#login").hidden = false; }
function setEngine(on) { const e = $("#engine"); e.textContent = "● Engine " + (on ? "online" : "disabled"); e.className = "pill " + (on ? "ok" : "warn"); }

// ---- Pages: each returns an HTML string ----
const pages = {
  async Overview() {
    const d = await api.dashboard(); setEngine(d.engine_enabled);
    return `<div class="grid g5">${stat("Overall threat score", d.threat_score + "/100", tone(d.threat_score))}${stat("Anomalies detected", d.anomalies, "warn")}${stat("Critical alerts", d.critical_alerts, "crit")}
      ${stat("Events processed", d.events_processed.toLocaleString(), "info")}${stat("Model confidence", d.model_confidence + "%", "ok")}</div>
    <div class="grid g3">${card("Threat activity (24h)", areaChart(d.activity.map((a) => a.threat), d.activity.map((a) => a.time), "#f43f5e"), "span2")}
      ${card("Severity distribution", donut(d.severity_distribution.map((s) => ({ n: s.name, v: s.value, c: COL[s.name] }))))}</div>
    <div class="grid g3">${card("Anomaly activity", barChart(d.activity.map((a) => ({ v: a.anomalies, c: "#60a5fa", l: a.time }))), "span2")}
      ${card("Detection engine status", `<p class="${d.engine_enabled ? "ok" : "warn"}" style="font-size:18px">${d.engine_enabled ? "Online" : "Disabled"}</p><p class="muted small" style="margin-top:6px">Isolation Forest, STMP and Zero-Day Lab run as simulated modules.</p>`)}</div>
    ${card("Recent alerts", d.recent_alerts.length ? d.recent_alerts.map((a) => `<div class="recent"><div><p>${esc(a.name)}</p><p class="muted small">${esc(a.source_ip)} · ${when(a.timestamp)}</p></div>${badge(a.severity)}</div>`).join("") : `<div class="empty">No alerts yet. Click Run Analysis to generate one.</div>`)}`;
  },
  async "Live Alerts"() { S.alerts = (await api.alerts()).alerts; return alertsView(); },
  async "Detection Analysis"() {
    const m = (await api.models()).models, r = S.last, d = r && r.details;
    const T = (t, v, s, c) => card(t, `<b class="${c}" style="font-size:26px">${v}</b><p class="muted small" style="margin-top:6px">${s}</p>`);
    const st = ["Raw Network Data", "Feature Extraction", "Anomaly Detection", "Zero-Day Analysis", "Threat Score", "Alert Generation"];
    return card("Detection pipeline", `<div class="pipe ${r ? "on" : ""}">${st.map((s, i) => `<span>${s}</span>${i < 5 ? "→" : ""}`).join("")}</div>`) +
      `<div class="grid g4">${T("ML Engine: Isolation Forest", m[0].confidence + "%", d ? `Last score ${d.isolation_forest} · STMP ${d.stmp}` : "Model confidence", "ok")}
      ${T("Anomaly Score", r ? r.anomaly_score : "0.82", "0 normal to 1 anomalous", "warn")}${T("Zero-Day Lab", (d ? d.zero_day_patterns : 7) + " patterns", "Suspicious patterns found", "info")}
      ${T("Threat Score", (r ? r.threat_score : 78) + "/100", r ? r.prediction : "Example values until you run an analysis", tone(r ? r.threat_score : 78))}</div>` +
      card("Run a simulated analysis", `<div class="form"><label>Source IP<input id="f_src" value="192.168.1.20"></label><label>Destination IP<input id="f_dst" value="10.0.0.5"></label>
        <label>Packets<input id="f_pk" value="450"></label><label>Protocol<select id="f_pr">${["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SSH"].map((p) => `<option>${p}</option>`).join("")}</select></label>
        <button class="btn" data-a="runForm">Run Analysis</button></div><div id="res" style="margin-top:12px;font-size:14px">${r ? resultLine(r) : ""}</div>`);
  },
  async "Network Activity"() {
    const ev = (await api.events()).events, pr = {}, src = {};
    ev.forEach((e) => { pr[e.protocol] = (pr[e.protocol] || 0) + 1; src[e.source_ip] = (src[e.source_ip] || 0) + e.packet_count; });
    const pal = ["#2dd4bf", "#60a5fa", "#f59e0b", "#f43f5e", "#a78bfa", "#94a3b8"], top = Object.entries(src).sort((a, b) => b[1] - a[1]).slice(0, 5), mx = top[0][1];
    return `<div class="grid g2">${card("Network traffic (KB per flow)", barChart(ev.slice(0, 24).map((e) => ({ v: e.volume_kb, c: e.anomaly_score > 0.7 ? "#f43f5e" : "#60a5fa" }))) + `<p class="muted small">Red bars: suspicious flows (anomaly score above 0.7).</p>`)}
      ${card("Protocol distribution", donut(Object.entries(pr).map(([n, v], i) => ({ n, v, c: pal[i % 6] }))))}</div>
    ${card("Top source IPs by packets", top.map(([ip, v]) => `<div class="bar"><span>${esc(ip)}</span><i style="width:${(v / mx) * 100}%"></i><span>${v}</span></div>`).join(""))}
    ${card("Flows", `<div class="tw"><table><thead><tr>${["Source", "Destination", "Protocol", "Port", "Packets", "Volume (KB)", "Anomaly", "Risk"].map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>
      ${ev.map((e) => `<tr><td>${esc(e.source_ip)}</td><td class="muted">${esc(e.destination_ip)}</td><td>${e.protocol}</td><td>${e.port}</td><td>${e.packet_count}</td><td>${e.volume_kb}</td><td>${e.anomaly_score}</td><td>${badge(e.risk)}</td></tr>`).join("")}</tbody></table></div>`)}`;
  },
  async Reports() {
    const r = (await api.reports()).reports;
    return `<div class="grid g2">${r.map((x) => card(esc(x.title), `<p class="muted" style="font-size:14px;margin-bottom:12px">${esc(x.description)}</p><button class="btn ghost" data-a="dl" data-id="${x.id}">Download report</button>`)).join("")}</div>`;
  },
  async Admin() {
    const d = await api.admin(); setEngine(d.engine_enabled);
    const it = [["API status", d.api], ["Model status", d.models], ["Database", d.database], ["System health", d.health + "%"], ["Active users", d.active_users], ["Detection engine", d.engine_enabled ? "Enabled" : "Disabled"]];
    return `<div class="grid g3">${it.map(([k, v]) => stat(k, v, "ok").replace("30px", "18px")).join("")}</div>` +
      card("Demo controls", `<div class="row"><button class="btn" data-a="engine" data-on="${!d.engine_enabled}">${d.engine_enabled ? "Disable" : "Enable"} detection engine</button>
        <button class="btn ghost" data-a="refreshModels">Refresh model status</button><button class="btn ghost" data-a="gen">Generate test alert</button><button class="btn danger" data-a="clear">Clear demo alerts</button></div>
        <p class="muted small" style="margin-top:12px">${d.alerts} alerts stored. Data is simulated and held in memory.</p>`);
  },
  async Settings() {
    return card("Settings", `<dl style="max-width:420px"><dt>User</dt><dd>${esc(S.user.username)}</dd><dt>Role</dt><dd>${esc(S.user.role)}</dd><dt>API URL</dt><dd>${esc(window.ATHENA_API_URL)}</dd></dl>
      <p class="muted small" style="margin-top:16px">ATHENA is an MVP running on simulated data. It is not a production detection engine.</p>`);
  },
};

function resultLine(r) { return `Result: ${badge(r.severity)} ${esc(r.prediction)} · confidence ${Math.round(r.confidence * 100)}% ${r.alert ? "· alert #" + r.alert.id + " created" : "· no alert (score below 40)"}`; }

function alertsView() {
  const q = S.search.toLowerCase();
  const rows = S.alerts.filter((a) => (S.sev === "All" || a.severity === S.sev) && (S.st === "All" || a.status === S.st) && (a.name + " " + a.source_ip + " " + a.threat_type).toLowerCase().includes(q))
    .sort((a, b) => (S.sort === "score" ? b.threat_score - a.threat_score : S.sort === "severity" ? ORDER[b.severity] - ORDER[a.severity] : b.timestamp.localeCompare(a.timestamp)));
  const sel = (id, opts, cur) => `<select id="${id}" aria-label="${id}">${opts.map(([v, l]) => `<option value="${v}" ${v === cur ? "selected" : ""}>${l || v}</option>`).join("")}</select>`;
  return card("Live alerts", `<div class="row" style="margin-bottom:12px">${sel("sev", ["All", "Critical", "High", "Medium", "Low"].map((x) => [x]), S.sev)}${sel("st", ["All", "New", "Investigating", "Resolved"].map((x) => [x]), S.st)}
    ${sel("sort", [["time", "Newest first"], ["score", "Highest score"], ["severity", "Highest severity"]], S.sort)}<span class="muted small">${rows.length} shown</span></div>` +
    (rows.length ? `<div class="tw"><table><thead><tr>${["Alert", "Source IP", "Time", "Threat type", "Severity", "Score", "Status", "Action"].map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>
    ${rows.map((a) => `<tr><td>${esc(a.name)}</td><td class="muted">${esc(a.source_ip)}</td><td class="muted">${when(a.timestamp)}</td><td>${esc(a.threat_type)}</td><td>${badge(a.severity)}</td><td class="${tone(a.threat_score)}">${a.threat_score}</td><td>${a.status}</td>
    <td><button class="btn ghost" data-a="view" data-id="${a.id}">View</button></td></tr>`).join("")}</tbody></table></div>` : `<div class="empty">No alerts match. Adjust the filters or run an analysis.</div>`));
}
function modal(a) {
  const old = $("#modal"); if (old) old.remove(); if (!a) return;
  const m = document.createElement("div"); m.id = "modal"; m.className = "modal"; m.dataset.a = "closeModal";
  m.innerHTML = `<div class="card" data-a="stop"><h3>Alert #${a.id}</h3><p style="font-size:16px;margin-bottom:8px">${esc(a.name)}</p>${badge(a.severity)}
    <dl style="margin:12px 0"><dt>Source IP</dt><dd>${esc(a.source_ip)}</dd><dt>Type</dt><dd>${esc(a.threat_type)}</dd><dt>Threat score</dt><dd>${a.threat_score}/100</dd><dt>Detected</dt><dd>${when(a.timestamp)}</dd><dt>Status</dt><dd>${a.status}</dd></dl>
    <div class="row">${["Investigating", "Resolved"].map((s) => `<button class="btn ghost" data-a="status" data-id="${a.id}" data-s="${s}" ${a.status === s ? "disabled" : ""}>Mark ${s.toLowerCase()}</button>`).join("")}<button class="btn ghost" data-a="closeModal">Close</button></div></div>`;
  document.body.appendChild(m);
}

async function go(page) {
  S.page = page; $("#side").classList.remove("open");
  $("#nav").innerHTML = NAV.map((n) => `<button class="${n === page ? "on" : ""}" data-a="nav" data-p="${n}">${n}</button>`).join("");
  $("#view").innerHTML = `<div class="empty" role="status">Loading…</div>`;
  try { $("#view").innerHTML = await pages[page](); } catch (e) { $("#view").innerHTML = errBox(e.message); }
}
async function run(payload) {
  const b = $("#runBtn"); b.disabled = true; b.textContent = "Analyzing…";
  const rnd = (n) => Math.floor(Math.random() * n);
  payload = payload || { source_ip: "192.168.1." + (20 + rnd(200)), destination_ip: "10.0.0.5", protocol: ["TCP", "UDP", "ICMP", "DNS"][rnd(4)], packet_count: 150 + rnd(700) };
  try {
    const r = await api.analyze(payload); S.last = r;
    toast(`Analysis complete: ${r.severity} (${r.threat_score}/100). ${r.alert ? "Alert #" + r.alert.id + " created." : "No alert raised."}`);
    await go(S.page); // refresh metrics and alerts for the current page
  } catch (e) { toast(e.message); } finally { b.disabled = false; b.textContent = "Run Analysis"; }
}
async function act(fn, msg) { try { await fn(); toast(msg); await go(S.page); } catch (e) { toast(e.message); } }

document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-a]"); if (!el) return;
  const a = el.dataset.a, d = el.dataset;
  if (a === "stop") return;
  if (a === "nav") go(d.p); else if (a === "reload") go(S.page); else if (a === "logout") logout();
  else if (a === "run") run(); else if (a === "closeModal") modal(null);
  else if (a === "runForm") run({ source_ip: $("#f_src").value.trim(), destination_ip: $("#f_dst").value.trim(), protocol: $("#f_pr").value, packet_count: Number($("#f_pk").value) });
  else if (a === "view") { S.sel = S.alerts.find((x) => x.id == d.id); modal(S.sel); }
  else if (a === "status") { try { const u = await api.setStatus(d.id, d.s); S.alerts = S.alerts.map((x) => (x.id === u.id ? u : x)); modal(u); $("#view").innerHTML = alertsView(); } catch (x) { toast(x.message); } }
  else if (a === "dl") api.download(d.id).catch((x) => toast(x.message));
  else if (a === "engine") act(() => api.toggleEngine(d.on === "true"), "Detection engine updated.");
  else if (a === "refreshModels") act(api.refreshModels, "Model status refreshed.");
  else if (a === "gen") act(api.genAlert, "Test alert generated.");
  else if (a === "clear" && confirm("Clear all demo alerts?")) act(api.clearAlerts, "Demo alerts cleared.");
});
document.addEventListener("change", (e) => { const k = e.target.id; if (["sev", "st", "sort"].includes(k)) { S[k] = e.target.value; $("#view").innerHTML = alertsView(); } });
$("#search").addEventListener("input", (e) => {
  S.search = e.target.value;
  if (S.page !== "Live Alerts") go("Live Alerts"); else $("#view").innerHTML = alertsView();
});
$("#menu").addEventListener("click", () => $("#side").classList.toggle("open"));
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault(); const u = $("#u").value.trim(), p = $("#p").value, err = $("#loginErr"); err.textContent = "";
  if (!u || !p) { err.textContent = "Enter your username and password."; return; }
  $("#loginBtn").disabled = true;
  try { const r = await api.login(u, p); setToken(r.token); localStorage.setItem("athena_user", JSON.stringify(r.user)); showApp(r.user); }
  catch (x) { err.textContent = x.message; } finally { $("#loginBtn").disabled = false; }
});
window.addEventListener("athena-logout", logout);
try { const u = JSON.parse(localStorage.getItem("athena_user")); if (token && u) showApp(u); } catch {}
