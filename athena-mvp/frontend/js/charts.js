// Dependency-free SVG charts.
const W = 600, H = 190, P = 24;
function areaChart(vals, labels, color) {
  const max = Math.max(...vals, 1), x = (i) => P + (i * (W - 2 * P)) / (vals.length - 1 || 1), y = (v) => H - P - (v / max) * (H - 2 * P);
  const pts = vals.map((v, i) => x(i) + "," + y(v)).join(" ");
  return `<svg viewBox="0 0 ${W} ${H}" class="chart" role="img" aria-label="Line chart"><polygon points="${x(0)},${H - P} ${pts} ${x(vals.length - 1)},${H - P}" fill="${color}" fill-opacity=".12"/>
  <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2"/>${labels.map((l, i) => (i % 2 ? "" : `<text x="${x(i)}" y="${H - 6}" font-size="10" fill="#64748b" text-anchor="middle">${l}</text>`)).join("")}</svg>`;
}
function barChart(items) { // items: [{v, c, l}]
  const max = Math.max(...items.map((i) => i.v), 1), bw = (W - 2 * P) / items.length;
  return `<svg viewBox="0 0 ${W} ${H}" class="chart" role="img" aria-label="Bar chart">${items.map((it, i) => {
    const h = (it.v / max) * (H - 2 * P - 10);
    return `<rect x="${P + i * bw + 2}" y="${H - P - h}" width="${bw - 4}" height="${h}" rx="3" fill="${it.c}"/>` + (it.l ? `<text x="${P + i * bw + bw / 2}" y="${H - 6}" font-size="10" fill="#64748b" text-anchor="middle">${it.l}</text>` : "");
  }).join("")}</svg>`;
}
function donut(items) { // items: [{n, v, c}]
  const tot = items.reduce((s, i) => s + i.v, 0) || 1, C = 2 * Math.PI * 40; let off = 0;
  const arcs = items.map((i) => { const d = (i.v / tot) * C, s = `<circle r="40" cx="60" cy="60" fill="none" stroke="${i.c}" stroke-width="18" stroke-dasharray="${d} ${C - d}" stroke-dashoffset="${-off}" transform="rotate(-90 60 60)"/>`; off += d; return s; }).join("");
  return `<div class="row" style="justify-content:center"><svg viewBox="0 0 120 120" width="140" height="140" role="img" aria-label="Distribution chart">${arcs}</svg>
  <div class="small">${items.map((i) => `<p style="color:${i.c}">${i.n}: ${i.v}</p>`).join("")}</div></div>`;
}
