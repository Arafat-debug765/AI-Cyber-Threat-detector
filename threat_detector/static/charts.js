/* Dashboard charts: dependency-free inline SVG.
 *
 * Built with createElementNS/textContent rather than markup strings — the same
 * rule the results table follows, since every number here derives from captured
 * traffic. Colours come from CSS custom properties so light/dark swap in one
 * place (palette slots 1 and 2: blue = normal, orange = flagged).
 */
(function (global) {
  "use strict";

  const NS = "http://www.w3.org/2000/svg";
  const NORMAL = "var(--series-normal)";
  const FLAGGED = "var(--series-flagged)";
  const GAP = 2; // surface gap between adjacent fills

  function el(name, attrs) {
    const node = document.createElementNS(NS, name);
    for (const key in attrs || {}) node.setAttribute(key, attrs[key]);
    return node;
  }

  /** Rounded only on the data end, square where it meets the baseline. */
  function barPath(x, y, w, h, r, side) {
    if (h <= 0 || w <= 0) return null;
    const radius = Math.min(r, w / 2, h / 2);
    if (side === "top") {
      return `M${x},${y + h} L${x},${y + radius} Q${x},${y} ${x + radius},${y} ` +
             `L${x + w - radius},${y} Q${x + w},${y} ${x + w},${y + radius} L${x + w},${y + h} Z`;
    }
    return `M${x},${y} L${x + w - radius},${y} Q${x + w},${y} ${x + w},${y + radius} ` +
           `L${x + w},${y + h - radius} Q${x + w},${y + h} ${x + w - radius},${y + h} L${x},${y + h} Z`;
  }

  /** Ticks from 0 to a round number at or above `max` — never below it, or
   *  the tallest bar would be drawn outside the plot area. */
  function niceTicks(max, count) {
    if (max <= 0) return [0];
    const raw = max / count;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    // These axes count packets, so never step below 1 — a fractional step
    // produces duplicate labels like 0, 0, 1, 1 on small datasets.
    const step = Math.max(1, [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) || mag * 10);
    const top = Math.ceil(max / step) * step;
    const ticks = [];
    for (let v = 0; v <= top + step / 1000; v += step) ticks.push(Math.round(v));
    return ticks;
  }

  /** One tooltip per chart container, positioned from the pointer. */
  function attachTooltip(container) {
    const tip = document.createElement("div");
    tip.className = "chart-tip";
    tip.hidden = true;
    container.append(tip);

    return {
      show(event, lines) {
        tip.replaceChildren();
        for (const [label, value] of lines) {
          const row = document.createElement("div");
          row.className = "chart-tip__row";
          const k = document.createElement("span");
          k.textContent = label;
          const v = document.createElement("strong");
          v.textContent = value;
          row.append(k, v);
          tip.append(row);
        }
        const box = container.getBoundingClientRect();
        tip.hidden = false;
        const width = tip.offsetWidth;
        let left = event.clientX - box.left + 12;
        if (left + width > box.width) left = event.clientX - box.left - width - 12;
        tip.style.left = Math.max(0, left) + "px";
        tip.style.top = Math.max(0, event.clientY - box.top - tip.offsetHeight - 10) + "px";
      },
      hide() { tip.hidden = true; },
    };
  }

  function legend(container, items) {
    const list = document.createElement("ul");
    list.className = "chart-legend";
    for (const [label, color] of items) {
      const li = document.createElement("li");
      const swatch = document.createElement("span");
      swatch.className = "chart-legend__swatch";
      swatch.style.background = color;
      const text = document.createElement("span");
      text.textContent = label;
      li.append(swatch, text);
      list.append(li);
    }
    container.append(list);
  }

  /* ---------- anomaly score distribution ---------- */

  function scoreHistogram(container, bins) {
    container.replaceChildren();
    if (!bins || !bins.length) return;

    const W = 720, H = 250;
    const M = { top: 14, right: 12, bottom: 36, left: 46 };
    const plotW = W - M.left - M.right;
    const plotH = H - M.top - M.bottom;

    const maxCount = Math.max(...bins.map((b) => b.normal + b.flagged), 1);
    const ticks = niceTicks(maxCount, 4);
    const yMax = ticks[ticks.length - 1];
    const band = plotW / bins.length;
    const barW = Math.max(1, band - GAP);
    const y = (v) => M.top + plotH - (v / yMax) * plotH;

    const svg = el("svg", {
      viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img",
      "aria-label": "Distribution of anomaly scores, normal versus flagged packets",
    });

    for (const tick of ticks) {
      svg.append(el("line", {
        x1: M.left, x2: W - M.right, y1: y(tick), y2: y(tick), class: "chart-grid",
      }));
      const label = el("text", { x: M.left - 8, y: y(tick) + 4, class: "chart-axis-label", "text-anchor": "end" });
      label.textContent = String(tick);
      svg.append(label);
    }

    bins.forEach((bin, i) => {
      const x = M.left + i * band + GAP / 2;
      const baseline = y(0);
      const normalH = (bin.normal / yMax) * plotH;
      const flaggedH = (bin.flagged / yMax) * plotH;

      // Normal sits on the baseline; flagged stacks above it with a 2px gap.
      if (normalH > 0) {
        const top = baseline - normalH;
        const d = barPath(x, top, barW, normalH, 4, "top");
        if (d) svg.append(el("path", { d: d, fill: NORMAL }));
      }
      if (flaggedH > 0) {
        const top = baseline - normalH - flaggedH - (normalH > 0 ? GAP : 0);
        const d = barPath(x, top, barW, flaggedH, 4, "top");
        if (d) svg.append(el("path", { d: d, fill: FLAGGED }));
      }

      const hit = el("rect", {
        x: M.left + i * band, y: M.top, width: band, height: plotH, fill: "transparent",
      });
      hit.addEventListener("pointermove", (event) => tip.show(event, [
        ["score", `${bin.start.toFixed(3)} to ${bin.end.toFixed(3)}`],
        ["normal", String(bin.normal)],
        ["flagged", String(bin.flagged)],
      ]));
      hit.addEventListener("pointerleave", () => tip.hide());
      svg.append(hit);
    });

    svg.append(el("line", {
      x1: M.left, x2: W - M.right, y1: y(0), y2: y(0), class: "chart-axis",
    }));

    // Only the extremes and the sign boundary are labelled — a label per bin is noise.
    const first = bins[0], last = bins[bins.length - 1];
    const xForScore = (s) => {
      const span = last.end - first.start || 1;
      return M.left + ((s - first.start) / span) * plotW;
    };
    for (const [score, text, anchor] of [
      [first.start, first.start.toFixed(2), "start"],
      [0, "0", "middle"],
      [last.end, last.end.toFixed(2), "end"],
    ]) {
      if (score < first.start || score > last.end) continue;
      const label = el("text", {
        x: xForScore(score), y: H - 14, class: "chart-axis-label", "text-anchor": anchor,
      });
      label.textContent = text;
      svg.append(label);
    }
    const caption = el("text", { x: M.left, y: H - 1, class: "chart-caption" });
    caption.textContent = "decision_function score — lower is more anomalous";
    svg.append(caption);

    container.append(svg);
    const tip = attachTooltip(container);
    legend(container, [["Normal", NORMAL], ["Flagged", FLAGGED]]);
  }

  /* ---------- per-protocol breakdown ---------- */

  function protocolBreakdown(container, rows) {
    container.replaceChildren();
    if (!rows || !rows.length) return;

    // Past eight rows, fold the tail into "Other" rather than adding hues.
    let data = rows.slice(0, 8);
    if (rows.length > 8) {
      const tail = rows.slice(8);
      data = data.concat([{
        name: "Other",
        normal: tail.reduce((a, r) => a + r.normal, 0),
        flagged: tail.reduce((a, r) => a + r.flagged, 0),
        total: tail.reduce((a, r) => a + r.total, 0),
      }]);
    }

    const rowH = 26, W = 720;
    const M = { top: 8, right: 56, bottom: 8, left: 66 };
    const H = M.top + M.bottom + data.length * rowH;
    const plotW = W - M.left - M.right;
    const maxTotal = Math.max(...data.map((r) => r.total), 1);
    const x = (v) => (v / maxTotal) * plotW;

    const svg = el("svg", {
      viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img",
      "aria-label": "Packets per protocol, normal versus flagged",
    });

    data.forEach((row, i) => {
      const top = M.top + i * rowH;
      const barY = top + 5;
      const barH = rowH - 12;

      const name = el("text", { x: M.left - 10, y: barY + barH - 2, class: "chart-row-label", "text-anchor": "end" });
      name.textContent = row.name;
      svg.append(name);

      const normalW = x(row.normal);
      const flaggedW = x(row.flagged);
      const gap = normalW > 0 && flaggedW > 0 ? GAP : 0;

      if (normalW > 0) {
        const d = barPath(M.left, barY, normalW, barH, 4, "right");
        if (d) svg.append(el("path", { d: d, fill: NORMAL }));
      }
      if (flaggedW > 0) {
        const d = barPath(M.left + normalW + gap, barY, flaggedW, barH, 4, "right");
        if (d) svg.append(el("path", { d: d, fill: FLAGGED }));
      }

      const total = el("text", {
        x: M.left + normalW + gap + flaggedW + 8, y: barY + barH - 2, class: "chart-value-label",
      });
      total.textContent = String(row.total);
      svg.append(total);

      const hit = el("rect", { x: M.left, y: top, width: plotW + M.right, height: rowH, fill: "transparent" });
      const share = row.total ? ((row.flagged / row.total) * 100).toFixed(1) + "%" : "0%";
      hit.addEventListener("pointermove", (event) => tip.show(event, [
        ["protocol", row.name],
        ["normal", String(row.normal)],
        ["flagged", String(row.flagged)],
        ["flagged share", share],
      ]));
      hit.addEventListener("pointerleave", () => tip.hide());
      svg.append(hit);
    });

    container.append(svg);
    const tip = attachTooltip(container);
    legend(container, [["Normal", NORMAL], ["Flagged", FLAGGED]]);
  }

  global.Charts = { scoreHistogram: scoreHistogram, protocolBreakdown: protocolBreakdown };
})(window);
