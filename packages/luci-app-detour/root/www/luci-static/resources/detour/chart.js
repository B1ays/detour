'use strict';
'require baseclass';
'require dom';

// The line charts of the Detour pages (Overview: the speed, Traffic: by day): smooth curves with a fading fill,
// a dashed grid, the scale on the left, labels under the picture, a cursor with a tooltip under the pointer.
// Two colours, both from the LuCI theme: "acc" (--primary-color-high) and "mute" (--text-color-medium); the
// neutral parts are currentColor with opacity, so a light theme and a dark one both read (detour.css).
// Only numbers go into the SVG markup; every text from the router goes in as text nodes (the tooltip, labels).

const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

let uid = 0;

// a smooth line through the points that never swings above or below its neighbours (monotone cubic,
// Fritsch-Carlson): a plain Catmull-Rom curve would draw values that were never there around a spike
function smooth(p) {
	const n = p.length, f = function(v) { return v.toFixed(1); };
	if (n < 3) return 'M' + p.map(function(q) { return f(q[0]) + ',' + f(q[1]); }).join(' L');
	const dx = [], sl = [], m = [];
	for (let i = 0; i < n - 1; i++) { dx[i] = p[i + 1][0] - p[i][0]; sl[i] = dx[i] ? (p[i + 1][1] - p[i][1]) / dx[i] : 0; }
	m[0] = sl[0]; m[n - 1] = sl[n - 2];
	for (let i = 1; i < n - 1; i++) m[i] = (sl[i - 1] * sl[i] <= 0) ? 0 : (sl[i - 1] + sl[i]) / 2;
	for (let i = 0; i < n - 1; i++) {
		if (!sl[i]) { m[i] = m[i + 1] = 0; continue; }
		const a = m[i] / sl[i], b = m[i + 1] / sl[i], h = a * a + b * b;
		if (h > 9) { const t = 3 / Math.sqrt(h); m[i] = t * a * sl[i]; m[i + 1] = t * b * sl[i]; }
	}
	let d = 'M' + f(p[0][0]) + ',' + f(p[0][1]);
	for (let i = 0; i < n - 1; i++) {
		const c = dx[i] / 3;
		d += ' C' + f(p[i][0] + c) + ',' + f(p[i][1] + m[i] * c) + ' ' + f(p[i + 1][0] - c) + ',' + f(p[i + 1][1] - m[i + 1] * c) + ' ' + f(p[i + 1][0]) + ',' + f(p[i + 1][1]);
	}
	return d;
}

// the top of the scale: a round number just above the peak, so the line at a half reads as a round number
// too, and the curves fill most of the height (the next step is at most a third above the peak)
function niceTop(v) {
	if (!(v > 0)) return 1;
	const p = Math.pow(10, Math.floor(Math.log10(v))), m = v / p;
	return ([ 1, 1.2, 1.6, 2, 2.5, 3, 4, 5, 6, 8, 10 ].find(function(s) { return m <= s; })) * p;
}

return baseclass.extend({
	smooth: smooth,
	niceTop: niceTop,

	// a chart: { el } goes into the page; draw() paints it. onHover() is called when the point under the
	// pointer changes (chart.hover: its index or null) - the page redraws, its head can show that point.
	create: function(onHover) {
		const c = { id: 'detour-ch' + (++uid), hover: null, geom: null };
		c.graph = E('div', { 'class': 'detour-chart-graph' }, E('em', { 'class': 'detour-muted' }, _('Measuring…')));
		c.tip = E('div', { 'class': 'detour-chart-tip', 'hidden': '' });
		c.el = E('div', { 'class': 'detour-chart' }, [ c.graph, c.tip ]);
		const set = function(i) { if (i !== c.hover) { c.hover = i; if (onHover) onHover(); } };
		c.el.addEventListener('mousemove', function(ev) {
			const g = c.geom; if (!g) return;
			const r = c.graph.getBoundingClientRect(), x = (ev.clientX - r.left) * g.W / Math.max(1, r.width);
			const i = Math.round((x - g.x0) / g.step);
			set((i < 0 || i >= g.n) ? null : i);
		});
		c.el.addEventListener('mouseleave', function() { set(null); });
		return c;
	},

	// o: {
	//   n        number of points,      slots  places on the x axis (n by default; more: the points sit on the right)
	//   series   [ { cls: 'acc'|'mute', vals: [ number|null ] } ] - drawn in this order; null = a gap
	//   fmt      a value for the scale,  minTop the lowest top of the scale,  binary: values are bytes
	//   labels   [ text ] under the points (optional),  tip(i) -> [ nodes ] for the tooltip
	//   empty    text when there is nothing to draw
	// }
	draw: function(c, o) {
		const n = o.n, slots = Math.max(o.slots || n, 2);
		if (n < 2) { c.geom = null; c.tip.hidden = true; dom.content(c.graph, E('em', { 'class': 'detour-muted' }, o.empty || _('Measuring…'))); return; }
		let max = 0;
		o.series.forEach(function(s) { s.vals.forEach(function(v) { if (v > max) max = v; }); });
		const peak = Math.max(max, o.minTop || 0);
		// bytes: round in their own units (KiB, MiB, GiB), not in powers of ten - "16 MiB", not "28.61 MiB"
		const unit = o.binary ? Math.pow(1024, Math.max(0, Math.floor(Math.log(peak) / Math.log(1024)))) : 1;
		const top = niceTop(peak / unit) * unit;
		const lab = o.labels ? 18 : 0;
		const W = Math.max(240, Math.round(c.graph.clientWidth || 600)), H = 180 + lab, T = 8, ph = H - T - 4 - lab;
		const pad = o.slots ? 0 : 6;            // a chart of its own points: a little air at both ends for the dots
		const step = (W - 2 * pad) / (slots - 1), x0 = W - pad - (n - 1) * step;
		c.geom = { W: W, x0: x0, step: step, n: n };
		const X = function(i) { return x0 + i * step; }, Y = function(v) { return T + ph - ph * v / top; };
		const base = (T + ph).toFixed(1);
		const id = c.id;
		let s = '<svg class="detour-chart-svg" viewBox="0 0 ' + W + ' ' + H + '" height="' + H + '" aria-hidden="true"><defs>' +
			[ 'acc', 'mute' ].map(function(k) {
				return '<linearGradient id="' + id + '-' + k + '" class="detour-c-' + k + '" x1="0" y1="0" x2="0" y2="1">' +
					'<stop offset="0" stop-color="currentColor" stop-opacity="' + (k == 'acc' ? '.35' : '.22') + '"/><stop offset="1" stop-color="currentColor" stop-opacity="0"/></linearGradient>';
			}).join('') + '</defs>';
		[ 0, 0.25, 0.5, 0.75 ].forEach(function(f) { const y = (T + ph * f).toFixed(1); s += '<line class="detour-chart-grid" x1="0" x2="' + W + '" y1="' + y + '" y2="' + y + '"/>'; });
		s += '<line class="detour-chart-base" x1="0" x2="' + W + '" y1="' + base + '" y2="' + base + '"/>';
		o.series.forEach(function(sr) {
			const runs = []; let cur = null;
			sr.vals.forEach(function(v, i) { if (v == null) { cur = null; return; } if (!cur) runs.push(cur = []); cur.push([ X(i), Y(v) ]); });
			runs.forEach(function(r) {
				if (r.length < 2) { s += '<circle class="detour-chart-dot detour-c-' + sr.cls + '" cx="' + r[0][0].toFixed(1) + '" cy="' + r[0][1].toFixed(1) + '" r="2.5"/>'; return; }
				const d = smooth(r);
				s += '<path fill="url(#' + id + '-' + sr.cls + ')" d="' + d + ' L' + r[r.length - 1][0].toFixed(1) + ',' + base + ' L' + r[0][0].toFixed(1) + ',' + base + ' Z"/>' +
					'<path class="detour-chart-line detour-c-' + sr.cls + '" d="' + d + '"/>';
			});
		});
		const hi = c.hover != null ? c.hover : n - 1;
		if (c.hover != null) s += '<line class="detour-chart-cursor" x1="' + X(hi).toFixed(1) + '" x2="' + X(hi).toFixed(1) + '" y1="' + T + '" y2="' + base + '"/>';
		o.series.forEach(function(sr) {
			const v = sr.vals[hi];
			if (v != null) s += '<circle class="detour-chart-dot detour-c-' + sr.cls + '" cx="' + X(hi).toFixed(1) + '" cy="' + Y(v).toFixed(1) + '" r="3.5"/>';
		});
		c.graph.innerHTML = s + '</svg>';
		// the scale and the labels: HTML over the picture, as text nodes
		const scale = E('div', { 'class': 'detour-chart-scale' }, [ [ top, T ], [ top / 2, T + ph / 2 ] ].map(function(q) {
			return E('span', { 'style': 'top:' + Math.round(q[1] - 15) + 'px' }, o.fmt(q[0]));
		}));
		c.graph.appendChild(scale);
		if (o.labels) {
			const every = Math.max(1, Math.ceil(n * 44 / W));
			c.graph.appendChild(E('div', { 'class': 'detour-chart-xlabels' }, o.labels.map(function(t, i) {
				if ((n - 1 - i) % every) return '';
				return E('span', { 'style': 'left:' + (X(i) / W * 100).toFixed(2) + '%' }, t);
			}).filter(function(x) { return x; })));
		}
		if (c.hover != null && o.tip) {
			c.tip.hidden = false;
			dom.content(c.tip, o.tip(hi));
			const left = X(hi) / W * 100;
			c.tip.style.left = left + '%';
			c.tip.classList.toggle('detour-chart-tip-left', left > 60);
		}
		else c.tip.hidden = true;
	}
});
