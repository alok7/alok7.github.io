'use strict';
(() => {
  const data = window.WALLSTRAT_DASHBOARD;
  if (!data) return;
  const charts = [];
  const ns = 'http://www.w3.org/2000/svg';
  const fmt = (v, digits = 2) => Number(v).toLocaleString('en-IN', {
    minimumFractionDigits: digits, maximumFractionDigits: digits
  });
  const money = v => `${v < 0 ? '−' : ''}₹${fmt(Math.abs(v), 0)}`;
  const day = value => new Date(value.length === 10 ? `${value}T12:00:00+05:30` : value);
  const dateLabel = value => day(value).toLocaleDateString('en-GB', {
    day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Asia/Kolkata'
  });
  function node(tag, attrs = {}, text) {
    const el = document.createElementNS(ns, tag);
    Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
    if (text !== undefined) el.textContent = text;
    return el;
  }
  function chart(panel, record, name) {
    const container = panel.querySelector('.chart');
    if (!container) return null;
    const svg = container.querySelector('svg');
    const tooltip = container.querySelector('.tooltip');
    let view = 'returnPct';
    let coordinates = [];
    let cursor = record.points.length - 1;
    let hoverLine, hoverDot;
    function value(v) { return view === 'pnl' ? money(v) : `${fmt(v)}%`; }
    function hide() {
      tooltip.hidden = true;
      hoverLine?.setAttribute('visibility', 'hidden');
      hoverDot?.setAttribute('visibility', 'hidden');
    }
    function inspect(index) {
      if (!coordinates.length) return;
      cursor = Math.max(0, Math.min(index, coordinates.length - 1));
      const p = coordinates[cursor];
      hoverLine.setAttribute('x1', p.x); hoverLine.setAttribute('x2', p.x);
      hoverLine.setAttribute('visibility', 'visible');
      hoverDot.setAttribute('cx', p.x); hoverDot.setAttribute('cy', p.y);
      hoverDot.setAttribute('visibility', 'visible');
      tooltip.textContent = `${dateLabel(p.point.date)} · ${value(p.point[view])}`;
      tooltip.hidden = false;
      tooltip.style.left = `${Math.max(0, Math.min(container.clientWidth - tooltip.offsetWidth, p.x + 12))}px`;
      tooltip.style.top = `${Math.max(0, p.y - 37)}px`;
    }
    function draw() {
      if (panel.hidden || !container.clientWidth) return;
      hide();
      const width = container.clientWidth;
      const height = width < 650 ? 230 : 290;
      const left = width < 650 ? 46 : 66, right = 10, top = 20, bottom = 32;
      const points = record.points;
      const values = points.map(p => p[view]);
      let lo = Math.min(0, ...values), hi = Math.max(0, ...values);
      const padding = (hi - lo || 1) * .08;
      lo -= padding; hi += padding;
      const x = i => left + i / Math.max(1, points.length - 1) * (width - left - right);
      const y = v => top + (hi - v) / (hi - lo) * (height - top - bottom);
      const color = view === 'drawdown' || values.at(-1) < 0 ? '#a4483d' : '#246451';
      svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
      svg.setAttribute('aria-label', `${name}: ${view === 'pnl' ? 'cumulative P&L' : view === 'returnPct' ? 'total return' : 'drawdown'}`);
      svg.replaceChildren(node('title', {}, svg.getAttribute('aria-label')),
        node('desc', {}, `${dateLabel(record.start)} to ${dateLabel(record.end)}. ${record.label}. ${record.valuation}.`));
      for (let i = 0; i < 5; i++) {
        const v = lo + i / 4 * (hi - lo);
        const label = view === 'pnl'
          ? `${v < 0 ? '−' : ''}₹${Math.abs(v) >= 100000 ? `${fmt(Math.abs(v)/100000, 1)}L` : Math.abs(v) >= 1000 ? `${fmt(Math.abs(v)/1000, 0)}k` : fmt(Math.abs(v), 0)}`
          : `${fmt(v, Math.abs(hi-lo) < 10 ? 1 : 0)}%`;
        svg.append(node('line', {x1: left, x2: width-right, y1: y(v), y2: y(v), class: 'grid'}),
          node('text', {x: left-9, y: y(v)+4, 'text-anchor': 'end'}, label));
      }
      svg.append(node('line', {x1: left, x2: width-right, y1: y(0), y2: y(0), stroke: '#b8c2b9', 'stroke-width': .65, 'stroke-dasharray': '3 5'}));
      const path = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(2)},${y(p[view]).toFixed(2)}`).join(' ');
      svg.append(node('path', {d: `${path} L${x(points.length-1)},${y(0)} L${left},${y(0)} Z`, fill: color, opacity: .035}),
        node('path', {d: path, fill: 'none', stroke: color, 'stroke-width': 1.8, 'stroke-linejoin': 'round'}));
      const ticks = width < 650 ? 3 : 5;
      for (let i = 0; i < ticks; i++) {
        const index = Math.round(i/(ticks-1)*(points.length-1));
        const label = day(points[index].date).toLocaleDateString('en-GB', {
          ...(points.length < 80 ? {day: 'numeric'} : {year: 'numeric'}), month: 'short', timeZone: 'Asia/Kolkata'
        });
        svg.append(node('text', {x: x(index), y: height-7, 'text-anchor': i === 0 ? 'start' : i === ticks-1 ? 'end' : 'middle'}, label));
      }
      hoverLine = node('line', {y1: top, y2: height-bottom, stroke: color, 'stroke-dasharray': '3 4', visibility: 'hidden'});
      hoverDot = node('circle', {r: 3, fill: color, stroke: '#f8f9fa', 'stroke-width': 2, visibility: 'hidden'});
      svg.append(hoverLine, hoverDot);
      coordinates = points.map((p, i) => ({x: x(i), y: y(p[view]), point: p}));
    }
    panel.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => {
      view = button.dataset.view;
      panel.querySelectorAll('[data-view]').forEach(b => b.setAttribute('aria-pressed', String(b === button)));
      panel.querySelector('.chart-title').textContent = view === 'pnl' ? 'Cumulative P&L' : view === 'returnPct' ? 'Cumulative return' : 'Drawdown from peak';
      draw();
    }));
    svg.addEventListener('pointermove', event => {
      if (!coordinates.length) return;
      const position = event.clientX - svg.getBoundingClientRect().left;
      const first = coordinates[0].x, last = coordinates.at(-1).x;
      inspect(Math.round((position-first)/(last-first)*(coordinates.length-1)));
    });
    svg.addEventListener('pointerleave', hide);
    container.addEventListener('keydown', event => {
      if (!['ArrowLeft','ArrowRight','Home','End','Escape'].includes(event.key)) return;
      event.preventDefault();
      if (event.key === 'Escape') { hide(); return; }
      inspect(event.key === 'Home' ? 0 : event.key === 'End' ? record.points.length-1 : cursor + (event.key === 'ArrowLeft' ? -1 : 1));
    });
    container.addEventListener('blur', hide);
    return {draw};
  }
  for (const strategy of data.strategies) {
    const section = document.querySelector(`[data-strategy="${strategy.id}"]`);
    const tabs = [...section.querySelectorAll('[role="tab"]')];
    const ownCharts = {};
    for (const mode of ['live','backtest']) {
      const panel = document.getElementById(`panel-${strategy.id}-${mode}`);
      ownCharts[mode] = chart(panel, strategy[mode], strategy.name);
      if (ownCharts[mode]) charts.push(ownCharts[mode]);
    }
    function select(mode) {
      tabs.forEach(tab => {
        const active = tab.dataset.mode === mode;
        tab.setAttribute('aria-selected', String(active)); tab.tabIndex = active ? 0 : -1;
        document.getElementById(`panel-${strategy.id}-${tab.dataset.mode}`).hidden = !active;
      });
      ownCharts[mode]?.draw();
    }
    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => select(tab.dataset.mode));
      tab.addEventListener('keydown', event => {
        const indexByKey = {ArrowLeft: (index+1)%2, ArrowRight: (index+1)%2, Home: 0, End: 1};
        if (!(event.key in indexByKey)) return;
        event.preventDefault();
        const next = tabs[indexByKey[event.key]];
        next.focus(); select(next.dataset.mode);
      });
    });
    section.querySelectorAll('.expand-positions').forEach(button => {
      const table = document.getElementById(button.getAttribute('aria-controls'));
      const count = table.querySelectorAll('tbody tr').length;
      button.addEventListener('click', () => {
        const expanded = table.classList.toggle('expanded');
        button.setAttribute('aria-expanded', String(expanded));
        button.textContent = expanded ? 'Show fewer positions ↑' : `View all ${count} positions ↓`;
      });
    });
    select(strategy.live.available ? 'live' : 'backtest');
  }
  let timer;
  window.addEventListener('resize', () => {
    clearTimeout(timer);
    timer = setTimeout(() => charts.forEach(c => c.draw()), 80);
  });
})();
