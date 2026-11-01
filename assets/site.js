'use strict';
(() => {
  const data = window.WALLSTRAT_DATA;
  if (!data || !Array.isArray(data.strategies)) return;
  const $ = (id) => document.getElementById(id);
  const svg = $('performance-chart');
  const tooltip = $('chart-tooltip');
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  let selected = data.strategies[0];
  let view = 'equity';
  let coordinates = [];
  const format = (v, digits = 2) => Number(v).toLocaleString('en-IN', { minimumFractionDigits: digits, maximumFractionDigits: digits });
  const dateLabel = (d) => new Date(`${d}T00:00:00Z`).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
  const notes = {
    vpt: 'Historical rolling ensemble simulation with quarterly selection. Research reused this history. Promoted rules do not make these live or independently audited results.',
    leader: 'Research candidate, not promoted. With doubled costs and an extra bar of entry delay, Sharpe falls to 1.1619 versus VPT’s 1.2594. The gate was developed on reused history; the headline is not independent validation.',
    strangle: 'Archived exploratory result. P&L is booked at expiry, not marked to market daily; the drawdown can understate intratrade risk. Intraday futures hedges use an index proxy. The corrected execution implementation does not yet have a validated multi-year result. Short options have no fixed loss cap.'
  };
  function element(name, attributes, content) {
    const node = document.createElementNS('http://www.w3.org/2000/svg', name);
    Object.entries(attributes || {}).forEach(([key, value]) => node.setAttribute(key, value));
    if (content !== undefined) node.textContent = content;
    return node;
  }
  function draw() {
    tooltip.hidden = true;
    const width = Math.max(320, svg.parentElement.clientWidth);
    const height = width < 650 ? 220 : 340;
    const left = 44, right = 12, top = 22, bottom = 35;
    const pts = selected.points;
    const col = view === 'equity' ? 1 : 2;
    const values = pts.map(p => p[col]);
    const isGrowth = view === 'equity';
    const min = isGrowth ? Math.floor(Math.min(...values, 100) / 25) * 25 : Math.floor(Math.min(...values) / 5) * 5;
    const max = isGrowth ? Math.ceil(Math.max(...values) / 50) * 50 : 0;
    const span = max - min || 1;
    const x = (i) => left + i / Math.max(pts.length - 1, 1) * (width - left - right);
    const y = (v) => top + (max - v) / span * (height - top - bottom);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    svg.replaceChildren();
    svg.append(element('title', {id: 'plot-svg-title'}, `${selected.name}: historical ${isGrowth ? 'growth of 100' : 'drawdown'}`));
    svg.append(element('desc', {id: 'plot-svg-description'}, `${dateLabel(selected.start)} to ${dateLabel(selected.end)}. Simulated return ${format(selected.totalReturn)}%; reported maximum drawdown ${format(selected.drawdown)}%. ${selected.accounting}.`));
    for (let i = 0; i <= 4; i++) {
      const value = min + i * span / 4;
      svg.append(element('line', {x1: left, x2: width-right, y1: y(value), y2: y(value), stroke: '#ced8cc', 'stroke-width': .7}));
      svg.append(element('text', {x: left-9, y: y(value)+4, 'text-anchor': 'end', fill: '#596665', 'font-size': 10}, `${Math.round(value)}${isGrowth ? '' : '%'}`));
    }
    const d = pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(2)},${y(p[col]).toFixed(2)}`).join(' ');
    const baseline = y(isGrowth ? min : 0);
    svg.append(element('path', {d: `${d} L${x(pts.length-1)},${baseline} L${left},${baseline} Z`, fill: '#236957', opacity: .065}));
    svg.append(element('path', {d, fill: 'none', stroke: '#236957', 'stroke-width': width < 650 ? 1.5 : 1.8, 'stroke-linejoin': 'round'}));
    const count = width < 650 ? 3 : 5;
    for (let i = 0; i < count; i++) {
      const idx = Math.round(i / (count-1) * (pts.length-1));
      const label = new Date(`${pts[idx][0]}T00:00:00Z`).toLocaleDateString('en-GB', {month: 'short', year: 'numeric', timeZone: 'UTC'});
      svg.append(element('text', {x: x(idx), y: height-9, 'text-anchor': i === 0 ? 'start' : i === count-1 ? 'end' : 'middle', fill: '#596665', 'font-size': 10}, label));
    }
    coordinates = pts.map((p, i) => ({x: x(i), y: y(p[col]), point: p}));
    svg.append(element('line', {id: 'hover-line', x1: 0, x2: 0, y1: top, y2: height-bottom, stroke: '#617e6a', 'stroke-dasharray': '3 4', visibility: 'hidden'}));
    svg.append(element('circle', {id: 'hover-dot', r: 3.2, fill: '#236957', stroke: '#edf0ea', 'stroke-width': 2, visibility: 'hidden'}));
  }
  function select(id) {
    selected = data.strategies.find(s => s.id === id) || data.strategies[0];
    tabs.forEach(tab => { const active = tab.dataset.strategy === selected.id; tab.setAttribute('aria-selected', String(active)); tab.tabIndex = active ? 0 : -1; });
    $('performance-panel').setAttribute('aria-labelledby', `tab-${selected.id}`);
    $('selected-name').textContent = selected.name;
    $('selected-period').textContent = `${dateLabel(selected.start)} – ${dateLabel(selected.end)}`;
    $('selected-status').textContent = selected.status;
    $('stat-cagr').textContent = `${format(selected.cagr)}%`;
    $('stat-return').textContent = `${format(selected.totalReturn)}%`;
    $('stat-sharpe').textContent = format(selected.sharpe, 4);
    $('stat-dd').textContent = `${format(selected.drawdown)}%${selected.id === 'strangle' ? '*' : ''}`;
    $('stat-trades').textContent = selected.trades;
    $('selected-caveat').textContent = notes[selected.id];
    $('selected-caveat').classList.toggle('warning', selected.id !== 'vpt');
    updateView();
  }
  function updateView() {
    $('plot-title').textContent = `${view === 'equity' ? 'Growth of 100' : 'Drawdown from peak'} · ${selected.id === 'strangle' ? 'expiry-booked, not daily MTM' : 'daily marked-to-market'}`;
    document.querySelectorAll('[data-view]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.view === view)));
    draw();
  }
  document.querySelectorAll('[data-strategy]').forEach(b => b.addEventListener('click', () => select(b.dataset.strategy)));
  tabs.forEach((tab, index) => tab.addEventListener('keydown', event => {
    let next;
    if (event.key === 'ArrowRight') next = (index+1)%tabs.length;
    if (event.key === 'ArrowLeft') next = (index+tabs.length-1)%tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length-1;
    if (next !== undefined) { event.preventDefault(); tabs[next].focus(); select(tabs[next].dataset.strategy); }
  }));
  document.querySelectorAll('[data-view]').forEach(b => b.addEventListener('click', () => { view = b.dataset.view; updateView(); }));
  svg.addEventListener('pointermove', event => {
    if (!coordinates.length) return;
    const rect = svg.getBoundingClientRect();
    const pos = (event.clientX-rect.left)*svg.viewBox.baseVal.width/rect.width;
    const first = coordinates[0], last = coordinates[coordinates.length-1];
    const idx = Math.max(0, Math.min(coordinates.length-1, Math.round((pos-first.x)/(last.x-first.x)*(coordinates.length-1))));
    const p = coordinates[idx];
    const line = $('hover-line'), dot = $('hover-dot');
    line.setAttribute('x1', p.x); line.setAttribute('x2', p.x); line.setAttribute('visibility', 'visible');
    dot.setAttribute('cx', p.x); dot.setAttribute('cy', p.y); dot.setAttribute('visibility', 'visible');
    tooltip.textContent = `${dateLabel(p.point[0])} · ${format(p.point[view === 'equity' ? 1 : 2])}${view === 'drawdown' ? '%' : ''}`;
    tooltip.hidden = false;
    tooltip.style.left = `${Math.max(0, Math.min(rect.width-tooltip.offsetWidth, event.clientX-rect.left+12))}px`;
    tooltip.style.top = `${Math.max(0, p.y*rect.height/svg.viewBox.baseVal.height-37)}px`;
  });
  svg.addEventListener('pointerleave', () => { tooltip.hidden = true; $('hover-line')?.setAttribute('visibility', 'hidden'); $('hover-dot')?.setAttribute('visibility', 'hidden'); });
  let timer;
  window.addEventListener('resize', () => {clearTimeout(timer);timer=setTimeout(draw,100);});
  select('vpt');
})();
