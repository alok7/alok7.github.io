/* Private transport-only prototype. No research values or existing decoders are modified. */
(function (host) {
  'use strict';
  const FORMAT = 'wallstrat-gzip-transport-v1';
  const LIMITS = Object.freeze({ manifest: 1048576, stored: 16000000, decoded: 16000000, records: 4096, timeout: 120000 });
  const HASH = /^[a-f0-9]{64}$/;
  let strictNativePromise;
  function fail(message) { throw new Error(message); }
  function positive(n, cap) { return Number.isSafeInteger(n) && n > 0 && n <= cap; }
  function stopped(signal) { if (signal?.aborted) fail('Research loading was cancelled.'); }
  function pathOK(path) {
    return typeof path === 'string' && /^sme\/[A-Z0-9]{12}(?:\.json|\/(?:atoms|schemas|nodes)-[0-9]{3}\.json|\/dictionary-[0-9]{3}\.jsonpart)(?:\.wsgz)?$/.test(path) &&
      path.split('/').every(part => part !== '' && part !== '.' && part !== '..');
  }
  function exactKeys(object, keys) {
    return object && typeof object === 'object' && !Array.isArray(object) &&
      Object.keys(object).length === keys.length && keys.every(key => Object.hasOwn(object, key));
  }
  async function sha(bytes) {
    const digest = await host.crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
  }
  async function readBounded(stream, expected, cap, signal) {
    if (!positive(expected, cap) || !stream?.getReader) fail('This browser cannot safely read the research bytes.');
    stopped(signal);
    const reader = stream.getReader(), bytes = new Uint8Array(expected);
    let received = 0;
    const cancel = () => { void reader.cancel().catch(() => {}); };
    signal?.addEventListener('abort', cancel, { once: true });
    try {
      for (;;) {
        stopped(signal);
        const part = await reader.read();
        stopped(signal);
        if (part.done) break;
        if (!(part.value instanceof Uint8Array) || !Number.isSafeInteger(part.value.byteLength) || part.value.byteLength < 1 || part.value.byteLength > expected - received)
          fail('Research bytes exceed their authenticated bound.');
        bytes.set(part.value, received); received += part.value.byteLength;
      }
      if (received !== expected) fail('Research byte count does not match.');
      return bytes;
    } catch (error) { try { await reader.cancel(); } catch {} throw error; }
    finally { signal?.removeEventListener('abort', cancel); reader.releaseLock(); }
  }
  function streamOf(bytes) { return new host.ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }); }
  async function inflate(bytes, expected, signal) {
    const stream = streamOf(bytes).pipeThrough(new host.DecompressionStream('gzip'));
    return readBounded(stream, expected, LIMITS.decoded, signal);
  }
  function unhex(text) { return Uint8Array.from(text.match(/../g), pair => parseInt(pair, 16)); }
  function concat(a, b) { const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out; }
  async function strictNativeCheck() {
    if (!host.crypto?.subtle || !host.DecompressionStream || !host.ReadableStream || !host.AbortController || !host.TextDecoder || !host.Response)
      fail('This browser cannot safely verify compressed research. Use a current browser on the secure website.');
    if (!strictNativePromise) strictNativePromise = (async () => {
      const controller = new host.AbortController(), timer = setTimeout(() => controller.abort(), 5000);
      try {
        const good = unhex('1f8b0800000000000203cbcf060047dddc7902000000');
        const empty = unhex('1f8b080000000000020303000000000000000000');
        const out = await inflate(good, 2, controller.signal);
        if (out[0] !== 111 || out[1] !== 107) fail('Unsupported gzip implementation.');
        const badCRC = good.slice(); badCRC[badCRC.length - 8] ^= 1;
        for (const bad of [concat(good, new Uint8Array([0])), concat(good, empty), badCRC, good.slice(0, -1)]) {
          let rejected = false;
          try { await inflate(bad, 2, controller.signal); } catch { stopped(controller.signal); rejected = true; }
          if (!rejected) fail('This browser does not enforce required gzip integrity rules.');
        }
      } finally { clearTimeout(timer); }
    })();
    return strictNativePromise;
  }
  function job(external, timeout) {
    if (!positive(timeout, LIMITS.timeout)) fail('Invalid research timeout.');
    const controller = new host.AbortController(), abort = () => controller.abort();
    if (external?.aborted) abort();
    external?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, timeout);
    return { signal: controller.signal, abort, close() { clearTimeout(timer); external?.removeEventListener('abort', abort); } };
  }
  async function fetchExact(url, binding, cap, fetcher, signal) {
    stopped(signal);
    const response = await fetcher(url.href, { mode: 'same-origin', redirect: 'error', credentials: 'same-origin', signal });
    try {
      if (!response || response.status !== 200 || response.redirected || response.type === 'opaque') fail('Research resource could not load safely.');
      if (response.url && new URL(response.url).href !== url.href) fail('Research response address changed.');
      const encoding = response.headers?.get?.('content-encoding');
      // Fetch exposes HTTP-decoded bytes; Content-Length describes the wire representation.
      // Authenticate the bounded body below before any application-level gzip inflation.
      const identity = encoding == null || encoding.trim().toLowerCase() === 'identity';
      const length = response.headers?.get?.('content-length');
      if (identity && length !== null && length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || !Number.isSafeInteger(Number(length)) || Number(length) !== binding.bytes))
        fail('Research response declared a different byte count.');
      const bytes = await readBounded(response.body, binding.bytes, cap, signal);
      if (await sha(bytes) !== binding.sha256) fail('Research stored-byte integrity check failed.');
      stopped(signal); return bytes;
    } catch (error) { try { await response?.body?.cancel?.(); } catch {} throw error; }
  }
  async function fromPinnedManifest(bytes, pin, options) {
    await strictNativeCheck();
    if (!(bytes instanceof Uint8Array) || !pin || !positive(pin.bytes, LIMITS.manifest) || bytes.byteLength !== pin.bytes || !HASH.test(pin.sha256) ||
        !/^[a-f0-9]{40}$/.test(pin.base_commit) || !positive(pin.records, LIMITS.records) || await sha(bytes) !== pin.sha256)
      fail('Invalid authenticated research transport manifest.');
    const value = JSON.parse(new host.TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!exactKeys(value, ['format', 'base_commit', 'records']) || value.format !== FORMAT || value.base_commit !== pin.base_commit ||
        !Array.isArray(value.records) || value.records.length !== pin.records) fail('Research transport manifest scope does not match.');
    const base = new URL(options.baseURL);
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash || !base.pathname.endsWith('/'))
      fail('Research transport requires an unchanged secure same-origin base.');
    if (typeof options.expectedOrigin !== 'string' || base.origin !== options.expectedOrigin ||
        (host.location?.origin && base.origin !== host.location.origin)) fail('Research origin does not match.');
    const entries = new Map(), stored = new Set();
    for (const item of value.records) {
      if (!exactKeys(item, ['logical_path', 'storage_path', 'gzip_bytes', 'gzip_sha256', 'decoded_bytes', 'decoded_sha256']) ||
          !pathOK(item.logical_path) || item.storage_path !== item.logical_path + '.wsgz' || !pathOK(item.storage_path) ||
          !positive(item.gzip_bytes, LIMITS.stored) || !positive(item.decoded_bytes, LIMITS.decoded) ||
          !HASH.test(item.gzip_sha256) || !HASH.test(item.decoded_sha256) || entries.has(item.logical_path) || stored.has(item.storage_path))
        fail('Invalid research transport address, count or hash.');
      const url = new URL(item.storage_path, base);
      if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname + 'sme/')) fail('Research address escaped its fixed origin.');
      entries.set(item.logical_path, Object.freeze({ ...item })); stored.add(item.storage_path);
    }
    const fetcher = options.fetchImpl || host.fetch.bind(host), timeout = options.timeoutMs ?? 30000;
    if (!positive(timeout, LIMITS.timeout)) fail('Invalid research timeout.');
    return Object.freeze({
      recordCount: entries.size,
      async fetchResearch(logicalPath, request = {}) {
        const entry = entries.get(logicalPath);
        if (!entry || !pathOK(logicalPath)) fail('Research address is not in the authenticated manifest.');
        const task = job(request.signal, timeout);
        try {
          stopped(task.signal);
          const url = new URL(entry.storage_path, base); url.searchParams.set('v', entry.gzip_sha256.slice(0, 16));
          const compressed = await fetchExact(url, { bytes: entry.gzip_bytes, sha256: entry.gzip_sha256 }, LIMITS.stored, fetcher, task.signal);
          const decoded = await inflate(compressed, entry.decoded_bytes, task.signal);
          if (await sha(decoded) !== entry.decoded_sha256) fail('Research decoded-byte integrity check failed.');
          stopped(task.signal);
          new host.TextDecoder('utf-8', { fatal: true }).decode(decoded);
          return new host.Response(decoded, { status: 200, headers: { 'content-type': 'application/json; charset=utf-8', 'content-length': String(decoded.byteLength) } });
        } catch (error) { task.abort(); throw error; }
        finally { task.close(); }
      }
    });
  }
  async function loadPinnedManifest(path, pin, options) {
    await strictNativeCheck();
    if (path !== 'sme-gzip-manifest.json' || !pin || !positive(pin.bytes, LIMITS.manifest) || !HASH.test(pin.sha256)) fail('Invalid manifest address or bound.');
    const base = new URL(options.baseURL);
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash || !base.pathname.endsWith('/') ||
        typeof options.expectedOrigin !== 'string' || base.origin !== options.expectedOrigin ||
        (host.location?.origin && base.origin !== host.location.origin)) fail('Invalid research manifest origin.');
    const task = job(options.signal, options.timeoutMs ?? 30000);
    try {
      const url = new URL(path, base); url.searchParams.set('v', pin.sha256.slice(0, 16));
      const bytes = await fetchExact(url, pin, LIMITS.manifest, options.fetchImpl || host.fetch.bind(host), task.signal);
      return await fromPinnedManifest(bytes, pin, options);
    } catch (error) { task.abort(); throw error; }
    finally { task.close(); }
  }
  const api = Object.freeze({ fromPinnedManifest, loadPinnedManifest, limits: LIMITS });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else host.WallstratGzipTransport = api;
})(globalThis);

(async()=>{
 const gzipPin={"bytes":183005,"sha256":"24aabe17a3833a2c122d262f5be615e94b77eb6e62d2ddcc9f3c4f3ed588c32a","base_commit":"cb411e56cd5e1a6485781464c2d7948893f45f7d","records":504};
 const gzipAdapter=await WallstratGzipTransport.loadPinnedManifest("sme-gzip-manifest.json",gzipPin,{baseURL:new URL("./",location.href).href,expectedOrigin:location.origin});
 const fetchResearchGzip=(path,options)=>gzipAdapter.fetchResearch(path,options);
/* Exact syntax-dictionary view. Values are resolved only when selected; no row is dropped. */
(()=>{'use strict';
 const schemaKeyOrder=new WeakMap();
 window.WALLSTRAT_SCHEMA_KEYS=value=>schemaKeyOrder.get(value)||null;
 window.WALLSTRAT_DECODE_340=function(p){
  if(p.codec!=='JSON-syntax-dictionary-v4'||!Array.isArray(p.atoms)||!Array.isArray(p.schemas)||!Array.isArray(p.nodes))throw Error('Invalid embedded research dictionary');
  const atoms=new Map(),nodes=new Map();
  function remember(cache,key,value,limit){cache.set(key,value);if(cache.size>limit)cache.delete(cache.keys().next().value);return value;}
  function atom(i){if(!Number.isSafeInteger(i)||i<0||i>=p.atoms.length||typeof p.atoms[i]!=='string')throw Error('Invalid research atom');if(!atoms.has(i)){const value=JSON.parse(p.atoms[i]);if(value!==null&&typeof value==='object'||typeof value==='number'&&(!Number.isFinite(value)||Number.isInteger(value)&&!Number.isSafeInteger(value)))throw Error('Research atoms must be finite primitive values');remember(atoms,i,value,16384);}return atoms.get(i);}
  function read(ref,parent){
   if(!Number.isSafeInteger(ref))throw Error('Invalid research reference');if(ref>=0)return atom(ref);
   const i=-1-ref;if(i<0||i>=p.nodes.length||i>=parent)throw Error('Invalid or cyclic research node');if(nodes.has(i))return nodes.get(i);
   const n=p.nodes[i];if(!Array.isArray(n)||!n.length||!Number.isSafeInteger(n[0]))throw Error('Invalid research node');let out;
   if(n[0]===-1){out=new Array(n.length-1);for(let j=1;j<n.length;j++)Object.defineProperty(out,String(j-1),{enumerable:true,get:()=>read(n[j],i)});}
   else{const keys=p.schemas[n[0]];if(!Array.isArray(keys)||keys.length!==n.length-1)throw Error('Invalid research schema');out={};const order=[];for(let j=0;j<keys.length;j++){const key=atom(keys[j]);if(typeof key!=='string'||Object.prototype.hasOwnProperty.call(out,key))throw Error('Invalid duplicate research key');order.push(key);Object.defineProperty(out,key,{enumerable:true,get:()=>read(n[j+1],i)});}schemaKeyOrder.set(out,Object.freeze(order));}
   remember(nodes,i,out,2048);return out;
  }
  return read(p.root,p.nodes.length);
 };
})();

/* Exact syntax-dictionary view. Values are resolved only when selected; no row is dropped. */
(()=>{'use strict';
 window.WALLSTRAT_DECODE=function(p){
  if(p.codec!=='JSON-syntax-dictionary-v4'||!Array.isArray(p.atoms)||!Array.isArray(p.schemas)||!Array.isArray(p.nodes))throw Error('Invalid embedded research dictionary');
  const atoms=new Map(),nodes=new Map();
  function remember(cache,key,value,limit){cache.set(key,value);if(cache.size>limit)cache.delete(cache.keys().next().value);return value;}
  function atom(i){if(!Number.isInteger(i)||i<0||i>=p.atoms.length||typeof p.atoms[i]!=='string')throw Error('Invalid research atom');if(!atoms.has(i))remember(atoms,i,JSON.parse(p.atoms[i]),16384);return atoms.get(i);}
  function read(ref,parent){
   if(!Number.isInteger(ref))throw Error('Invalid research reference');if(ref>=0)return atom(ref);
   const i=-1-ref;if(i<0||i>=p.nodes.length||i>=parent)throw Error('Invalid or cyclic research node');if(nodes.has(i))return nodes.get(i);
   const n=p.nodes[i];if(!Array.isArray(n)||!n.length||!Number.isInteger(n[0]))throw Error('Invalid research node');let out;
   if(n[0]===-1){out=new Array(n.length-1);for(let j=1;j<n.length;j++)Object.defineProperty(out,String(j-1),{enumerable:true,get:()=>read(n[j],i)});}
   else{const keys=p.schemas[n[0]];if(!Array.isArray(keys)||keys.length!==n.length-1)throw Error('Invalid research schema');out={};for(let j=0;j<keys.length;j++){const key=atom(keys[j]);if(typeof key!=='string'||Object.prototype.hasOwnProperty.call(out,key))throw Error('Invalid duplicate research key');Object.defineProperty(out,key,{enumerable:true,get:()=>read(n[j+1],i)});}}
   remember(nodes,i,out,2048);return out;
  }
  return read(p.root,p.nodes.length);
 };
})();

'use strict';
(() => {
 const new359=window.WallstratResearch359;
 const isBatch359=c=>new359.is(c);
 const root=document.getElementById('app'), esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const safe=u=>{try {return ['https:','http:'].includes(new URL(u).protocol)?u:null;}catch{return null;}};
 const link=(u,t)=>safe(u)?`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t)}</a>`:esc(t);
 const text=s=>esc(s).replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g,(_,t,u)=>link(u.replaceAll('&amp;','&'),t)).replace(/\[([SE]\d+)\]/g,(m,id)=>{const source=sourceRecords(current)?.find(s=>s.id===id);return source?link(source.url,'['+id+']'):m;}).replace(/\n/g,'<br>');
 const label=k=>({BQS:'Business quality',GQS:'Growth quality',IAS:'Investment attractiveness',GOV:'Governance',MOAT:'Competitive advantage',REV:'Demonstrated revenue growth',DUR:'Growth durability',CAP:'Capital efficiency',CASH:'Cash conversion',BAL:'Balance-sheet resilience',EXEC:'Execution',EARN:'Profit-growth quality',Q:'Underlying quality',R:'Prospective return',D:'Downside resilience',P:'Price-implied expectations',L:'Liquidity',raw:'Raw score',final:'Final score',coverage:'Evidence coverage',cap:'Applied cap',lower:'Lower bound',upper:'Upper bound',source_ids:'Sources',evidence_ids:'Evidence',irr:'Annualized return',cagr:'Annual growth'}[k]||k.replaceAll('_',' ').replace(/\bcr\b/g,'₹ crore'));
 const table=(headers,rows)=>'<div class="sme-table-wrap" tabindex="0" role="region" aria-label="Scrollable research data table"><table class="sme-audit-table"><thead><tr>'+headers.map(h=>'<th scope="col">'+esc(h)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(row=>'<tr>'+row.map(x=>'<td>'+x+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>';
 function render(v,key=''){
  if(v==null)return '<span class="subtle">Not established</span>';
  if(typeof v==='number'){
   if(/irr|cagr/i.test(key)&&!/pct|percent|multiple/i.test(key)||key==='coverage')return new Intl.NumberFormat('en-IN',{style:'percent',maximumFractionDigits:2}).format(v);
   return new Intl.NumberFormat('en-IN',{maximumFractionDigits:4}).format(v);
  }
  if(typeof v!=='object')return typeof v==='string'&&safe(v)?link(v,v):text(v);
  if(key==='factor_audit'&&!Array.isArray(v))return table(['Factor','Score / 10','Confidence','Assessment','Evidence'],Object.entries(v).map(([k,x])=>[esc(k)+'<small>'+esc(label(k))+'</small>',x.score==null?'NS':render(x.score),text(x.confidence),text(x.reason),render(x.evidence_ids||[])]));
  if(key==='score_audit'&&!Array.isArray(v))return table(['Measure','Raw','Final','Coverage','Raw bounds (before caps)','Cap','Calculation weights'],Object.entries(v).map(([k,x])=>[esc(k),render(x.raw),render(x.final),render(x.coverage,'coverage'),render(x.lower)+'–'+render(x.upper),x.cap==null?'None':render(x.cap),Object.entries(x.weights||{}).map(([f,w])=>esc(f)+' '+render(w,'coverage')).join(' · ')]))+'<p class="sme-meta">Unrounded arithmetic is retained for classification; displayed index scores use half-up rounding to one decimal. Missing factors are not reweighted. Raw bounds are arithmetic bounds before caps; an applied cap limits the final score and its final bounds.</p>';
  if(key==='scenarios'&&!Array.isArray(v))return Object.entries(v).map(([k,x])=>'<details class="sme-scenario"'+(/base/i.test(k)?' open':'')+'><summary>'+esc(label(k))+' scenario</summary>'+render(x,k)+'</details>').join('');
  if(Array.isArray(v)){
   if(!v.length)return '<span class="subtle">None listed</span>';
   const primitive=x=>x==null||typeof x!=='object'||Array.isArray(x)&&x.every(y=>y==null||typeof y!=='object');
   if(v.every(x=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.values(x).every(primitive))){
    const keys=[...new Set(v.flatMap(x=>Object.keys(x)))];
    if(keys.length>1&&keys.length<=40)return table(keys.map(label),v.map(r=>keys.map(k=>render(r[k],k))));
   }
   if(v.every(x=>x==null||typeof x!=='object'))return v.map(x=>render(x,key)).join(', ');
   return '<ul>'+v.map(x=>'<li>'+render(x,key)+'</li>').join('')+'</ul>';
  }
  return '<dl class="sme-audit">'+Object.entries(v).map(([k,x])=>'<dt><strong>'+esc(label(k))+'</strong></dt><dd>'+render(x,k)+'</dd>').join('')+'</dl>';
 }

 const isRecovered=c=>['partial_packet_only','narrative_edition'].includes(c?.recovery_status);
 const extendedReviewIds=new Set(["INE0PXC01024","INE1OSW01015","INE433T01015","INE0SDC01012","INE0S1L01013","INE0SQZ01015","INE23ER01017","INE0D2I01014","INE1KEC01023","INE0R9I01021","INE0I7D01019","INE0SUH01015","INE11HF01010","INE0U2501017","INE0YUW01020","INE1D0M01019","INE0YKW01013","INE0SFW01015","INE1W3Q01011","INE1LMA01010","INE1ZGR01024","INE1H1501013","INE0U8P01015","INE0S7E01015","INE1GUJ01014","INE0BUQ01012","INE1ITY01011","INE0R8C01018","INE0ZOM01013","INE0PS501019","INE0QFE01017","INE12E301017","INE17DP01015","INE0JVH01012","INE0PLX01017","INE1UYW01010","INE0OLZ01015","INE0GYI01028","INE0PIC01017","INE1KI801019","INE1OTR01013","INE0TO501019","INE111601014","INE0O7401018","INE0XE501015","INE0PA401012","INE0WKY01013","INE16XA01017","INE0MRE01011","INE464Z01017","INE0MYZ01012","INE0NNZ01013","INE1YC401018","INE1JJF01019","INE0S1D01010","INE870Z01015","INE0W5Q01017","INE0XOW01017","INE1IE301018","INE0P3N01018","INE0N6U01018","INE0V8A01016","INE0L1C01019","INE0MGA01012","INE0KZ301010","INE0HOL01013","INE0Q7P01013","INE0QVH01025","INE1L0M01019","INE0NR701018","INE1MTV01019","INE163701019","INE1SFA01019","INE0TJ801010","INE0X9I01023","INE920P01019","INE0H4B01011","INE0RH001011","INE0SGC01015","INE0X6O01027","INE004Z01011","INE0OLH01013","INE1P5601010","INE0P6701019","INE0U9D01019","INE0SVD01012","INE632Q01018","INE0U4H01011","INE104Y01012","INE0RU901015","INE1ERK01013","INE0TD401015","INE0JSJ01014","INE0SH001010","INE132901013","INE0OJM01017","INE10A501018","INE0G1D01014","INE1KH601014","INE1K0V01011","INE0QZR01017","INE1RQS01010","INE1II801013","INE1SRC01010","INE1YNB01019","INE0V0L01028","INE0LCG01010","INE1DV401010","INE0N7S01028","INE0UH001016","INE0N6D01014","INE0D7801012","INE0RVQ01016","INE2B5L01011","INE1K8Y01018","INE08NZ01012","INE0YJA01011","INE156901014","INE21UM01018","INE0UZO01024","INE0DQN01013","INE1TFS01019","INE0VYX01018","INE346R01013","INE00ER01015","INE1IA801011","INE2D0Q01027","INE0YHV01011","INE0UR501013","INE1JZB01022","INE0MIO01019","INE15B101011","INE0KN801013","INE0RMF01018","INE0OUT01027","INE14LM01012","INE0SMW01011","INE0TBC01014","INE06ZX01015","INE1H7V01011","INE473T01011","INE161701011","INE484S01010","INE17GV01016","INE0VG601013","INE998U01015","INE0MLZ01019","INE0NT601018","INE517M01028","INE1C2Q01017","INE288301026","INE0O7A01017","INE2JG601017","INE0TI501017","INE0M1F01011","INE0GAO01018","INE0CQA01020","INE0MJQ01020","INE0VJT01017","INE0V9N01017","INE1FFX01018","INE10XK01019","INE510U01018","INE0P5R01014","INE0VDK01019","INE1G2W01011","INE1XJ401012","INE0Q1R01012","INE0OAB01019","INE0OYE01013"]);
 const newReviewIds=new Set(["INE0I7D01019","INE0SUH01015","INE11HF01010","INE0U2501017","INE0YUW01020","INE1D0M01019","INE0YKW01013","INE0SFW01015","INE1W3Q01011","INE1LMA01010","INE1ZGR01024","INE1H1501013","INE0U8P01015","INE0S7E01015","INE1GUJ01014","INE0BUQ01012","INE1ITY01011","INE0R8C01018","INE0ZOM01013","INE0PS501019","INE0QFE01017","INE12E301017","INE17DP01015","INE0JVH01012","INE0PLX01017","INE1UYW01010","INE0OLZ01015","INE0GYI01028","INE0PIC01017","INE1KI801019","INE1OTR01013","INE0TO501019","INE111601014","INE0O7401018","INE0XE501015","INE0PA401012","INE0WKY01013","INE16XA01017","INE0MRE01011","INE464Z01017","INE0MYZ01012","INE0NNZ01013","INE1YC401018","INE1JJF01019","INE0S1D01010","INE870Z01015","INE0W5Q01017","INE0XOW01017","INE1IE301018","INE0P3N01018","INE0N6U01018","INE0V8A01016","INE0L1C01019","INE0MGA01012","INE0KZ301010","INE0HOL01013","INE0Q7P01013","INE0QVH01025","INE1L0M01019","INE0NR701018","INE1MTV01019","INE163701019","INE1SFA01019","INE0TJ801010","INE0X9I01023","INE920P01019","INE0H4B01011","INE0RH001011","INE0SGC01015","INE0X6O01027","INE004Z01011","INE0OLH01013","INE1P5601010","INE0P6701019","INE0U9D01019","INE0SVD01012","INE632Q01018","INE0U4H01011","INE104Y01012","INE0RU901015","INE1ERK01013","INE0TD401015","INE0JSJ01014","INE0SH001010","INE132901013","INE0OJM01017","INE10A501018","INE0G1D01014","INE1KH601014","INE1K0V01011","INE0QZR01017","INE1RQS01010","INE1II801013","INE1SRC01010","INE1YNB01019","INE0V0L01028","INE0LCG01010","INE1DV401010","INE0N7S01028","INE0UH001016","INE0N6D01014","INE0D7801012","INE0RVQ01016","INE2B5L01011","INE1K8Y01018","INE08NZ01012","INE0YJA01011","INE156901014","INE21UM01018","INE0UZO01024","INE0DQN01013","INE1TFS01019","INE0VYX01018","INE346R01013","INE00ER01015","INE1IA801011","INE2D0Q01027","INE0YHV01011","INE0UR501013","INE1JZB01022","INE0MIO01019","INE15B101011","INE0KN801013","INE0RMF01018","INE0OUT01027","INE14LM01012","INE0SMW01011","INE0TBC01014","INE06ZX01015","INE1H7V01011","INE473T01011","INE161701011","INE484S01010","INE17GV01016","INE0VG601013","INE998U01015","INE0MLZ01019","INE0NT601018","INE517M01028","INE1C2Q01017","INE288301026","INE0O7A01017","INE2JG601017","INE0TI501017","INE0M1F01011","INE0GAO01018","INE0CQA01020","INE0MJQ01020","INE0VJT01017","INE0V9N01017","INE1FFX01018","INE10XK01019","INE510U01018","INE0P5R01014","INE0VDK01019","INE1G2W01011","INE1XJ401012","INE0Q1R01012","INE0OAB01019","INE0OYE01013"]);
 const isNewReview=c=>newReviewIds.has(c?.id);
 // New340-only renderer. Prior320 branches and output remain unchanged.
 const derivedKeyOrder340=new WeakMap();
 const keys340=value=>derivedKeyOrder340.get(value)||window.WALLSTRAT_SCHEMA_KEYS?.(value)||Object.keys(value);
 const batch340Ids=new Set(["INE0TNW01017","INE2O2Y01016","INE0ZN101029","INE0VN801010","INE0PCU01012","INE0VHU01019","INE1S7M01017","INE0QX901013","INE0NA301016","INE0MVO01012","INE2B6701015","INE0O5T01011","INE15WN01014","INE0KWJ01014","INE1W8R01018","INE0KYI01012","INE2BTZ01011","INE0PTR01012","INE0EO401019","INE0PDJ01013"]);
 const isBatch340=c=>batch340Ids.has(c?.id);
 const point340=(c,k)=>c.reader_score_points?.[k]??null;
 const display340=(c,k)=>{const v=point340(c,k);return typeof v==='string'&&/^-?\d+(?:\.\d+)?$/.test(v)?exactDecimalDisplay(v):typeof v==='number'&&Number.isFinite(v)?exactDecimalDisplay(String(v)):'NS';};
 const eligible340=(c,k)=>{const v=point340(c,k);return c.ranking_eligibility?.[k]===true&&(typeof v==='number'&&Number.isFinite(v)||typeof v==='string'&&/^-?\d+(?:\.\d+)?$/.test(v));};
 function large340(value){
  if(!value||typeof value!=='object')return false;let budget=1200;const stack=[value];
  while(stack.length&&budget>0){const v=stack.pop();budget--;if(v&&typeof v==='object'){if(Array.isArray(v)&&v.length>40)return true;let n=0;for(const key of keys340(v)){if(++n>40)return true;stack.push(v[key]);if(stack.length>1200)return true;}}}return budget<=0;
 }
 function range340(a,start,end){const out=new Array(end-start);for(let i=start;i<end;i++)Object.defineProperty(out,String(i-start),{enumerable:true,get:()=>a[i]});return out;}
 function modelChunk340(id){
  const job=modelChunks.get(String(id));if(!job)throw Error('This model view has expired. Reopen the section.');
  modelPruneChildren(id);const previous=modelChunkParent;modelChunkParent=String(id);
  try{const {c,value,key,description}=job;let out='<p><strong>'+esc(description)+'</strong> <button data-model-collapse="'+esc(id)+'">Close this group</button></p>';
   if(Array.isArray(value)&&value.length>40){const step=Math.max(40,Math.ceil(value.length/40));out+='<p class="sme-meta">'+value.length+' complete rows. Open a numbered range, then use browser Find within that range.</p>';for(let i=0;i<value.length;i+=step)out+=modelOpenButton(c,range340(value,i,Math.min(i+step,value.length)),key,'rows '+(i+1)+'–'+Math.min(i+step,value.length)+' of '+value.length);return out;}
   if(!Array.isArray(value)&&keys340(value).length>40){const keys=keys340(value),step=Math.max(40,Math.ceil(keys.length/40));for(let i=0;i<keys.length;i+=step){const group={},order=Object.freeze(keys.slice(i,i+step));for(const k of order)Object.defineProperty(group,k,{enumerable:true,get:()=>value[k]});derivedKeyOrder340.set(group,order);out+=modelOpenButton(c,group,key,'fields '+(i+1)+'–'+Math.min(i+step,keys.length)+' of '+keys.length);}return out;}
   return out+(Array.isArray(value)?'<ol>'+value.map(v=>'<li>'+record340(c,v,key)+'</li>').join('')+'</ol>':'<dl class="sme-audit">'+keys340(value).map(k=>'<dt><strong>'+esc(label(k))+'</strong></dt><dd>'+record340(c,value[k],k)+'</dd>').join('')+'</dl>');
  }finally{modelChunkParent=previous;}
 }
 function record340(c,v,key=''){
  if(v===null||v===undefined)return '<span class="subtle">Not recorded</span>';
  if(typeof v==='number'||typeof v==='boolean')return esc(String(v));
  if(typeof v==='string'&&v.length>262144){const ends=[0];for(let i=32768;i<v.length;i+=32768){if(/[\uD800-\uDBFF]/.test(v[i-1])&&/[\uDC00-\uDFFF]/.test(v[i]))i--;ends.push(i);}ends.push(v.length);const blocks=new Array(ends.length-1);for(let i=0;i<blocks.length;i++)Object.defineProperty(blocks,String(i),{enumerable:true,get:()=>v.slice(ends[i],ends[i+1])});return '<p class="sme-meta">This complete long text is shown in consecutive blocks. Read every block in order; their concatenation is the exact original text.</p>'+modelOpenButton(c,blocks,key,'complete text · '+blocks.length+' consecutive blocks');}
  if(typeof v!=='object')return safe(v)?link(v,v):exactText320(v);
  if(large340(v))return modelOpenButton(c,v,key,label(key||'complete model')+' · '+(Array.isArray(v)?v.length+' rows':keys340(v).length+' fields'));
  if(Array.isArray(v))return v.length?'<ul>'+v.map(x=>'<li>'+record340(c,x,key)+'</li>').join('')+'</ul>':'<span class="subtle">None listed</span>';
  return '<dl class="sme-audit">'+keys340(v).map(k=>'<dt><strong>'+esc(label(k))+'</strong></dt><dd>'+record340(c,v[k],k)+'</dd>').join('')+'</dl>';
 }
 function sections340(c){
  const result=[{id:'overview',title:'Overview',html:()=>'<h2>At a glance</h2><p>Completed research. The full narrative, evidence holds, source qualifications and complete analytical rows remain accessible below. A model calculation does not establish the truth of an unverified assumption.</p><div class="snapshot sme-snapshot">'+['BQS','GQS','IAS'].map(k=>'<div><small>'+k+'</small><strong>'+display340(c,k)+'</strong><span class="score-explain">'+(point340(c,k)==null?'Insufficient evidence':eligible340(c,k)?'Explicitly ranking eligible':'Ranking not enabled')+'</span></div>').join('')+'</div>'}];
  for(const [i,s] of c.sections.entries())result.push({id:'analysis-'+i,title:s.title,html:()=>'<h2>'+esc(s.number)+'. '+esc(s.title)+'</h2>'+record340(c,s.content_markdown)});
  for(const key of keys340(c)){
   if(key==='sections'||key==='analytical_companions')continue;
   result.push({id:'field-'+key,title:key==='report_markdown'?'Complete accepted research narrative':key==='reader_source_records'?'Source records and qualifications':label(key),html:()=>'<h2>'+esc(key==='report_markdown'?'Complete accepted research narrative':label(key))+'</h2>'+record340(c,c[key],key)});
  }
  for(const name of keys340(c.analytical_companions||{}))result.push({id:'companion-'+name,title:'Complete analytical file: '+name,html:()=>'<h2>'+esc(name)+'</h2>'+record340(c,c.analytical_companions[name],name)});
  return result;
 }

 const batch308Ids=new Set(["INE288301026","INE0O7A01017","INE2JG601017","INE0TI501017","INE0M1F01011","INE0GAO01018","INE0CQA01020","INE0MJQ01020"]);
 const isBatch308=c=>batch308Ids.has(c?.id);
 const batch320Ids=new Set(["INE0VJT01017","INE0V9N01017","INE1FFX01018","INE10XK01019","INE510U01018","INE0P5R01014","INE0VDK01019","INE1G2W01011","INE1XJ401012","INE0Q1R01012","INE0OAB01019","INE0OYE01013"]);
 const isBatch320=c=>batch320Ids.has(c?.id);
 const batch320Point=(c,k)=>{const v=c.reader_score_points?.[k];return c.reader_score_points?(v==='NS'?null:v):batch300Point(c,k);};
 const sourceRecords=c=>isBatch340(c)?c.reader_source_records:isBatch320(c)&&c.reader_source_records?c.reader_source_records:c?.sources;
 const batch320Display=(c,k)=>{const v=batch320Point(c,k);if(v==null)return 'NS';if(typeof v==='string'&&/^-?\d+(?:\.\d+)?$/.test(v))return exactDecimalDisplay(v);if(typeof v==='number'&&Number.isFinite(v))return exactDecimalDisplay(String(v));return 'NS';};
 const batch320Rounded=(c,k)=>{const v=batch320Display(c,k);return v==='NS'?NaN:Number(v);};
 const batch320Eligibility=(c,k)=>c.ranking_eligibility===false?false:batch300Eligibility(c,k)??c.scores?.[k]?.ranking_eligible??c.scores?.[k]?.rank_eligible;
 const batch320Eligible=(c,k)=>{const v=batch320Point(c,k);return batch320Eligibility(c,k)===true&&(typeof v==='number'&&Number.isFinite(v)||typeof v==='string'&&/^-?\d+(?:\.\d+)?$/.test(v)&&Number.isFinite(Number(v)));};
 const batch320Body=s=>{for(const key of ['text','content','body','content_markdown','body_markdown','paragraphs','prose','markdown'])if(s[key]!==undefined&&s[key]!==null)return {key,value:s[key]};return {key:null,value:undefined};};
 const exactText320=s=>esc(s).replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g,(_,t,u)=>{const unescape=x=>x.replace(/&(?:amp|lt|gt|quot|#39);/g,e=>({'&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&#39;':"'"}[e]));return link(unescape(u),unescape(t));}).replace(/\[([SE]\d+)\]/g,(m,id)=>{const source=sourceRecords(current)?.find(s=>s.id===id);return source?link(source.url,'['+id+']'):m;}).replace(/\n/g,'<br>');

 const batch300Ids=new Set(["INE0MIO01019","INE15B101011","INE0KN801013","INE0RMF01018","INE0OUT01027","INE14LM01012","INE0SMW01011","INE0TBC01014","INE06ZX01015","INE1H7V01011","INE473T01011","INE161701011","INE484S01010","INE17GV01016","INE0VG601013","INE998U01015","INE0MLZ01019","INE0NT601018","INE517M01028","INE1C2Q01017","INE288301026","INE0O7A01017","INE2JG601017","INE0TI501017","INE0M1F01011","INE0GAO01018","INE0CQA01020","INE0MJQ01020","INE0VJT01017","INE0V9N01017","INE1FFX01018","INE10XK01019","INE510U01018","INE0P5R01014","INE0VDK01019","INE1G2W01011","INE1XJ401012","INE0Q1R01012","INE0OAB01019","INE0OYE01013"]);
 const isBatch300=c=>batch300Ids.has(c?.id);
 const batch300Point=(c,k)=>{let v=c.scores?.[k];if(v!==null&&typeof v==='object'){const keys=['final','final_unrounded','final_score'].filter(x=>Object.prototype.hasOwnProperty.call(v,x));if(keys.length!==1)throw Error('Ambiguous final score');v=v[keys[0]];}return v==='NS'?null:v;};
 const batch300Eligibility=(c,k)=>c.ranking_eligibility?.[k]??c.ranking_eligibility?.[({BQS:'quality',GQS:'growth_quality',IAS:'investment'})[k]]??c.ranking_eligibility?.[k.toLowerCase()]??c.ranking_eligibility?.[({BQS:'best_businesses',GQS:'best_growth_businesses',IAS:'best_investments'})[k]]??c.ranking_eligibility?.[({BQS:'business_quality',GQS:'growth_quality',IAS:'investment_attractiveness'})[k]];
 const batch300Display=(c,k)=>{const v=batch300Point(c,k);if(v==null)return 'NS';if(typeof v==='string'&&/^-?\d+(?:\.\d+)?$/.test(v))return exactDecimalDisplay(v);if(typeof v==='number'&&Number.isFinite(v))return exactDecimalDisplay(String(v));return 'NS';};
 const batch300Rounded=(c,k)=>{const v=batch300Display(c,k);return v==='NS'?NaN:Number(v);};
 const batch300Eligible=(c,k)=>{const v=batch300Point(c,k);return batch300Eligibility(c,k)===true&&(typeof v==='number'&&Number.isFinite(v)||typeof v==='string'&&/^-?\d+(?:\.\d+)?$/.test(v)&&Number.isFinite(Number(v)));};
 const batch300Body=s=>{for(const key of ['text','content','body','content_markdown','body_markdown','paragraphs'])if(s[key]!==undefined&&s[key]!==null)return {key,value:s[key]};return {key:null,value:undefined};};

 const batch280Ids=new Set(["INE0N6D01014","INE0D7801012","INE0RVQ01016","INE2B5L01011","INE1K8Y01018","INE08NZ01012","INE0YJA01011","INE156901014","INE21UM01018","INE0UZO01024","INE0DQN01013","INE1TFS01019","INE0VYX01018","INE346R01013","INE00ER01015","INE1IA801011","INE2D0Q01027","INE0YHV01011","INE0UR501013","INE1JZB01022"]);
 const isBatch280=c=>batch280Ids.has(c?.id);
 const batch280Point=(c,k)=>{let v=c.scores?.[k];if(v!==null&&typeof v==='object'){const keys=['final','final_unrounded','final_score'].filter(x=>Object.prototype.hasOwnProperty.call(v,x));if(keys.length!==1)throw Error('Ambiguous final score');v=v[keys[0]];}return v==='NS'?null:v;};
 const batch280Eligibility=(c,k)=>c.ranking_eligibility?.[k]??c.ranking_eligibility?.[({BQS:'quality',GQS:'growth_quality',IAS:'investment'})[k]]??c.ranking_eligibility?.[k.toLowerCase()]??c.ranking_eligibility?.[({BQS:'best_businesses',GQS:'best_growth_businesses',IAS:'best_investments'})[k]]??c.ranking_eligibility?.[({BQS:'business_quality',GQS:'growth_quality',IAS:'investment_attractiveness'})[k]];
 const batch280Display=(c,k)=>{const v=batch280Point(c,k);if(v==null)return 'NS';if(typeof v==='string'&&/^-?\d+(?:\.\d+)?$/.test(v))return exactDecimalDisplay(v);if(typeof v==='number'&&Number.isFinite(v))return exactDecimalDisplay(String(v));return 'NS';};
 const batch280Rounded=(c,k)=>{const v=batch280Display(c,k);return v==='NS'?NaN:Number(v);};
 const batch280Eligible=(c,k)=>{const v=batch280Point(c,k);return batch280Eligibility(c,k)===true&&(typeof v==='number'&&Number.isFinite(v)||typeof v==='string'&&/^-?\d+(?:\.\d+)?$/.test(v)&&Number.isFinite(Number(v)));};
 const batch280Body=s=>{for(const key of ['text','content','body','content_markdown','body_markdown','paragraphs'])if(s[key]!==undefined&&s[key]!==null)return {key,value:s[key]};return {key:null,value:undefined};};

 const batch260Ids=new Set(["INE1ERK01013","INE0TD401015","INE0JSJ01014","INE0SH001010","INE132901013","INE0OJM01017","INE10A501018","INE0G1D01014","INE1KH601014","INE1K0V01011","INE0QZR01017","INE1RQS01010","INE1II801013","INE1SRC01010","INE1YNB01019","INE0V0L01028","INE0LCG01010","INE1DV401010","INE0N7S01028","INE0UH001016"]);
 const isBatch260=c=>batch260Ids.has(c?.id);
 const batch260Point=(c,k)=>{let v=c.scores?.[k];if(v!==null&&typeof v==='object'){const keys=['final','final_unrounded','final_score'].filter(x=>Object.prototype.hasOwnProperty.call(v,x));if(keys.length!==1)throw Error('Ambiguous final score');v=v[keys[0]];}return v==='NS'?null:v;};
 const batch260Eligibility=(c,k)=>c.ranking_eligibility?.[k]??c.ranking_eligibility?.[({BQS:'quality',GQS:'growth_quality',IAS:'investment'})[k]]??c.ranking_eligibility?.[k.toLowerCase()]??(c.id==='INE0SH001010'?c.ranking_eligibility?.['descriptive_'+k]:undefined);
 const batch260Display=(c,k)=>{const v=batch260Point(c,k);if(v==null)return 'NS';if(typeof v==='string'&&/^-?\d+(?:\.\d+)?$/.test(v))return exactDecimalDisplay(v);if(typeof v==='number'&&Number.isFinite(v))return exactDecimalDisplay(String(v));return 'NS';};
 const batch260Rounded=(c,k)=>{const v=batch260Display(c,k);return v==='NS'?NaN:Number(v);};
 const batch260Eligible=(c,k)=>{const v=batch260Point(c,k);return batch260Eligibility(c,k)===true&&(typeof v==='number'&&Number.isFinite(v)||typeof v==='string'&&/^-?\d+(?:\.\d+)?$/.test(v)&&Number.isFinite(Number(v)));};
 const batch260Body=s=>{for(const key of ['text','content','body','content_markdown','body_markdown','paragraphs'])if(s[key]!==undefined&&s[key]!==null)return {key,value:s[key]};return {key:null,value:undefined};};

 const batch240Ids=new Set(["INE1MTV01019","INE163701019","INE1SFA01019","INE0TJ801010","INE0X9I01023","INE920P01019","INE0H4B01011","INE0RH001011","INE0SGC01015","INE0X6O01027","INE004Z01011","INE0OLH01013","INE1P5601010","INE0P6701019","INE0U9D01019","INE0SVD01012","INE632Q01018","INE0U4H01011","INE104Y01012","INE0RU901015","INE1ERK01013","INE0TD401015","INE0JSJ01014","INE0SH001010","INE132901013","INE0OJM01017","INE10A501018","INE0G1D01014","INE1KH601014","INE1K0V01011","INE0QZR01017","INE1RQS01010","INE1II801013","INE1SRC01010","INE1YNB01019","INE0V0L01028","INE0LCG01010","INE1DV401010","INE0N7S01028","INE0UH001016","INE0N6D01014","INE0D7801012","INE0RVQ01016","INE2B5L01011","INE1K8Y01018","INE08NZ01012","INE0YJA01011","INE156901014","INE21UM01018","INE0UZO01024","INE0DQN01013","INE1TFS01019","INE0VYX01018","INE346R01013","INE00ER01015","INE1IA801011","INE2D0Q01027","INE0YHV01011","INE0UR501013","INE1JZB01022","INE0MIO01019","INE15B101011","INE0KN801013","INE0RMF01018","INE0OUT01027","INE14LM01012","INE0SMW01011","INE0TBC01014","INE06ZX01015","INE1H7V01011","INE473T01011","INE161701011","INE484S01010","INE17GV01016","INE0VG601013","INE998U01015","INE0MLZ01019","INE0NT601018","INE517M01028","INE1C2Q01017"]);
 const isBatch240=c=>batch240Ids.has(c?.id);
 const researchDate=c=>isBatch359(c)?(typeof c.as_of==='string'?c.as_of:'see research header'):isBatch340(c)?(typeof c.as_of==='string'?c.as_of:'see research header'):isBatch240(c)&&c.as_of!==null&&typeof c.as_of==='object'?c.as_of.information_cutoff:c.as_of;
 const scorePoint=(c,k)=>isBatch359(c)?new359.point(c,k):isBatch340(c)?point340(c,k):isBatch320(c)?batch320Point(c,k):isBatch300(c)?batch300Point(c,k):isBatch280(c)?batch280Point(c,k):isBatch260(c)?batch260Point(c,k):isBatch240(c)&&c.scores?.[k]!==null&&typeof c.scores?.[k]==='object'&&Object.prototype.hasOwnProperty.call(c.scores[k],'final')?c.scores[k].final:c.scores?.[k];
 const batch220Ids=new Set(["INE0MYZ01012","INE0NNZ01013","INE1YC401018","INE1JJF01019","INE0S1D01010","INE870Z01015","INE0W5Q01017","INE0XOW01017","INE1IE301018","INE0P3N01018","INE0N6U01018","INE0V8A01016","INE0L1C01019","INE0MGA01012","INE0KZ301010","INE0HOL01013","INE0Q7P01013","INE0QVH01025","INE1L0M01019","INE0NR701018","INE1MTV01019","INE163701019","INE1SFA01019","INE0TJ801010","INE0X9I01023","INE920P01019","INE0H4B01011","INE0RH001011","INE0SGC01015","INE0X6O01027","INE004Z01011","INE0OLH01013","INE1P5601010","INE0P6701019","INE0U9D01019","INE0SVD01012","INE632Q01018","INE0U4H01011","INE104Y01012","INE0RU901015","INE1ERK01013","INE0TD401015","INE0JSJ01014","INE0SH001010","INE132901013","INE0OJM01017","INE10A501018","INE0G1D01014","INE1KH601014","INE1K0V01011","INE0QZR01017","INE1RQS01010","INE1II801013","INE1SRC01010","INE1YNB01019","INE0V0L01028","INE0LCG01010","INE1DV401010","INE0N7S01028","INE0UH001016","INE0N6D01014","INE0D7801012","INE0RVQ01016","INE2B5L01011","INE1K8Y01018","INE08NZ01012","INE0YJA01011","INE156901014","INE21UM01018","INE0UZO01024","INE0DQN01013","INE1TFS01019","INE0VYX01018","INE346R01013","INE00ER01015","INE1IA801011","INE2D0Q01027","INE0YHV01011","INE0UR501013","INE1JZB01022","INE0MIO01019","INE15B101011","INE0KN801013","INE0RMF01018","INE0OUT01027","INE14LM01012","INE0SMW01011","INE0TBC01014","INE06ZX01015","INE1H7V01011","INE473T01011","INE161701011","INE484S01010","INE17GV01016","INE0VG601013","INE998U01015","INE0MLZ01019","INE0NT601018","INE517M01028","INE1C2Q01017"]);
 const isBatch220=c=>batch220Ids.has(c?.id);
 const batch200Ids=new Set(["INE0QFE01017","INE12E301017","INE17DP01015","INE0JVH01012","INE0PLX01017","INE1UYW01010","INE0OLZ01015","INE0GYI01028","INE0PIC01017","INE1KI801019","INE1OTR01013","INE0TO501019","INE111601014","INE0O7401018","INE0XE501015","INE0PA401012","INE0WKY01013","INE16XA01017","INE0MRE01011","INE464Z01017"]);
 const isBatch200=c=>batch200Ids.has(c?.id);
 const reviewValue=(c,v,key="")=>isNewReview(c)?recoveredRecord(c,v,key):render(v,key);
 const isExtendedReview=c=>extendedReviewIds.has(c?.id);
 const alreadyRenderedReviewFields=new Set(["id","isin","name","symbol","exchange","sector","research_status","as_of","summary","identity_note","quote","scores","score_note","sections","existing_research","metrics","financial_history","gates","factor_audit","score_audit","valuation","confidence","liquidity","monitoring_plan","evidence","limitations","next_steps","sources"]);
 const supplementalReviewFields=c=>Object.fromEntries(Object.entries(c).filter(([k])=>!alreadyRenderedReviewFields.has(k)));
 const recoveredSources=(c,ids)=>(ids||[]).map(id=>{let s=sourceRecords(c)?.find(x=>x.id===id||((isBatch260(c)||(isBatch280(c)||isBatch300(c)))&&x.source_id===id));if(!s&&(isBatch260(c)||(isBatch280(c)||isBatch300(c)))&&typeof id==='string'){const matches=(sourceRecords(c)||[]).filter(x=>id.startsWith((x.id??x.source_id)+' '));if(matches.length===1)s=matches[0];}return s?link(s.url,id):esc(id);}).join(', ');
 // Applied only to the new unpublished batch. The underlying research is never
 // filtered, truncated or recomputed. Every branch has an explicit open control.
 const modelChunks=new Map(),modelLargeCache=new WeakMap();let modelChunkSerial=0,modelChunkParent=null;
 function isLargeModelValue(value){
  if(!value||typeof value!=='object')return false;
  if(modelLargeCache.has(value))return modelLargeCache.get(value);
  let budget=1200;const stack=[value];
  while(stack.length&&budget>0){const v=stack.pop();budget--;if(v&&typeof v==='object')for(const x of Object.values(v)){stack.push(x);if(stack.length>1200){budget=0;break;}}}
  const large=budget<=0;modelLargeCache.set(value,large);return large;
 }
 function modelOpenButton(c,value,key,description){
  const id=String(++modelChunkSerial);modelChunks.set(id,{c,value,key,description,children:new Set()});
  if(modelChunkParent!==null)modelChunks.get(modelChunkParent)?.children.add(id);
  return '<div class="sme-model-region" data-model-region="'+id+'"><button data-model-expand="'+id+'">Open '+esc(description)+'</button><p class="sme-meta">Complete data retained. Open a labelled field or row range to inspect every value; nothing has been omitted.</p></div>';
 }
 function modelPruneChildren(id){
  const job=modelChunks.get(String(id));if(!job)return;
  for(const child of job.children){modelPruneChildren(child);modelChunks.delete(child);}job.children.clear();
 }
 function modelChunkContent(id){
  if(isBatch340(modelChunks.get(String(id))?.c))return modelChunk340(id);
  const job=modelChunks.get(String(id));if(!job)throw Error('This model view has expired. Reopen the research section.');
  modelPruneChildren(id);const previousParent=modelChunkParent;modelChunkParent=String(id);
  try{const {c,value,key,description}=job;let result='<p><strong>'+esc(description)+'</strong> <button data-model-collapse="'+esc(id)+'">Close this group</button></p>';
  if(Array.isArray(value)){
   if(value.length>40){result+='<p class="sme-meta">'+value.length+' total rows, numbered from 1. Each range is complete.</p>';
    for(let i=0;i<value.length;i+=40)result+=modelOpenButton(c,value.slice(i,i+40),key,'rows '+(i+1)+'–'+Math.min(i+40,value.length)+' of '+value.length);
   }else result+='<ol>'+value.map(v=>'<li>'+recoveredRecord(c,v,key)+'</li>').join('')+'</ol>';
  }else result+='<dl class="sme-audit">'+Object.entries(value).map(([k,v])=>'<dt><strong>'+esc(label(k))+'</strong></dt><dd>'+recoveredRecord(c,v,k)+'</dd>').join('')+'</dl>';
  return result;}finally{modelChunkParent=previousParent;}
 }
 function modelCollapseContent(id){
  const job=modelChunks.get(String(id));if(!job)throw Error('This model view has expired.');modelPruneChildren(id);
  return '<button data-model-expand="'+esc(id)+'">Open '+esc(job.description)+'</button><p class="sme-meta">Complete data retained. Open this group again to inspect every value.</p>';
 }

 function recoveredRecord(c,v,key=''){
  if(isBatch340(c))return record340(c,v,key);
  if(isBatch320(c)&&isLargeModelValue(v))return modelOpenButton(c,v,key,label(key||'complete model')+' · '+(Array.isArray(v)?v.length+' rows':Object.keys(v).length+' fields'));
  if(key==='source_ids'&&Array.isArray(v))return recoveredSources(c,v);
  if(v===null||v===undefined)return '<span class="subtle">Not recorded</span>';
  if(typeof v==='number'||typeof v==='boolean')return esc(String(v));
  if(typeof v!=='object')return safe(v)?link(v,v):(isBatch320(c)?exactText320(v):text(v));
  if(Array.isArray(v))return v.length?'<ul>'+v.map(x=>'<li>'+recoveredRecord(c,x,key)+'</li>').join('')+'</ul>':'<span class="subtle">None listed</span>';
  return '<dl class="sme-audit">'+Object.entries(v).map(([k,x])=>'<dt><strong>'+esc(label(k))+'</strong></dt><dd>'+recoveredRecord(c,x,k)+'</dd>').join('')+'</dl>';
 }
 const recoveredNotice=c=>isRecovered(c)?'<aside class="sme-note" role="note"><strong>Recovered narrative edition · original model tables unavailable</strong><p>This edition preserves the approved 15-section narrative, gates, evidence, qualifications and source ledger. The original financial-history tables, year-by-year scenario cash flows, sensitivity arrays, daily liquidity series and some compact audit fields were not recoverable. Numbers stated in the approved text are retained; missing numbers have not been recreated. This is not a restored executable financial model. An unavailable recovered table field is not a new NS judgment.</p><p>Any quality scores shown are transcribed from the approved scorecard and remain subject to its qualifications and provisional comparison scope. NS remains NS. This edition is not an investment-clearance certificate.</p></aside>':'';
 const recoveredSourceExtras=(c,s)=>{if(!isRecovered(c)&&!isExtendedReview(c))return '';const omitted=new Set(['id','title','url','kind','document_date','accessed','read_status','locator']);const extra=Object.fromEntries(Object.entries(s).filter(([k])=>!omitted.has(k)));return Object.keys(extra).length?'<h4>Additional source qualifications and metadata</h4>'+recoveredRecord(c,extra):'';};

 const loaded=new Map(),loading=new Map();let requestVersion=0,loadError='',metadata={};
 const defaults={q:'',status:'all',sector:'all',page:1,size:10,sort:'BQS',order:'desc',minBQS:'',minGQS:'',minIAS:''};
 let data=[],byId,current=null,active='',state={...defaults},filterOpen=false,contentsOpen=!(window.matchMedia?.('(max-width: 800px)').matches);
 const route=()=>{const p=new URLSearchParams(location.hash.slice(1));state={...defaults};for(const k of Object.keys(defaults))if(p.has(k))state[k]=p.get(k);state.page=Math.max(1,Number(state.page)||1);state.size=[10,20,25,50,100].includes(Number(state.size))?Number(state.size):10;if(!['BQS','GQS','IAS','name'].includes(state.sort))state.sort='BQS';if(!['asc','desc','name-asc','name-desc','sector-asc','sector-desc'].includes(state.order))state.order='desc';current=byId.get(p.get('company'))||null;active=p.get('section')||'';draw();};
 function address(company=current?.id,section=active){const p=new URLSearchParams();for(const [k,v] of Object.entries(state))if(v!==defaults[k])p.set(k,v);if(company)p.set('company',company);if(section&&company)p.set('section',section);return '#'+p.toString();}
 function write(replace=false){history[replace?'replaceState':'pushState'](null,'',address());}
 const exactDecimalDisplay=v=>{const m=/^(-?)(\d+)(?:\.(\d+))?$/.exec(v);if(!m)return null;const f=(m[3]||'')+'00';let n=BigInt(m[2])*10n+BigInt(f[0]);if(f[1]>='5')n+=1n;return (m[1]&&n!==0n?'-':'')+(n/10n).toString()+'.'+(n%10n).toString();};
 const score=(c,k)=>isBatch359(c)?(new359.point(c,k)==null?'NS':exactDecimalDisplay(String(new359.point(c,k)))):isBatch340(c)?display340(c,k):isBatch320(c)?batch320Display(c,k):isBatch300(c)?batch300Display(c,k):isBatch280(c)?batch280Display(c,k):isBatch260(c)?batch260Display(c,k):isBatch220(c)&&typeof c.scores?.[k]==='string'&&/^-?\d+(?:\.\d+)?$/.test(c.scores[k])?exactDecimalDisplay(c.scores[k]):scorePoint(c,k)==null?'NS':typeof c.scores[k]==='number'?(Math.floor(c.scores[k]*10+0.5+1e-8)/10).toFixed(1):esc(c.scores[k].score??'NS');
 const count=s=>data.filter(c=>c.research_status===s).length;
 const option=(v,t,selected)=>`<option value="${esc(v)}"${selected===v?' selected':''}>${esc(t)}</option>`;
 const rounded=(c,k)=>isBatch340(c)?((c,k)=>display340(c,k)==='NS'?NaN:Number(display340(c,k)))(c,k):isBatch320(c)?batch320Rounded(c,k):isBatch300(c)?batch300Rounded(c,k):isBatch280(c)?batch280Rounded(c,k):isBatch260(c)?batch260Rounded(c,k):isBatch220(c)&&typeof c.scores?.[k]==='string'&&exactDecimalDisplay(c.scores[k])!==null?Number(exactDecimalDisplay(c.scores[k])):Math.floor(c.scores[k]*10+0.5+1e-8)/10;
 const eligible=(c,k)=>isBatch359(c)?new359.eligible(c,k):isBatch340(c)?eligible340(c,k):isBatch320(c)?batch320Eligible(c,k):isBatch300(c)?batch300Eligible(c,k):isBatch280(c)?batch280Eligible(c,k):isBatch260(c)?batch260Eligible(c,k):(isNewReview(c)||c.research_status==='deep')&&(c.ranking_eligibility?.[k]===true||(isBatch220(c)&&c.ranking_eligibility?.[k]===undefined&&c.ranking_eligibility?.[({BQS:'quality',GQS:'growth_quality',IAS:'investment'})[k]]===true))&&(Number.isFinite(c.scores?.[k])||(isBatch220(c)&&typeof c.scores?.[k]==='string'&&/^-?\d+(?:\.\d+)?$/.test(c.scores[k])&&Number.isFinite(Number(c.scores[k]))));
 const ordering=k=>(a,b)=>rounded(b,k)-rounded(a,k)||a.name.localeCompare(b.name);
 function ranking(c){if(state.sort==='name')return '—';const all=data.filter(x=>eligible(x,state.sort)).sort(ordering(state.sort));return String(all.findIndex(x=>rounded(x,state.sort)===rounded(c,state.sort))+1);}
 function filtered(){const words=state.q.toLowerCase().split(/\s+/).filter(Boolean);const list=data.filter(c=>(state.status==='all'||c.research_status===state.status)&&(state.sector==='all'||c.sector===state.sector)&&words.every(w=>[c.name,c.symbol,c.isin,c.sector,c.exchange].join(' ').toLowerCase().includes(w))&&(state.sort==='name'||eligible(c,state.sort))&&['BQS','GQS','IAS'].every(k=>!state['min'+k]||eligible(c,k)&&c.scores[k]>=Number(state['min'+k])));return list.sort((a,b)=>{if(state.order.startsWith('sector-')){const d=(a.sector||'').localeCompare(b.sector||'');return (state.order.endsWith('desc')?-d:d)||a.name.localeCompare(b.name);}if(state.sort==='name'||state.order.startsWith('name-')){const d=a.name.localeCompare(b.name);return state.order==='name-desc'?-d:d;}const d=rounded(b,state.sort)-rounded(a,state.sort);return (state.order==='asc'?-d:d)||a.name.localeCompare(b.name);});}
 function index(){
  const list=filtered(),pages=Math.max(1,Math.ceil(list.length/state.size));state.page=Math.min(state.page,pages);
  const ranks=new Map();let prior=null,rank=0;list.filter(c=>state.sort!=='name'&&eligible(c,state.sort)).slice().sort(ordering(state.sort)).forEach((c,i)=>{const val=rounded(c,state.sort);if(val!==prior)rank=i+1;ranks.set(c.id,rank);prior=val;});
  const nfilters=Number(state.status!=='all')+['BQS','GQS','IAS'].filter(k=>state['min'+k]).length;
  return `<section id="research" class="index-section" tabindex="-1" aria-labelledby="rankings-title"><div class="section-heading"><div><p class="eyebrow">EXPLORE &amp; COMPARE</p><h2 id="rankings-title">The company index</h2></div><p class="research-date">Quality, growth &amp; entry price</p></div>
  <div class="controls"><div class="search-field"><svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="m15.5 15.5 5 5" stroke="currentColor" stroke-width="1.7"/></svg><label class="sr-only" for="smeSearch">Search names, tickers, ISINs or sectors</label><input id="smeSearch" type="search" placeholder="Search companies, tickers or sectors" value="${esc(state.q)}" autocomplete="off"></div>
  <label class="sr-only" for="smeSector">Filter by sector</label><select id="smeSector">${option('all','All sectors',state.sector)}${[...new Set(data.map(c=>c.sector||'Unknown'))].sort().map(s=>option(s,s,state.sector)).join('')}</select>
  <details id="filterPanel" class="filter-disclosure"${filterOpen?' open':''}><summary>Filters ${nfilters?'<span id="filterBadge">'+nfilters+'</span>':''}<span class="filter-icon" aria-hidden="true">⌄</span></summary><div class="filter-fields"><label>Research status<select id="smeStatus">${[['all','All research statuses'],['deep','Reviewed companies'],['pending','Pending research']].map(([v,t])=>option(v,t,state.status)).join('')}</select><fieldset class="minimums"><legend>Minimum eligible score</legend>${['BQS','GQS','IAS'].map(k=>'<label>'+k+'<select id="min'+k+'" aria-label="Minimum eligible '+k+'">'+option('','Any',state['min'+k])+[5,6,7,8,9].map(n=>option(String(n),n+'+',state['min'+k])).join('')+'</select></label>').join('')}</fieldset><label>Rows per page<select id="smeSize">${[10,20,25,50,100].map(n=>option(String(n),n+' rows',String(state.size))).join('')}</select></label><p class="subtle">Every search word must match. Score rankings and minimums include only eligible point scores.</p></div></details><button id="resetFilters" class="reset-button">Reset</button></div>
  <div class="index-topline"><div class="tabs" role="group" aria-label="Select ranking">${[['BQS','Business quality'],['GQS','Growth quality'],['IAS','Entry attractiveness'],['name','A–Z']].map(([k,t])=>'<button data-rank="'+k+'" aria-pressed="'+(state.sort===k)+'" class="'+(state.sort===k?'active':'')+'">'+(k==='name'?t:'<span>'+k+'</span> '+t)+'</button>').join('')}</div><label class="sort-control"><span class="sr-only">Sort companies</span><select id="sortRows">${[['desc','Score: high to low'],['asc','Score: low to high'],['name-asc','Company: A–Z'],['name-desc','Company: Z–A'],['sector-asc','Sector: A–Z'],['sector-desc','Sector: Z–A']].map(([v,t])=>option(v,t,state.order)).join('')}</select></label></div>
  <p class="active-filters" aria-live="polite">${esc([state.q&&'“'+state.q+'”',state.sector!=='all'&&state.sector,state.status!=='all'&&(state.status==='deep'?'Reviewed companies':'Pending research'),...['BQS','GQS','IAS'].map(k=>state['min'+k]&&k+' ≥ '+state['min'+k])].filter(Boolean).join(' · '))}</p>
  <div class="index-panel"><div class="scroll rank-scroll" tabindex="0" role="region" aria-label="Company scores; scroll horizontally on narrow screens"><table class="ranktable"><caption class="sr-only">Company quality comparisons. NS means insufficient evidence, not zero. Only eligible scores receive a rank.</caption><colgroup><col class="rank-col"><col class="name-col"><col class="sector-col"><col class="score-col"><col class="score-col"><col class="score-col"><col class="arrow-col"></colgroup><thead><tr><th scope="col">#</th><th scope="col"><button data-rank="name">Company</button></th><th scope="col">Sector</th>${['BQS','GQS','IAS'].map(k=>'<th scope="col" class="num"><button data-rank="'+k+'">'+k+'</button></th>').join('')}<th scope="col" class="arrow-col"><span class="sr-only">Open analysis</span></th></tr></thead><tbody>${list.slice((state.page-1)*state.size,state.page*state.size).map(c=>`<tr><td>${ranks.get(c.id)||'—'}</td><td class="name"><a class="company-link" href="${address(c.id,'')}" data-company="${esc(c.id)}">${esc(c.name)}</a><span class="sym">${esc(c.symbol||c.isin)}${c.research_status==='pending'?' · Pending':isRecovered(c)?' · Recovered narrative':''}<span class="sector-mobile">${esc(c.sector||'Unknown')}</span></span></td><td class="sector-cell">${esc(c.sector||'Unknown')}</td>${['BQS','GQS','IAS'].map(k=>'<td class="num '+(state.sort===k?'selected-measure':'')+'" title="'+(scorePoint(c,k)==null?'NS · insufficient evidence':eligible(c,k)?'Ranking eligible':'Excluded from ranking')+'"><span class="'+(scorePoint(c,k)==null?'ns':'score')+'">'+score(c,k)+'</span>'+ (c.scores?.[k]!=null&&!eligible(c,k)?'<span class="score-explain">Unranked</span>':'')+'</td>').join('')}<td class="arrow-col"><a class="open-analysis" href="${address(c.id,'')}" data-company="${esc(c.id)}" aria-label="Open ${esc(c.name)} analysis">↗</a></td></tr>`).join('')||'<tr><td colspan="7" class="blank">No companies match these filters.<div class="empty-actions"><button id="resetFilters">Clear filters</button></div></td></tr>'}</tbody></table></div>
  <div class="pagination"><span class="count" role="status">${list.length?((state.page-1)*state.size+1)+'–'+Math.min(state.page*state.size,list.length)+' of '+list.length+' companies':'0 matches'}</span><span>Page ${state.page} of ${pages}</span><button data-page="${state.page-1}" aria-label="Previous page" ${state.page<=1?'disabled':''}>←</button><button data-page="${state.page+1}" aria-label="Next page" ${state.page>=pages?'disabled':''}>→</button></div></div>
  <div class="index-notes"><p>${list.length} matching companies · ${state.sort==='name'?'alphabetical view':state.sort+' ranking-eligible only · ties share a rank'} · ${count('deep')} completed research reviews · ${metadata.currently_published_reviews} currently public. <a href="#status=deep&amp;sort=name">View all reviewed companies ↗</a></p><p><strong>NS</strong> means insufficient evidence, not zero. Unranked scores retain their limitations. <a href="#methodology">About the scores ↗</a></p></div></section>`;
 }
 function sections359(c){
  const result=[{id:'overview',title:'Overview',html:()=>'<h2>At a glance</h2><p>Completed qualified research. Read the full narrative, source limitations and exact analytical companions. NS means insufficient evidence, not zero. A conditional calculation does not authenticate an uncertain input.</p><div class="snapshot sme-snapshot">'+['BQS','GQS','IAS'].map(k=>'<div><small>'+k+'</small><strong>'+score(c,k)+'</strong><span class="score-explain">'+(new359.point(c,k)==null?'Insufficient evidence':new359.eligible(c,k)?'Explicitly ranking eligible':'Ranking not enabled')+'</span></div>').join('')+'</div>'}];
  for(const [i,s] of c.sections.entries())result.push({id:'analysis-'+i,title:s.title,html:()=>'<h2>'+esc(s.number)+'. '+esc(s.title)+'</h2>'+exactText320(s.content_markdown)});
  result.push({id:'sources',title:'Sources and source qualifications',html:()=>new359.markup(c,'reader_source_registers')});
  result.push({id:'score-audit',title:'Complete score and factor audit',html:()=>new359.markup(c,'reader_score_audit')});
  result.push({id:'full-record-and-companions',title:'Complete analytical record, sources and models',html:()=>new359.markup(c)});
  return result;
 }
 function sections(c){if(isBatch359(c))return sections359(c);if(isBatch340(c))return sections340(c);const result=[{id:'overview',title:'Overview',html:()=>`<h2>At a glance</h2><p class="lead">${text(c.summary)}</p><p class="sme-meta">${esc(isRecovered(c)?'Recovered approved narrative; original structured model tables are unavailable.':c.research_status==='screen'?'Preliminary screen, not completed forensic research.':c.research_status==='pending'?'Research pending. No investment conclusion has been issued.':'Completed review; evidence gaps and conditional conclusions remain visible below.')}</p><div class="snapshot sme-snapshot">${['BQS','GQS','IAS'].map(k=>'<div><small>'+k+'</small><strong>'+score(c,k)+'</strong><span class="score-explain">'+ (scorePoint(c,k)==null?'Insufficient evidence':eligible(c,k)?'Ranking eligible':'Excluded from ranking')+'</span></div>').join('')}</div><p>${text(c.score_note||'')}</p>${c.identity_note?'<h3>Identity and listing</h3>'+reviewValue(c,c.identity_note):''}${c.quote?'<h3>Dated quote</h3>'+reviewValue(c,c.quote):''}${c.existing_research?'<h3>Earlier research</h3>'+reviewValue(c,c.existing_research):''}`}];
 if(isRecovered(c)&&c.approved_disclosure_summary)result.push({id:'approved-disclosure',title:'Approved publication qualifications',html:()=>'<h2>Approved publication qualifications</h2>'+text(c.approved_disclosure_summary)});
 for(const [i,s] of (c.sections||[]).entries()){if(isBatch320(c)){result.push({id:'analysis-'+(s.id||i),title:s.title||'Research finding',html:()=>{const body=batch320Body(s),omit=new Set(['id','number','title',body.key]);let citations='';if(Array.isArray(s.source_ids)&&s.source_ids.length){omit.add('source_ids');citations='<p class="sme-meta">Evidence: '+recoveredSources(c,s.source_ids)+'</p>';}return '<h2>'+esc(s.title||'Research finding')+'</h2>'+recoveredRecord(c,body.value)+citations+recoveredRecord(c,Object.fromEntries(Object.entries(s).filter(([k])=>!omit.has(k))));}});continue;}if(isBatch300(c)){result.push({id:'analysis-'+(s.id||i),title:s.title||'Research finding',html:()=>{const body=batch300Body(s),omit=new Set(['id','number','title',body.key]);let citations='';if(Array.isArray(s.source_ids)&&s.source_ids.length){omit.add('source_ids');citations='<p class="sme-meta">Evidence: '+recoveredSources(c,s.source_ids)+'</p>';}return '<h2>'+esc(s.title||'Research finding')+'</h2>'+recoveredRecord(c,body.value)+citations+recoveredRecord(c,Object.fromEntries(Object.entries(s).filter(([k])=>!omit.has(k))));}});continue;}{if(isBatch280(c)){result.push({id:'analysis-'+(s.id||i),title:s.title||'Research finding',html:()=>{const body=batch280Body(s),omit=new Set(['id','number','title',body.key]);let citations='';if(Array.isArray(s.source_ids)&&s.source_ids.length){omit.add('source_ids');citations='<p class="sme-meta">Evidence: '+recoveredSources(c,s.source_ids)+'</p>';}return '<h2>'+esc(s.title||'Research finding')+'</h2>'+recoveredRecord(c,body.value)+citations+recoveredRecord(c,Object.fromEntries(Object.entries(s).filter(([k])=>!omit.has(k))));}});continue;}{if(isBatch260(c)){result.push({id:'analysis-'+(s.id||i),title:s.title||'Research finding',html:()=>{const body=batch260Body(s),omit=new Set(['id','number','title',body.key]);let citations='';if(Array.isArray(s.source_ids)&&s.source_ids.length){omit.add('source_ids');citations='<p class="sme-meta">Evidence: '+recoveredSources(c,s.source_ids)+'</p>';}return '<h2>'+esc(s.title||'Research finding')+'</h2>'+recoveredRecord(c,body.value)+citations+recoveredRecord(c,Object.fromEntries(Object.entries(s).filter(([k])=>!omit.has(k))));}});continue;}result.push({id:'analysis-'+(s.id||i),title:s.title||'Research finding',html:()=>'<h2>'+esc(s.title||'Research finding')+'</h2>'+render(s.text??s.content??s.body??(isBatch240(c)?s.content_markdown:undefined))+(s.source_ids?.length?'<p class="sme-meta">Evidence: '+(isRecovered(c)?recoveredSources(c,s.source_ids):esc(s.source_ids.join(', ')))+'</p>':'')+(isNewReview(c)?recoveredRecord(c,Object.fromEntries(Object.entries(s).filter(([k])=>!['id','number','title','text','content','body','source_ids'].includes(k)&&!(isBatch240(c)&&k==='content_markdown'&&s.text===undefined&&s.content===undefined&&s.body===undefined)))):'')});}}}
 for(const [key,title] of [['metrics','Reported metrics'],['financial_history','Financial history'],['gates','Gates'],['factor_audit','Factor audit'],['score_audit','Score calculation audit'],['valuation','Valuation and scenarios'],['confidence','Evidence confidence'],['liquidity','Liquidity and implementation'],['monitoring_plan','Monitoring plan'],['evidence','Evidence ledger']])if(c[key]&&(Array.isArray(c[key])?c[key].length:true))result.push({id:key,title,html:()=>'<h2>'+title+'</h2>'+(isRecovered(c)?(key==='factor_audit'?'<p>Scores are transcribed from the approved scorecard. Some compact confidence and evidence-ID fields were not serialized in the approval packet. Read the exact scorecard and supplemental passages for the surviving qualifications; a missing reconstructed field is not a new analytical conclusion.</p>':'')+recoveredRecord(c,c[key],key):isExtendedReview(c)?recoveredRecord(c,c[key],key):render(c[key],key))});
 if(isRecovered(c)){
  if(c.recovered_qualifiers?.length)result.push({id:'recovered-qualifications',title:'Approved supplemental passages',html:()=>'<h2>Approved supplemental passages</h2><p>Verbatim surviving text from the approved packet, in its original order and with original path labels. References to attached tables, full models or separate audit files describe the original review; those underlying files are not restored in this edition.</p>'+c.recovered_qualifiers.map(q=>'<section><h3>'+esc(q.path_label)+'</h3>'+text(q.text)+(q.source_ids?.length?'<p class="sme-meta">Sources: '+recoveredSources(c,q.source_ids)+'</p>':'')+'</section>').join('')});
  if(c.recovered_structured_extras?.length)result.push({id:'recovered-records',title:'Additional approved records',html:()=>'<h2>Additional approved records</h2>'+c.recovered_structured_extras.map(x=>'<section><h3>'+esc(x.title)+'</h3>'+recoveredRecord(c,x.record)+'</section>').join('')});
  if(c.ranking_eligibility)result.push({id:'recovered-ranking-scope',title:'Score and ranking qualifications',html:()=>'<h2>Score and ranking qualifications</h2><p>Quality-comparison eligibility and investment eligibility are separate. These are the approved scorecard outcomes, not newly recomputed model results. All full-universe comparisons remain provisional.</p>'+recoveredRecord(c,c.ranking_eligibility)});
 }
 if(isNewReview(c)){for(const [key,title] of [['financial_model','Financial model'],['valuation_model','Valuation model'],['financial_models','Detailed financial models'],['monitoring_register','Monitoring register'],['supplementary_analytical_models','Supplementary analytical models'],['historical_financial_statements','Historical financial statements'],['valuation_and_funding_model','Valuation and funding model'],['liquidity_evidence','Liquidity evidence'],['monitoring','Monitoring conditions'],['historical_financials','Historical financial statements'],['financial_calculations','Financial calculations'],['reconciliations','Financial reconciliations'],['capital_advance_adjustment_opening_basis','Capital-advance adjustment and opening basis']])if(c[key]!==undefined)result.push({id:key,title,html:()=>'<h2>'+title+'</h2>'+recoveredRecord(c,c[key],key)});}
 if(isBatch200(c)){for(const [key,title] of [["financial_inputs","Financial inputs and assumptions"],["financials","Detailed financial analysis"],["historical_extraction","Historical financial extraction"],["liquidity_model","Liquidity model"],["historical_financial_model","Historical financial model"],["annual_funding_and_valuation_model","Annual funding and valuation model"],["financial_bridges","Financial reconciliations"],["annual_models","Annual financial models"],["historical","Historical financial statements"],["model","Detailed financial and valuation model"]])if(c[key]!==undefined)result.push({id:key,title,html:()=>'<h2>'+title+'</h2>'+recoveredRecord(c,c[key],key)});}
 if(isBatch220(c)){for(const [key,title] of [["financial_inputs","Financial inputs and assumptions"],["financials","Detailed financial analysis"],["historical_extraction","Historical financial extraction"],["liquidity_model","Liquidity model"],["historical_financial_model","Historical financial model"],["annual_funding_and_valuation_model","Annual funding and valuation model"],["financial_bridges","Financial reconciliations"],["annual_models","Annual financial models"],["historical","Historical financial statements"],["model","Detailed financial and valuation model"],["financial_reconciliations","Financial reconciliations"],["latest_interim","Latest interim financials"],["prior_comparable_interim","Comparable interim financials"],["operating_metrics","Operating metrics"],["historical_calculations","Historical calculations"],["normalization","Financial normalization"],["audit_annexures","Audit annexures"],["capital_return_bridge","Capital return reconciliation"],["historical_reconciliation","Historical financial reconciliation"],["history","Historical financial records"],["growth_calculations","Growth calculations"],["annual_revenue_additions","Annual revenue additions"],["capital_diagnostics","Capital diagnostics"],["project_register","Project register"],["growth_analysis","Growth analysis"],["capital_efficiency","Capital efficiency"],["cash_quality","Cash-flow quality"],["earnings_normalization","Earnings normalization"],["market_multiples","Dated market multiples"],["current_funding","Current funding"],["financial_forensics","Financial diagnostics"]])if(c[key]!==undefined)result.push({id:key,title,html:()=>'<h2>'+title+'</h2>'+recoveredRecord(c,c[key],key)});}
 if(isBatch240(c)){for(const [key,title] of [["financial_metrics","Financial metrics"],["unit_economics","Unit economics"],["invested_capital_bridges","Invested capital reconciliations"],["cash_reclassification","Cash-flow reclassification"],["safe_financial_inputs","Safe financial inputs"],["incremental_return_analysis","Incremental return analysis"],["capital_allocation_audit","Capital allocation audit"],["audit_annexure","Audit annexure"],["funding_capitalization_audit","Funding and capitalization audit"],["full_model","Full financial and valuation model"],["liquidity_sessions","Dated liquidity sessions"],["original_financial_versions","Original financial versions"],["cash_flow_reconciliation","Cash-flow reconciliation"],["financial_ratio_diagnostics","Financial ratio diagnostics"],["original_FY2022_context","Original FY2022 context"],["financial_analysis","Financial analysis"],["financial_extracts","Financial extracts"],["calculations","Financial calculations"],["historical_cash_bridges","Historical cash-flow reconciliations"],["audit_package_review","Audit package review"],["financial_valuation_funding_model","Financial, valuation and funding model"],["historical_inputs","Historical financial inputs"],["derived_financial_metrics","Derived financial metrics"]])if(c[key]!==undefined)result.push({id:key,title,html:()=>'<h2>'+title+'</h2>'+recoveredRecord(c,c[key],key)});}
 if(isBatch260(c)){for(const [key,title] of [["models","Financial and valuation models"],["model_output","Financial model outputs"],["model_inputs","Financial model inputs"],["annual_model_rows","Annual financial model rows"],["funding_and_valuation_model","Funding and valuation model"],["funding_valuation_sensitivity","Funding, valuation and sensitivity"],["historical_and_capital_metrics","Historical and capital metrics"],["source_numbers_exact","Exact reported source values"],["source_safe_exchange_rows","Dated exchange rows"],["market_rows","Dated market rows"],["security_master_safe_extract","Dated security information"],["capital_and_growth","Capital and growth analysis"],["derived_metrics","Derived financial metrics"],["statutory_audit","Statutory audit review"],["audit_review","Audit review"],["audit_status","Audit scope and status"],["capital_bridge","Capital reconciliation"],["promises_versus_delivery","Promises versus delivery"],["execution_register","Execution evidence register"],["assumption_sensitivities","Assumption sensitivities"],["safe_market_observations","Dated market observations"],["audit_annexure_register","Audit annexure register"],["market_evidence","Market evidence"],["capital_events","Capital events"],["security_extract","Security evidence"],["funding_valuation_model","Funding and valuation model"],["market_evidence_rows","Dated market observations"],["security_master","Dated security information"],["liquidity_analysis","Liquidity evidence"],["historical_financial_rows","Historical financial rows"],["multibagger_rows","Required growth and return scenarios"],["audit_register","Audit evidence register"],["valuation_crosschecks","Valuation cross-checks"],["peer_comparison","Peer comparison"],["promises_vs_delivery","Promises versus delivery"],["ipo_proceeds_bridge","IPO proceeds reconciliation"],["share_claims_bridge","Share claims reconciliation"],["factor_uncertainty_sensitivity","Factor uncertainty and sensitivity"]])if(c[key]!==undefined)result.push({id:key,title,html:()=>'<h2>'+title+'</h2>'+recoveredRecord(c,c[key],key)});}
 if(isBatch280(c)){for(const [key,title] of [["models","Financial and valuation models"],["model_output","Financial model outputs"],["model_inputs","Financial model inputs"],["annual_model_rows","Annual financial model rows"],["funding_and_valuation_model","Funding and valuation model"],["funding_valuation_sensitivity","Funding, valuation and sensitivity"],["historical_and_capital_metrics","Historical and capital metrics"],["source_numbers_exact","Exact reported source values"],["source_safe_exchange_rows","Dated exchange rows"],["market_rows","Dated market rows"],["security_master_safe_extract","Dated security information"],["capital_and_growth","Capital and growth analysis"],["derived_metrics","Derived financial metrics"],["statutory_audit","Statutory audit review"],["audit_review","Audit review"],["audit_status","Audit scope and status"],["capital_bridge","Capital reconciliation"],["promises_versus_delivery","Promises versus delivery"],["execution_register","Execution evidence register"],["assumption_sensitivities","Assumption sensitivities"],["safe_market_observations","Dated market observations"],["audit_annexure_register","Audit annexure register"],["market_evidence","Market evidence"],["capital_events","Capital events"],["security_extract","Security evidence"],["funding_valuation_model","Funding and valuation model"],["market_evidence_rows","Dated market observations"],["security_master","Dated security information"],["liquidity_analysis","Liquidity evidence"],["historical_financial_rows","Historical financial rows"],["multibagger_rows","Required growth and return scenarios"],["audit_register","Audit evidence register"],["valuation_crosschecks","Valuation cross-checks"],["peer_comparison","Peer comparison"],["promises_vs_delivery","Promises versus delivery"],["ipo_proceeds_bridge","IPO proceeds reconciliation"],["share_claims_bridge","Share claims reconciliation"],["factor_uncertainty_sensitivity","Factor uncertainty and sensitivity"]])if(c[key]!==undefined)result.push({id:key,title,html:()=>'<h2>'+title+'</h2>'+recoveredRecord(c,c[key],key)});}
 if(isBatch300(c)){for(const [key,title] of [["models","Financial and valuation models"],["model_output","Financial model outputs"],["model_inputs","Financial model inputs"],["annual_model_rows","Annual financial model rows"],["funding_and_valuation_model","Funding and valuation model"],["funding_valuation_sensitivity","Funding, valuation and sensitivity"],["historical_and_capital_metrics","Historical and capital metrics"],["source_numbers_exact","Exact reported source values"],["source_safe_exchange_rows","Dated exchange rows"],["market_rows","Dated market rows"],["security_master_safe_extract","Dated security information"],["capital_and_growth","Capital and growth analysis"],["derived_metrics","Derived financial metrics"],["statutory_audit","Statutory audit review"],["audit_review","Audit review"],["audit_status","Audit scope and status"],["capital_bridge","Capital reconciliation"],["promises_versus_delivery","Promises versus delivery"],["execution_register","Execution evidence register"],["assumption_sensitivities","Assumption sensitivities"],["safe_market_observations","Dated market observations"],["audit_annexure_register","Audit annexure register"],["market_evidence","Market evidence"],["capital_events","Capital events"],["security_extract","Security evidence"],["funding_valuation_model","Funding and valuation model"],["market_evidence_rows","Dated market observations"],["security_master","Dated security information"],["liquidity_analysis","Liquidity evidence"],["historical_financial_rows","Historical financial rows"],["multibagger_rows","Required growth and return scenarios"],["audit_register","Audit evidence register"],["valuation_crosschecks","Valuation cross-checks"],["peer_comparison","Peer comparison"],["promises_vs_delivery","Promises versus delivery"],["ipo_proceeds_bridge","IPO proceeds reconciliation"],["share_claims_bridge","Share claims reconciliation"],["factor_uncertainty_sensitivity","Factor uncertainty and sensitivity"]])if(c[key]!==undefined)result.push({id:key,title,html:()=>'<h2>'+title+'</h2>'+recoveredRecord(c,c[key],key)});}
 if(isBatch308(c)){for(const [key,title] of [["original_display_source_fields","Original score and eligibility source fields"],["composites","Complete composite-score audit"],["factors","Complete factor evidence and rationale"],["factor_scores","Factor score inputs"],["historical_inputs","Historical financial inputs"],["historical","Historical financial statements"],["historical_metrics","Historical financial metrics"],["model_outputs","Financial and scenario model outputs"],["model","Detailed financial and funding model"],["all_sensitivity_rows","Complete sensitivity tables"],["funding_ledger_rows","Annual funding ledger"],["financial_extracts","Reported financial extracts"],["score_uncertainty_sensitivity","Score uncertainty and sensitivity"],["score_sensitivities","Score sensitivities"],["audit_annexure_review","Audit annexure review"],["cash_components","Cash and fund-value components"],["governance_data","Governance evidence"],["unresolved_data","Unresolved data and limitations"],["security_master_evidence","Security-master evidence"],["asset_recovery_diagnostic","Asset-recovery diagnostic"]])if(c[key]!==undefined)result.push({id:key,title,html:()=>'<h2>'+title+'</h2>'+recoveredRecord(c,c[key],key)});}
 if(isBatch320(c)){for(const [key,title] of [["original_display_source_fields","Original score and eligibility source fields"],["composites","Complete composite-score audit"],["factors","Complete factor evidence and rationale"],["factor_scores","Factor score inputs"],["historical_inputs","Historical financial inputs"],["historical","Historical financial statements"],["historical_metrics","Historical financial metrics"],["model_outputs","Financial and scenario model outputs"],["model","Detailed financial and funding model"],["all_sensitivity_rows","Complete sensitivity tables"],["funding_ledger_rows","Annual funding ledger"],["financial_extracts","Reported financial extracts"],["score_uncertainty_sensitivity","Score uncertainty and sensitivity"],["score_sensitivities","Score sensitivities"],["audit_annexure_review","Audit annexure review"],["cash_components","Cash and fund-value components"],["governance_data","Governance evidence"],["unresolved_data","Unresolved data and limitations"],["security_master_evidence","Security-master evidence"],["asset_recovery_diagnostic","Asset-recovery diagnostic"],["reader_score_points","Exact unrounded score inputs and explicit NS status"],["tables","Reported tables and analytical reconciliations"],["source_audit","Source review and authentication qualifications"],["corporate_action_bridge","Corporate action reconciliation"],["project_drivers","Project drivers and assumptions"],["tax_rate_basis","Tax-rate basis and qualifications"],["score_uncertainty","Score uncertainty and bounds"],["restriction_evidence","Trading-restriction evidence"],["market_calculations","Dated market calculations"]])if(c[key]!==undefined)result.push({id:key,title,html:()=>'<h2>'+title+'</h2>'+recoveredRecord(c,c[key],key)});}
 if(isExtendedReview(c)){const extra=supplementalReviewFields(c);if(isBatch320(c)){for(const key of ["original_display_source_fields","composites","factors","factor_scores","historical_inputs","historical","historical_metrics","model_outputs","model","all_sensitivity_rows","funding_ledger_rows","financial_extracts","score_uncertainty_sensitivity","score_sensitivities","audit_annexure_review","cash_components","governance_data","unresolved_data","security_master_evidence","asset_recovery_diagnostic","reader_score_points","tables","source_audit","corporate_action_bridge","project_drivers","tax_rate_basis","score_uncertainty","restriction_evidence","market_calculations"])delete extra[key];}if(isBatch308(c)){for(const key of ["original_display_source_fields","composites","factors","factor_scores","historical_inputs","historical","historical_metrics","model_outputs","model","all_sensitivity_rows","funding_ledger_rows","financial_extracts","score_uncertainty_sensitivity","score_sensitivities","audit_annexure_review","cash_components","governance_data","unresolved_data","security_master_evidence","asset_recovery_diagnostic"])delete extra[key];}if(isBatch300(c)){for(const key of ["models","model_output","model_inputs","annual_model_rows","funding_and_valuation_model","funding_valuation_sensitivity","historical_and_capital_metrics","source_numbers_exact","source_safe_exchange_rows","market_rows","security_master_safe_extract","capital_and_growth","derived_metrics","statutory_audit","audit_review","audit_status","capital_bridge","promises_versus_delivery","execution_register","assumption_sensitivities","safe_market_observations","audit_annexure_register","market_evidence","capital_events","security_extract","funding_valuation_model","market_evidence_rows","security_master","liquidity_analysis","historical_financial_rows","multibagger_rows","audit_register","valuation_crosschecks","peer_comparison","promises_vs_delivery","ipo_proceeds_bridge","share_claims_bridge","factor_uncertainty_sensitivity"])delete extra[key];}if(isBatch280(c)){for(const key of ["models","model_output","model_inputs","annual_model_rows","funding_and_valuation_model","funding_valuation_sensitivity","historical_and_capital_metrics","source_numbers_exact","source_safe_exchange_rows","market_rows","security_master_safe_extract","capital_and_growth","derived_metrics","statutory_audit","audit_review","audit_status","capital_bridge","promises_versus_delivery","execution_register","assumption_sensitivities","safe_market_observations","audit_annexure_register","market_evidence","capital_events","security_extract","funding_valuation_model","market_evidence_rows","security_master","liquidity_analysis","historical_financial_rows","multibagger_rows","audit_register","valuation_crosschecks","peer_comparison","promises_vs_delivery","ipo_proceeds_bridge","share_claims_bridge","factor_uncertainty_sensitivity"])delete extra[key];}if(isBatch260(c)){for(const key of ["models","model_output","model_inputs","annual_model_rows","funding_and_valuation_model","funding_valuation_sensitivity","historical_and_capital_metrics","source_numbers_exact","source_safe_exchange_rows","market_rows","security_master_safe_extract","capital_and_growth","derived_metrics","statutory_audit","audit_review","audit_status","capital_bridge","promises_versus_delivery","execution_register","assumption_sensitivities","safe_market_observations","audit_annexure_register","market_evidence","capital_events","security_extract","funding_valuation_model","market_evidence_rows","security_master","liquidity_analysis","historical_financial_rows","multibagger_rows","audit_register","valuation_crosschecks","peer_comparison","promises_vs_delivery","ipo_proceeds_bridge","share_claims_bridge","factor_uncertainty_sensitivity"])delete extra[key];}if(isBatch240(c)){for(const key of ["financial_metrics","unit_economics","invested_capital_bridges","cash_reclassification","safe_financial_inputs","incremental_return_analysis","capital_allocation_audit","audit_annexure","funding_capitalization_audit","full_model","liquidity_sessions","original_financial_versions","cash_flow_reconciliation","financial_ratio_diagnostics","original_FY2022_context","financial_analysis","financial_extracts","calculations","historical_cash_bridges","audit_package_review","financial_valuation_funding_model","historical_inputs","derived_financial_metrics"])delete extra[key];if(c.as_of!==null&&typeof c.as_of==='object')extra.as_of=c.as_of;}if(isBatch220(c)){for(const key of ["financial_inputs","financials","historical_extraction","liquidity_model","historical_financial_model","annual_funding_and_valuation_model","financial_bridges","annual_models","historical","model","financial_reconciliations","latest_interim","prior_comparable_interim","operating_metrics","historical_calculations","normalization","audit_annexures","capital_return_bridge","historical_reconciliation","history","growth_calculations","annual_revenue_additions","capital_diagnostics","project_register","growth_analysis","capital_efficiency","cash_quality","earnings_normalization","market_multiples","current_funding","financial_forensics"])delete extra[key];if(Object.prototype.hasOwnProperty.call(c,'existing_research'))extra.existing_research=c.existing_research;}if(isBatch200(c)){for(const key of ["financial_inputs","financials","historical_extraction","liquidity_model","historical_financial_model","annual_funding_and_valuation_model","financial_bridges","annual_models","historical","model"])delete extra[key];if(Object.prototype.hasOwnProperty.call(c,'existing_research'))extra.existing_research=c.existing_research;}if(isNewReview(c)){for(const key of ['financial_model','valuation_model','financial_models','monitoring_register','supplementary_analytical_models','historical_financial_statements','valuation_and_funding_model','liquidity_evidence','monitoring','historical_financials','financial_calculations','reconciliations','capital_advance_adjustment_opening_basis'])delete extra[key];extra.research_status=c.research_status;extra.scores=c.scores;}if(Object.keys(extra).length)result.push({id:'review-supplements',title:'Additional review qualifications and audit fields',html:()=>'<h2>Additional review qualifications and audit fields</h2><p>Supplemental fields are retained from the source review. Any workflow-status labels describe that saved source version, not the current publication status of this page.</p>'+recoveredRecord(c,extra)});}
 result.push({id:'limitations',title:'Limits and next steps',html:()=>'<h2>Limitations</h2>'+(isNewReview(c)&&!Object.prototype.hasOwnProperty.call(c,'limitations')?'<p>No separate limitations list was supplied. Read the narrative and model qualifications for the stated evidence limits.</p>':reviewValue(c,c.limitations||[]))+'<h3>Next steps</h3>'+(isRecovered(c)&&!c.next_steps?'<p>See the approved analysis and supplemental passages for surviving next steps and monitoring conditions. No missing action list has been reconstructed.</p>':(isNewReview(c)&&!Object.prototype.hasOwnProperty.call(c,'next_steps')?'<p>No separate next-steps list was supplied. Read the monitoring register and narrative for the stated follow-up conditions.</p>':reviewValue(c,c.next_steps||[])))});
 result.push({id:'sources',title:'Sources',html:()=>isBatch320(c)&&!Array.isArray(c.sources)?'<h2>Sources and source qualifications</h2>'+recoveredRecord(c,c.sources):'<h2>Sources</h2><p>Read status distinguishes reviewed evidence from inaccessible or discovery-only material. A link alone does not verify a claim.</p><ol>'+ (c.sources||[]).map(s=>isNewReview(c)?'<li>'+recoveredRecord(c,s)+'</li>':'<li><strong>'+esc(s.id)+' · '+link(s.url,s.title||s.url)+'</strong><p>'+esc([s.kind,s.document_date&&'Document '+s.document_date,s.accessed&&'Accessed '+s.accessed,s.read_status].filter(Boolean).join(' · '))+'</p>'+(isRecovered(c)?recoveredRecord(c,s.locator||''):render(s.locator||''))+recoveredSourceExtras(c,s)+'</li>').join('')+'</ol>'});return result;}
 const groupOf=s=>s.id==='overview'?'Overview':s.id==='sources'?'Sources':s.id.startsWith('analysis-')?'Analysis':'Data & models';
 function navCompanies(){const list=filtered();return (list.some(c=>c.id===current?.id)?list:data).slice().sort((a,b)=>a.name.localeCompare(b.name));}

 function standaloneDossier(c){return `<section id="research" class="analysis-view"><div class="reader-topbar"><a href="${address(null,'')}" data-back>← Company index</a><div class="reader-actions"><button data-copy>Copy link</button></div></div><span id="linkStatus" role="status"></span><div id="copyFallback" hidden><input id="shareAddress" readonly></div><h1>${esc(c.name)}</h1><p>Full 15-section research report · Research ${esc(c.as_of)} · ${['BQS','GQS','IAS'].map(k=>k+' '+esc(c.score_display[k])).join(' · ')}</p><p><a href="${esc(c.standalone_report)}" target="_blank" rel="noopener">Open full report in a new tab</a> · <a href="${esc(c.source_package)}" ${c.source_package.endsWith('.zip')?'download':''}>Download complete research, models, inputs and retained vintages (ZIP)</a></p><p class="subtle">Scores and evidence limitations are preserved from the accepted research. A completed report does not imply investment eligibility. The ZIP retains every source-safe analytical member; its projection ledger documents local-path-only changes and original hashes.</p><div class="section-selector"><label for="sectionSelect">Research section</label><select id="sectionSelect" disabled><option>Loading sections…</option></select><span id="standaloneSectionStatus" role="status">Opening report…</span></div><iframe id="standaloneFrame" title="${esc(c.name)} — paginated research report" src="${esc(c.standalone_report)}" style="visibility:hidden;width:100%;height:80vh;min-height:600px;border:1px solid #ddd;background:white"></iframe><div class="section-pagination"><button id="standalonePrevious" data-section="" disabled>← Previous section</button><span id="standalonePageCount"></span><button id="standaloneNext" data-section="" disabled>Next section →</button></div></section>`;}
 function mountStandalone(c,version){
  const frame=document.getElementById('standaloneFrame');if(!frame)return;let pagedDocument=null;
  const live=()=>version===requestVersion&&current?.id===c.id&&document.getElementById('standaloneFrame')===frame;
  function mount(){
   if(!live())return;const doc=frame.contentDocument;
   if(!doc?.body||doc.URL==='about:blank')return;
   if(doc===pagedDocument)return;frame.style.visibility='hidden';
   const headings=Array.from(doc.body.querySelectorAll('h2'));
   if(headings.length!==15||headings.some(h=>h.parentElement!==doc.body)){document.getElementById('standaloneSectionStatus').textContent='Pagination unavailable. Open the full report above; no report text has been removed.';return;}
   const originalNodes=Array.from(doc.body.childNodes),pages=[];let page=doc.createElement('section');page.className='wallstrat-paged-section';pages.push(page);let headingIndex=0;
   for(const n of originalNodes){if(n.nodeType===1&&n.tagName==='H2'){if(headingIndex++>0){page=doc.createElement('section');page.className='wallstrat-paged-section';pages.push(page);}}page.appendChild(n);}
   for(const p of pages)doc.body.appendChild(p);
   const style=doc.createElement('style');style.textContent='.wallstrat-paged-section[hidden]{display:none!important}';doc.head.appendChild(style);pagedDocument=doc;
   const select=document.getElementById('sectionSelect');select.innerHTML=headings.map((h,i)=>'<option value="analysis-'+(i+1)+'">'+esc(h.textContent)+'</option>').join('');select.disabled=false;
   function show(index,target){if(!live())return;index=Math.max(0,Math.min(14,index));active='analysis-'+(index+1);pages.forEach((p,i)=>{p.hidden=i!==index;});select.value=active;const previous=document.getElementById('standalonePrevious'),next=document.getElementById('standaloneNext');previous.disabled=index===0;previous.dataset.section='analysis-'+index;next.disabled=index===14;next.dataset.section='analysis-'+(index+2);document.getElementById('standalonePageCount').textContent='Section '+(index+1)+' of 15';document.getElementById('standaloneSectionStatus').textContent=headings[index].textContent;frame.contentWindow.scrollTo(0,0);if(target)target.scrollIntoView({block:'start'});}
   const match=/^analysis-(\d+)$/.exec(active);show(match?Number(match[1])-1:0);frame.style.visibility='visible';
   doc.addEventListener('click',e=>{const a=e.target.closest?.('a[href^="#"]');if(!a||e.ctrlKey||e.metaKey||e.shiftKey||e.altKey||!live())return;let id;try{id=decodeURIComponent(a.getAttribute('href').slice(1));}catch{return;}const target=doc.getElementById(id)||Array.from(doc.getElementsByName(id))[0];if(!target)return;const index=pages.findIndex(p=>p.contains(target));if(index<0)return;e.preventDefault();show(index,target);write();});
  }
  frame.addEventListener('load',mount);if(frame.contentDocument?.readyState==='complete')mount();
 }
 function dossier(c){
  if(c.standalone_report)return standaloneDossier(c);
  const ss=sections(c),s=ss.find(x=>x.id===active)||ss[0];active=s.id;const i=ss.indexOf(s),groups=[...new Set(ss.map(groupOf))],list=navCompanies(),ci=list.findIndex(x=>x.id===c.id);
  const choices=groups.map(g=>'<optgroup label="'+esc(g)+'">'+ss.filter(x=>groupOf(x)===g).map(x=>option(x.id,x.title,s.id)).join('')+'</optgroup>').join('');
  const adjacent=(delta)=>list[ci+delta];
  return `<section id="research" class="analysis-view" aria-label="Company analysis"><div class="reader-topbar"><a href="${address(null,'')}" data-back class="text-link">← Company index</a><div class="reader-actions"><button data-copy>Copy link</button><button data-print>Print section</button></div></div><span id="linkStatus" role="status"></span><div id="copyFallback" hidden><label for="shareAddress">Copy this address</label><input id="shareAddress" readonly></div><div class="reader-heading"><p class="eyebrow">${esc(isBatch300(c)&&c.symbol==null&&c.bse_code!=null?'BSE scrip '+c.bse_code:c.symbol||c.isin)} / ${esc(c.sector||'Unknown')}</p><h1>${esc(c.name)}</h1><p class="subtle">Research ${esc(researchDate(c)||'pending')} · ${esc(c.exchange||'listing verification pending')}${c.quote?.date?' · Quote '+esc(c.quote.date):''}</p></div>
  ${recoveredNotice(c)}<div class="detail-nav"><button data-company="${esc(adjacent(-1)?.id||'')}" aria-label="Previous company" ${!adjacent(-1)?'disabled':''}>←</button><label class="sr-only" for="companySelect">Choose a company</label><select id="companySelect">${list.map(x=>option(x.id,x.name+' · '+(x.symbol||x.isin),c.id)).join('')}</select><span class="subtle">${ci+1} / ${list.length}</span><button data-company="${esc(adjacent(1)?.id||'')}" aria-label="Next company" ${!adjacent(1)?'disabled':''}>→</button></div>
  <div class="reader-layout"><aside id="dossierContents" aria-label="Company analysis contents"><details${contentsOpen?' open':''}><summary>Company contents</summary><nav class="toc-body" aria-label="Research sections"><p>${esc(c.symbol||c.isin)}<br><span class="subtle">${ss.length} sections</span></p>${groups.map(g=>'<h4>'+esc(g)+'</h4><ul>'+ss.filter(x=>groupOf(x)===g).map(x=>'<li><a href="'+address(c.id,x.id)+'" data-section="'+esc(x.id)+'"'+(s.id===x.id?' aria-current="location"':'')+'>'+esc(x.title)+'</a></li>').join('')+'</ul>').join('')}</nav></details></aside>
  <div class="reader-main"><div class="section-tabs" role="group" aria-label="Analysis categories">${groups.map(g=>'<button data-group="'+esc(g)+'" aria-pressed="'+(groupOf(s)===g)+'">'+esc(g)+'</button>').join('')}</div><div class="section-selector"><label class="sr-only" for="sectionSelect">Research section</label><select id="sectionSelect">${choices}</select><span class="subtle">${i+1} / ${ss.length}</span></div><article class="company sme-section" tabindex="-1"><div class="section-number">${esc(groupOf(s))} / ${esc(c.symbol||c.isin)}</div>${s.html()}<div class="company-footer">${esc(c.name)} · Research ${esc(researchDate(c)||'pending')}</div></article><div class="section-pagination"><button data-section="${esc(ss[i-1]?.id||'')}" ${i===0?'disabled':''}>← Previous section</button><span class="subtle">Section ${i+1} of ${ss.length}</span><button data-section="${esc(ss[i+1]?.id||'')}" ${i===ss.length-1?'disabled':''}>Next section →</button></div></div></div><div class="detail-bottom"><button data-company="${esc(adjacent(-1)?.id||'')}" ${!adjacent(-1)?'disabled':''}>← Previous company</button><span class="subtle">Company ${ci+1} of ${list.length}</span><button data-company="${esc(adjacent(1)?.id||'')}" ${!adjacent(1)?'disabled':''}>Next company →</button></div></section>`;
 }
 function decodeDossierTransport(p,entry){
  if(!p||typeof p!=='object'||Array.isArray(p))throw Error('Invalid company research.');
  if(!Object.prototype.hasOwnProperty.call(p,'codec'))return p;
  if(p.codec!=='JSON-syntax-dictionary-v4')throw Error('Unknown research transport format.');
  if(entry.id!=='INE1RQS01010'||p.original_sha256!=='17f6981afce30c1cce9d48450da7d40c6b280b45584072192a3d3f5b123c48c4'||!Array.isArray(p.atoms)||!Array.isArray(p.schemas)||!Array.isArray(p.nodes))throw Error('Invalid research transport package.');
  function atom(i){if(!Number.isInteger(i)||i<0||i>=p.atoms.length||typeof p.atoms[i]!=='string')throw Error('Invalid research atom.');return p.atoms[i];}
  let calls=0;
  function decode(ref,parent,depth=0){
   if(++calls>10000000||depth>512)throw Error('Research transport exceeds safety limits.');
   if(!Number.isInteger(ref))throw Error('Invalid research reference.');
   if(ref>=0){const value=atom(ref);if(value.length>25000000)throw Error('Research atom exceeds safety limit.');return value;}
   const i=-1-ref;if(i<0||i>=p.nodes.length||i>=parent)throw Error('Invalid or cyclic research node.');
   const n=p.nodes[i];if(!Array.isArray(n)||!n.length||!Number.isInteger(n[0]))throw Error('Invalid research node.');
   if(n[0]===-1){const values=[];let length=2;for(let j=1;j<n.length;j++){const v=decode(n[j],i,depth+1);length+=v.length+(j>1?1:0);if(length>25000000)throw Error('Research array exceeds safety limit.');values.push(v);}return '['+values.join(',')+']';}
   const keys=p.schemas[n[0]];if(!Array.isArray(keys)||keys.length!==n.length-1)throw Error('Invalid research schema.');
   const fields=[];let length=2;for(let j=0;j<keys.length;j++){const field=atom(keys[j])+':'+decode(n[j+1],i,depth+1);length+=field.length+(j>0?1:0);if(length>25000000)throw Error('Research object exceeds safety limit.');fields.push(field);}return '{'+fields.join(',')+'}';
  }
  const restored=decode(p.root,p.nodes.length);if(restored.length>25000000)throw Error('Research output exceeds safety limit.');return JSON.parse(restored);
 }
 // New unpublished12 only. Existing308 transport logic is retained separately.
 async function checkedTransportJSON(response,binding){
  if(!response.ok)throw Error('Research component could not load ('+response.status+').');
  if(!binding||!Number.isSafeInteger(binding.bytes)||binding.bytes<1||binding.bytes>12000000||!/^[a-f0-9]{64}$/.test(binding.sha256))throw Error('Invalid research byte binding.');
  const declared=response.headers?.get?.('content-length'),encoding=(response.headers?.get?.('content-encoding')||'identity').toLowerCase();
  if(declared!==null&&declared!==undefined&&(!/^\d+$/.test(declared)||!Number.isSafeInteger(Number(declared))||Number(declared)>12000000||(encoding==='identity'&&Number(declared)!==binding.bytes))){await response.body?.cancel?.();throw Error('Research component declared-size mismatch.');}
  const stream=response.body?.getReader?.();if(!stream)throw Error('This browser cannot safely read the research package.');
  const chunks=[];let received=0;
  try{for(;;){const next=await stream.read();if(next.done)break;const value=next.value;if(!ArrayBuffer.isView(value)||!Number.isSafeInteger(value.byteLength)||received+value.byteLength>binding.bytes||received+value.byteLength>12000000){await stream.cancel();throw Error('Research component exceeds its pinned byte size.');}chunks.push(new Uint8Array(value.buffer,value.byteOffset,value.byteLength));received+=value.byteLength;}}catch(error){try{await stream.cancel();}catch{}throw error;}finally{stream.releaseLock();}
  if(received!==binding.bytes)throw Error('Research component byte size mismatch.');
  const bytes=new Uint8Array(received);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
  if(!globalThis.crypto?.subtle)throw Error('This browser cannot verify the research package. Use a current browser on the secure website.');
  const digest=await globalThis.crypto.subtle.digest('SHA-256',bytes),actual=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
  if(actual!==binding.sha256)throw Error('Research component integrity check failed.');
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }
 async function decodeNewBatchTransport(p,entry){
  const a=p?.wallstrat_transport,b=entry.lossless_transport;
  if(!p||!a||!b||['scope','id','isin','source_projection_sha256','payload_sha256','payload_bytes','atoms','schemas','nodes','root'].some(k=>a[k]!==b[k])||a.scope!=='completed-unpublished-309-320'||a.id!==entry.id||a.isin!==entry.isin)throw Error('Invalid qualified research transport.');
  const boundedPositive=(value,cap)=>Number.isSafeInteger(value)&&value>0&&value<=cap;
  if(!boundedPositive(a.payload_bytes,350000000)||!boundedPositive(a.atoms,2000000)||!boundedPositive(a.schemas,100000)||!boundedPositive(a.nodes,2000000)||!Number.isSafeInteger(a.root)||a.root>=0||a.root < -a.nodes)throw Error('Invalid research dictionary bounds.');
  if(p.codec==='JSON-syntax-dictionary-v4-chunks'){
   if(!Array.isArray(p.parts)||!p.parts.length||p.parts.length>1000||p.root!==a.root)throw Error('Invalid research component manifest.');
   const out={codec:'JSON-syntax-dictionary-v4',root:p.root,atoms:[],schemas:[],nodes:[]},fields=['atoms','schemas','nodes'],ordinals={atoms:0,schemas:0,nodes:0};let lastField=-1;
   for(const part of p.parts){
    const field=fields.indexOf(part.field);if(field<lastField||field<0||!boundedPositive(part.ordinal,1000)||part.ordinal!==ordinals[part.field]+1||!Number.isSafeInteger(part.start)||part.start<0||part.start!==out[part.field].length||!boundedPositive(part.count,a[part.field])||part.start+part.count>a[part.field]||part.path!=='sme/'+entry.id+'/'+part.field+'-'+String(part.ordinal).padStart(3,'0')+'.json'||!boundedPositive(part.bytes,8000000))throw Error('Invalid research component address or order.');
    const values=await checkedTransportJSON(await fetchResearchGzip(part.path),part);
    if(!Array.isArray(values)||values.length!==part.count||out[part.field].length+values.length>a[part.field])throw Error('Research component row-count mismatch.');
    for(const value of values)out[part.field].push(value);ordinals[part.field]++;lastField=field;
   }
   p=out;
  }
  if(p.codec!=='JSON-syntax-dictionary-v4'||p.root!==a.root||!Array.isArray(p.atoms)||!Array.isArray(p.schemas)||!Array.isArray(p.nodes)||p.atoms.length!==a.atoms||p.schemas.length!==a.schemas||p.nodes.length!==a.nodes)throw Error('Incomplete research dictionary.');
  return window.WALLSTRAT_DECODE(p);
 }
 // The next20 use independent byte-pinned dictionaries. The prior320 loaders stay unchanged.
 let active340Load=null,completed340Id=null,load340Generation=0;
 function cancel340Load(){if(active340Load){active340Load.controller.abort();active340Load=null;}if(completed340Id){loaded.delete(completed340Id);completed340Id=null;}load340Generation++;}
 function releasePrior320Cache(){for(const id of loaded.keys())if(isBatch320({id}))loaded.delete(id);}
 const positive340=(n,cap)=>Number.isSafeInteger(n)&&n>0&&n<=cap;
 const hash340=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
 function assert340Active(job){if(job.controller.signal.aborted||active340Load!==job||job.generation!==load340Generation)throw Error('Research loading was cancelled. Select the company again.');}
 async function bytes340(response,binding,job){
  assert340Active(job);
  if(!response.ok)throw Error('Research component could not load ('+response.status+').');
  if(!binding||!positive340(binding.bytes,4000000)||!hash340(binding.sha256))throw Error('Invalid research component binding.');
  const declared=response.headers?.get?.('content-length'),encoding=(response.headers?.get?.('content-encoding')||'identity').toLowerCase();
  if(!['identity','gzip','br','deflate'].includes(encoding))throw Error('Unsupported research content encoding.');
  if(declared!==null&&declared!==undefined&&(!/^\d+$/.test(declared)||!Number.isSafeInteger(Number(declared))||Number(declared)>4000000||(encoding==='identity'&&Number(declared)!==binding.bytes))){await response.body?.cancel?.();throw Error('Research component declared-size mismatch.');}
  const stream=response.body?.getReader?.();if(!stream)throw Error('This browser cannot safely read the research package.');
  const out=new Uint8Array(binding.bytes);let received=0;
  try{for(;;){assert340Active(job);const next=await stream.read();assert340Active(job);if(next.done)break;const v=next.value;if(!ArrayBuffer.isView(v)||!Number.isSafeInteger(v.byteLength)||v.byteLength>binding.bytes-received){await stream.cancel();throw Error('Research component exceeds its pinned byte size.');}out.set(new Uint8Array(v.buffer,v.byteOffset,v.byteLength),received);received+=v.byteLength;}}
  catch(error){try{await stream.cancel();}catch{}throw error;}finally{stream.releaseLock();}
  if(received!==binding.bytes)throw Error('Research component byte size mismatch.');
  if(!globalThis.crypto?.subtle)throw Error('This browser cannot verify the research package. Use a current browser on the secure website.');
  const digest=await globalThis.crypto.subtle.digest('SHA-256',out);assert340Active(job);
  const actual=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
  if(actual!==binding.sha256)throw Error('Research component integrity check failed.');
  new TextDecoder('utf-8',{fatal:true}).decode(out);return out;
 }
 async function decode340Transport(manifest,entry,job){
  const a=manifest?.wallstrat_transport,b=entry.lossless_transport;
  const fields=['scope','id','isin','source_canonical_sha256','projection_ledger_sha256','dictionary_sha256','dictionary_bytes','payload_sha256','payload_bytes','atoms','schemas','nodes','root'];
  if(!a||!b||fields.some(k=>a[k]!==b[k])||manifest.codec!=='JSON-syntax-dictionary-v4-utf8-fragments'||a.scope!=='completed-unpublished-321-340'||a.id!==entry.id||a.isin!==entry.isin)throw Error('Invalid qualified research transport.');
  if(!['source_canonical_sha256','projection_ledger_sha256','dictionary_sha256','payload_sha256'].every(k=>hash340(a[k]))||!positive340(a.dictionary_bytes,100000000)||!positive340(a.payload_bytes,400000000)||!positive340(a.atoms,1000000)||!positive340(a.schemas,1000)||!positive340(a.nodes,1000000)||!Number.isSafeInteger(a.root)||a.root>=0||a.root < -a.nodes||!Array.isArray(manifest.parts)||!positive340(manifest.parts.length,64))throw Error('Invalid research dictionary bounds.');
  let nextOffset=0;
  for(let i=0;i<manifest.parts.length;i++){const p=manifest.parts[i];if(!p||!positive340(p.ordinal,64)||p.ordinal!==i+1||!Number.isSafeInteger(p.offset)||p.offset<0||p.offset!==nextOffset||!positive340(p.bytes,4000000)||p.bytes>a.dictionary_bytes-nextOffset||!hash340(p.sha256)||p.path!=='sme/'+entry.id+'/dictionary-'+String(i+1).padStart(3,'0')+'.jsonpart')throw Error('Invalid research fragment address or order.');nextOffset+=p.bytes;}
  if(nextOffset!==a.dictionary_bytes)throw Error('Incomplete research fragment manifest.');
  const all=new Uint8Array(a.dictionary_bytes);
  for(const p of manifest.parts){assert340Active(job);const response=await fetchResearchGzip(p.path,{signal:job.controller.signal});const bytes=await bytes340(response,p,job);assert340Active(job);all.set(bytes,p.offset);}
  const digest=await globalThis.crypto.subtle.digest('SHA-256',all);assert340Active(job);const actual=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
  if(actual!==a.dictionary_sha256)throw Error('Complete research dictionary integrity check failed.');
  const p=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(all));assert340Active(job);
  if(p.codec!=='JSON-syntax-dictionary-v4'||p.root!==a.root||!Array.isArray(p.atoms)||!Array.isArray(p.schemas)||!Array.isArray(p.nodes)||p.atoms.length!==a.atoms||p.schemas.length!==a.schemas||p.nodes.length!==a.nodes)throw Error('Research dictionary count mismatch.');
  return window.WALLSTRAT_DECODE_340(p);
 }
 function ensure340Dossier(entry){
  if(entry.dossier!=='sme/'+entry.id+'.json'||!/^[A-Z0-9]{12}$/.test(entry.id)||!isBatch340(entry))return Promise.reject(Error('Invalid research address.'));
  if(loaded.has(entry.id)&&loading.size===0){if(active340Load&&active340Load.id!==entry.id)cancel340Load();return Promise.resolve(loaded.get(entry.id));}
  if(active340Load?.id===entry.id)return active340Load.promise;
  cancel340Load();releasePrior320Cache();
  const job={id:entry.id,controller:new AbortController(),generation:load340Generation,promise:null};active340Load=job;
  job.promise=(async()=>{
   // Legacy loaders cannot be aborted without changing their proven behavior. Let them settle before allocating a new dictionary.
   while(loading.size){await Promise.allSettled(Array.from(loading.values()));assert340Active(job);}
   releasePrior320Cache();assert340Active(job);
   const response=await fetchResearchGzip(entry.dossier,{signal:job.controller.signal});const raw=await bytes340(response,entry.transport_file,job);const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));const c=await decode340Transport(manifest,entry,job);assert340Active(job);if(c.id!==entry.id||c.isin!==entry.isin)throw Error('Company identity mismatch.');loaded.set(c.id,c);completed340Id=c.id;return c;})().finally(()=>{if(active340Load===job)active340Load=null;});
  return job.promise;
 }
 async function ensureDossier(entry){
  if(entry.standalone_report){loaded.set(entry.id,entry);return entry;}
  if(isBatch359(entry)){const ownerVersion=requestVersion,ownerId=current?.id;const own=()=>{if(ownerId!==entry.id||requestVersion!==ownerVersion||current?.id!==entry.id)throw Error('Research route superseded.');};own();while(loading.size){await Promise.allSettled(Array.from(loading.values()));own();}own();releasePrior320Cache();own();const c=await new359.load(entry);own();loaded.clear();loaded.set(c.id,c);return c;}
  if(isBatch340(entry))return ensure340Dossier(entry);
  if(loaded.has(entry.id))return loaded.get(entry.id);
  if(loading.has(entry.id))return loading.get(entry.id);
  if(entry.dossier!=='sme/'+entry.id+'.json'||!/^[A-Z0-9]{12}$/.test(entry.id))throw Error('Invalid dossier address.');
  const promise=fetchResearchGzip(entry.dossier).then(r=>{if(isBatch320(entry))return checkedTransportJSON(r,entry.transport_file);if(!r.ok)throw Error('Company research could not load ('+r.status+').');return r.json();}).then(async c=>{if(isBatch320(entry)){c=await decodeNewBatchTransport(c,entry);loaded.clear();}else c=decodeDossierTransport(c,entry);if(c.id!==entry.id||c.isin!==entry.isin)throw Error('Company identity mismatch.');loaded.set(c.id,c);return c;}).finally(()=>loading.delete(entry.id));
  loading.set(entry.id,promise);return promise;
 }
 function pending(c){return {...c,summary:'Company-specific research has not yet been published. No investment conclusion or score has been issued.',identity_note:'Name, ticker and ISIN originate from the submitted universe. Current listing classification still requires verification.',sections:[],sources:[],limitations:['Research pending.'],next_steps:[]};}
 function draw(){
  new359.cancelOther(current?.id);new359.unmount();if(!isBatch359(current))new359.cancel();
  if(!isBatch340(current))cancel340Load();
  modelChunks.clear();modelChunkSerial=0;
  const version=++requestVersion;document.getElementById('indexIntro').hidden=!!current;document.getElementById('methodology').hidden=!!current;document.title=current?current.name+' | Wallstrat SME Research':'SME Research | Wallstrat';
  if(!current){root.innerHTML=index();return;}
  if(current.research_status==='pending'){root.innerHTML=dossier(pending(current));return;}
  const cached=loaded.get(current.id);if(cached){current=cached;root.innerHTML=dossier(cached);if(isBatch359(cached))new359.mount(root.querySelector('[data-research359]'),cached);if(cached.standalone_report)mountStandalone(cached,version);return;}
  const entry=byId.get(current.id);root.innerHTML='<section id="research"><a href="'+address(null,'')+'" data-back>← Back to SME index</a><h2>'+esc(current.name)+'</h2><p role="status">Opening company research…</p></section>';
  ensureDossier(entry).then(c=>{if(version!==requestVersion||current?.id!==c.id)return;current=c;draw();}).catch(e=>{if(version!==requestVersion)return;root.innerHTML='<section id="research"><a href="'+address(null,'')+'" data-back>← Back to SME index</a><p role="alert">'+esc(e.message)+'</p><button data-retry>Try again</button></section>';});
 }
 function rememberPanels(){const filter=document.getElementById('filterPanel'),contents=document.querySelector?.('#dossierContents details');if(filter)filterOpen=filter.open;if(contents)contentsOpen=contents.open;}
 function openCompany(id){if(!byId.has(id))return;rememberPanels();current=byId.get(id);active='';write();draw();document.getElementById('research').scrollIntoView({block:'start'});}
 root.addEventListener('click',async e=>{const el=e.target.closest('[data-model-expand],[data-model-collapse],[data-company],[data-back],[data-section],[data-group],[data-rank],[data-page],[data-retry],[data-copy],[data-print],#resetFilters');if(!el||e.ctrlKey||e.metaKey||e.shiftKey||e.altKey||e.button>0)return;e.preventDefault();if(el.disabled)return;rememberPanels();
  if(el.hasAttribute('data-model-expand')){el.closest('[data-model-region]').innerHTML=modelChunkContent(el.dataset.modelExpand);return;}
  if(el.hasAttribute('data-model-collapse')){el.closest('[data-model-region]').innerHTML=modelCollapseContent(el.dataset.modelCollapse);return;}
  if(el.hasAttribute('data-copy')){try{await navigator.clipboard.writeText(location.href);document.getElementById('linkStatus').textContent='Link copied to this company and section.';}catch{document.getElementById('copyFallback').hidden=false;const input=document.getElementById('shareAddress');input.value=location.href;input.focus();input.select();}return;}
  if(el.hasAttribute('data-print')){window.print();return;}
  if(el.hasAttribute('data-retry')){draw();return;}
  if(el.hasAttribute('data-company')){openCompany(el.dataset.company);return;}
  if(el.hasAttribute('data-back')){current=null;active='';}
  else if(el.hasAttribute('data-section'))active=el.dataset.section;
  else if(el.hasAttribute('data-group'))active=sections(current).find(s=>groupOf(s)===el.dataset.group)?.id||'overview';
  else if(el.hasAttribute('data-rank')){state.sort=el.dataset.rank;state.order=state.sort==='name'?'name-asc':'desc';state.page=1;}
  else if(el.hasAttribute('data-page'))state.page=Number(el.dataset.page);
  else {state={...defaults};filterOpen=false;}
  write();draw();document.getElementById('research').scrollIntoView({block:'start'});
 });
 root.addEventListener('input',e=>{if(e.target.id!=='smeSearch')return;rememberPanels();const pos=e.target.selectionStart;state.q=e.target.value;state.page=1;write(true);draw();const input=document.getElementById('smeSearch');input.focus();try{input.setSelectionRange(pos,pos);}catch{}});
 root.addEventListener('change',e=>{rememberPanels();if(e.target.id==='companySelect'){openCompany(e.target.value);return;}if(e.target.id==='sectionSelect'){active=e.target.value;write();draw();return;}const keys={smeStatus:'status',smeSector:'sector',smeSize:'size',smeSort:'sort',sortRows:'order',minBQS:'minBQS',minGQS:'minGQS',minIAS:'minIAS'},key=keys[e.target.id];if(!key)return;state[key]=key==='size'?Number(e.target.value):e.target.value;if(key==='status'&&state.status==='pending'){state.sort='name';state.order='name-asc';}if(key==='order'&&state.order.startsWith('name-'))state.sort='name';state.page=1;write();draw();});
 document.getElementById('quickJump').addEventListener('submit',e=>{e.preventDefault();const input=document.getElementById('quickCompany'),q=input.value.trim().toLowerCase(),exact=data.filter(c=>[c.name,c.symbol,c.isin].some(v=>v?.toLowerCase()===q)),matches=exact.length?exact:data.filter(c=>[c.name,c.symbol,c.isin].join(' ').toLowerCase().includes(q));if(q&&matches.length===1){input.setCustomValidity('');input.value='';openCompany(matches[0].id);}else{input.setCustomValidity('Choose a company or enter a more specific name or ticker.');input.reportValidity();}});
 document.getElementById('quickCompany').addEventListener('input',e=>e.target.setCustomValidity(''));
 document.querySelectorAll?.('[data-index-link]').forEach(a=>a.addEventListener('click',e=>{if(e.ctrlKey||e.metaKey||e.shiftKey||e.altKey)return;e.preventDefault();current=null;active='';write();draw();if(a.getAttribute('href')==='#methodology')document.getElementById('methodology').scrollIntoView({block:'start'});}));
 window.addEventListener('hashchange',route);window.addEventListener('popstate',route);
 fetch('sme-data.json').then(r=>{if(!r.ok)throw Error('Research index could not load ('+r.status+').');return r.json();}).then(d=>{metadata=d.metadata||{};data=d.companies; if(!Array.isArray(data)||!data.length)throw Error('The SME collection has no published records yet.');data.sort((a,b)=>a.name.localeCompare(b.name));byId=new Map(data.map(c=>[c.id,c]));document.getElementById('companyChoices').innerHTML=data.map(c=>'<option value="'+esc(c.symbol||c.isin)+'">'+esc(c.name)+'</option>').join('');document.getElementById('coverageCount').textContent=data.some(isRecovered)?(count('deep')-data.filter(isRecovered).length)+' full structured reviews + '+data.filter(isRecovered).length+' recovered narrative editions · '+count('pending')+' pending':metadata.reviewed_companies+' of '+data.length+' companies reviewed · '+count('pending')+' pending';route();window.SME_RESEARCH={companies:data,sections,eligible,ordering,ready:true,getLoadedCount:()=>loaded.size};}).catch(e=>{root.innerHTML='<p class="sme-note" role="alert">'+esc(e.message)+'</p><button id="retryLoad">Try again</button>';document.getElementById('retryLoad').onclick=()=>location.reload();});
})();

})().catch(error=>{const app=document.getElementById("app");if(app){app.textContent=error.message;app.setAttribute("role","alert");}});
