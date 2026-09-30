/* ═══════════════════════════════════════════════════════════════════════════
   SCRYER GRAPH ENGINE v1 — custom WebGL renderer (zero dependencies)
   ─────────────────────────────────────────────────────────────────────────
   force layout: Barnes-Hut quadtree O(n log n) + springs + centering
   rendering:    WebGL gl.POINTS (nodes) + gl.LINES (edges), labels na 2D overlay
   interakcja:   pan (drag), zoom (wheel/pinch do kursora), hover+tooltip,
                 click → onSelect, pulsing ring dla zaznaczenia
   fallback:     brak WebGL → renderer 2D canvas (ten sam layout, wolniejszy)
   Rozmiar canvasa śledzony ResizeObserverem NA BEZPOŚREDNIO — koniec bugów 0×0.
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";

function GraphEngine(container, opts) {
  opts = opts || {};
  const DIAG = opts.onDiag || function () {};

  /* ---------- stan ---------- */
  let nodes = [];            // {id,label,kind,color,size,hot,title,start,x,y,vx,vy,idx}
  let edges = [];            // {a,b,len,color} — a,b = indeksy
  let byId = new Map();
  let dpr = Math.max(1, window.devicePixelRatio || 1);
  let W = 0, H = 0;          // device px
  let cx = 0, cy = 0;        // środek kamery (world)
  let scale = 1;
  let alpha = 0;             // temperatura layoutu (1→0)
  let raf = 0;
  let hovered = -1, selected = -1;
  let followIdx = -1;          // kamera śledzi węzeł (follow mode)
  let needLabelDraw = true;
  const ALPHA_MIN = 0.002;

  /* ---------- canvasy ---------- */
  container.style.position = container.style.position || "relative";
  const glCanvas = document.createElement("canvas");
  const labelCanvas = document.createElement("canvas");
  for (const c of [glCanvas, labelCanvas]) {
    c.style.cssText = "position:absolute;inset:0;width:100%;height:100%;display:block";
  }
  labelCanvas.style.pointerEvents = "none";
  container.appendChild(glCanvas);
  container.appendChild(labelCanvas);
  const lctx = labelCanvas.getContext("2d");

  /* ---------- tooltip ---------- */
  const tip = document.createElement("div");
  tip.style.cssText = [
    "position:absolute", "z-index:8", "pointer-events:none", "display:none",
    "background:rgba(8,13,22,.96)", "border:1px solid rgba(140,170,230,.24)",
    "border-radius:4px", "color:#e9eff9", "font:11px/1.55 'JetBrains Mono',monospace",
    "padding:6px 10px", "box-shadow:0 8px 24px rgba(0,0,0,.6)", "white-space:pre-line",
    "max-width:340px", "backdrop-filter:blur(6px)",
  ].join(";");
  container.appendChild(tip);

  /* ================================================================
     SHADERY — nodes jako gl.POINTS (okrąg z miękkim brzegiem w FS),
     edges jako gl.LINES. Wszystko w device px, y w dół (flip w VS).
     ================================================================ */
  const VS = `
    attribute vec2 a_pos; attribute vec4 a_col; attribute float a_size;
    uniform vec2 u_view; uniform float u_dpr; uniform vec2 u_center; uniform float u_scale;
    varying vec4 v_col;
    void main() {
      vec2 dev = (a_pos - u_center) * u_scale * u_dpr + u_view * 0.5;
      vec2 clip = vec2(dev.x / u_view.x * 2.0 - 1.0, 1.0 - dev.y / u_view.y * 2.0);
      gl_Position = vec4(clip, 0.0, 1.0);
      gl_PointSize = a_size * u_scale * u_dpr;
      v_col = a_col;
    }`;
  const FS = `
    precision mediump float; varying vec4 v_col; uniform float u_ring;
    void main() {
      vec2 p = gl_PointCoord * 2.0 - 1.0;
      float d = length(p);
      float core = 1.0 - smoothstep(0.72, 0.98, d);
      float ring = u_ring > 0.5 ? (smoothstep(0.62, 0.78, d) * (1.0 - smoothstep(0.86, 1.0, d))) : 0.0;
      float a = max(core, ring) * v_col.a;
      if (a < 0.01) discard;
      gl_FragColor = vec4(v_col.rgb, a);
    }`;
  const VS_LINE = `
    attribute vec2 a_pos; attribute vec4 a_col;
    uniform vec2 u_view; uniform float u_dpr; uniform vec2 u_center; uniform float u_scale;
    varying vec4 v_col;
    void main() {
      vec2 dev = (a_pos - u_center) * u_scale * u_dpr + u_view * 0.5;
      vec2 clip = vec2(dev.x / u_view.x * 2.0 - 1.0, 1.0 - dev.y / u_view.y * 2.0);
      gl_Position = vec4(clip, 0.0, 1.0);
      v_col = a_col;
    }`;
  const FS_LINE = `
    precision mediump float; varying vec4 v_col;
    void main() { if (v_col.a < 0.004) discard; gl_FragColor = v_col; }`;

  function compile(gl, type, src) {
    const s = gl.createShader(type);
    gl.shaderSource(s, src); gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s));
    return s;
  }
  function program(gl, vs, fs) {
    const p = gl.createProgram();
    gl.attachShader(p, compile(gl, gl.VERTEX_SHADER, vs));
    gl.attachShader(p, compile(gl, gl.FRAGMENT_SHADER, fs));
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p));
    return p;
  }

  /* ---------- renderer WebGL ---------- */
  let gl = null, progNode, progLine, bufNode, bufLine, uniNode, uniLine;
  let nodeArr = new Float32Array(0);   // [x,y,size,r,g,b,a] * n  (stride 7)
  let edgeArr = new Float32Array(0);   // [x,y,r,g,b,a] * 2 * e   (stride 6)
  let use2D = false, ctx2d = null;

  function initGL() {
    try {
      gl = glCanvas.getContext("webgl", { antialias: true, alpha: true, premultipliedAlpha: false })
        || glCanvas.getContext("experimental-webgl");
      if (!gl) throw new Error("context null");
      progNode = program(gl, VS, FS);
      progLine = program(gl, VS_LINE, FS_LINE);
      bufNode = gl.createBuffer(); bufLine = gl.createBuffer();
      DIAG("webgl OK — renderer własny");
    } catch (e) {
      use2D = true; ctx2d = glCanvas.getContext("2d");
      DIAG("brak WebGL → fallback 2D (" + e.message + ")", true);
    }
  }
  initGL();

  function hexRGBA(hex, a) {
    const h = hex.replace("#", "");
    const n = parseInt(h.length === 3 ? h.split("").map(c => c + c).join("") : h, 16);
    return [(n >> 16 & 255) / 255, (n >> 8 & 255) / 255, (n & 255) / 255, a];
  }

  /* ================================================================
     DANE
     ================================================================ */
  function setData(data) {
    nodes = []; edges = []; byId.clear();
    const N = data.nodes || [];
    for (let i = 0; i < N.length; i++) {
      const n = N[i];
      const s = n.start || [0, 0];
      nodes.push({
        id: n.id, label: n.label || n.id, kind: n.kind || "podmiot",
        color: n.color || "#66789a", colA: hexRGBA(n.color || "#66789a", 1),
        size: n.size || 6, hot: !!n.hot, title: n.title || n.label || "",
        alpha: n.alpha !== undefined ? n.alpha : 1,
        x: s[0], y: s[1], vx: 0, vy: 0, idx: i,
      });
      byId.set(n.id, i);
    }
    const E = data.edges || [];
    for (const e of E) {
      const a = byId.get(e.s), b = byId.get(e.t);
      if (a === undefined || b === undefined) continue;
      edges.push({ a, b, len: e.len || 95, colA: hexRGBA(e.color || "#1c2a44", e.alpha || 0.5) });
    }
    // start: podmioty bez startu → okrąg; reszta przy rodzicu z krawędzi
    let pi = 0;
    const podm = nodes.filter(n => n.kind === "podmiot").length || 1;
    for (const n of nodes) {
      if (n.start) continue;
      if (n.kind === "podmiot") {
        const ang = (pi++ / podm) * Math.PI * 2;
        n.x = Math.cos(ang) * 380; n.y = Math.sin(ang) * 380;
      } else {
        const e = edges.find(x => x.b === n.idx) || edges.find(x => x.a === n.idx);
        const p = e ? nodes[e.a === n.idx ? e.b : e.a] : null;
        const a = Math.random() * Math.PI * 2, r = 18 + Math.random() * 14;
        n.x = (p ? p.x : 0) + Math.cos(a) * r;
        n.y = (p ? p.y : 0) + Math.sin(a) * r;
      }
    }
    nodeArr = new Float32Array(nodes.length * 7);
    edgeArr = new Float32Array(edges.length * 12);
    alpha = 1.0;
    hovered = -1; selected = -1;
    if (opts.onCounts) opts.onCounts(nodes.length, edges.length);
    fitView(false);
    wake();
    DIAG(`dane: ${nodes.length} węzłów, ${edges.length} krawędzi`);
  }

  /* ================================================================
     FIZYKA — Barnes-Hut
     ================================================================ */
  function stepPhysics() {
    const n = nodes.length;
    if (!n) return;
    // quadtree
    let minX = 1e9, minY = 1e9, maxX = -1e9, maxY = -1e9;
    for (const nd of nodes) {
      if (nd.x < minX) minX = nd.x; if (nd.x > maxX) maxX = nd.x;
      if (nd.y < minY) minY = nd.y; if (nd.y > maxY) maxY = nd.y;
    }
    const root = buildTree(minX, minY, Math.max(maxX - minX, maxY - minY) + 1);
    const REP = 4200, SPRING = 0.055, GRAV = 0.045, DAMP = 0.86, MAXV = 16;
    let maxV2 = 0;
    for (const nd of nodes) {
      let fx = 0, fy = 0;
      // odpychanie przez drzewo
      if (root) applyRepulsion(root, nd, 0.9, REP, (f) => { fx += f[0]; fy += f[1]; });
      // grawitacja do środka
      fx += -nd.x * GRAV; fy += -nd.y * GRAV;
      nd.vx = (nd.vx + fx) * DAMP; nd.vy = (nd.vy + fy) * DAMP;
      const v2 = nd.vx * nd.vx + nd.vy * nd.vy;
      if (v2 > maxV2) maxV2 = v2;
      if (v2 > MAXV * MAXV) { const k = MAXV / Math.sqrt(v2); nd.vx *= k; nd.vy *= k; }
    }
    // sprężyny
    for (const e of edges) {
      const A = nodes[e.a], B = nodes[e.b];
      let dx = B.x - A.x, dy = B.y - A.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const f = (d - e.len) * SPRING;
      const ux = dx / d, uy = dy / d;
      A.vx += ux * f; A.vy += uy * f;
      B.vx -= ux * f; B.vy -= uy * f;
    }
    // integracja
    for (const nd of nodes) { nd.x += nd.vx; nd.y += nd.vy; }
    alpha *= 0.986;
    if (alpha < ALPHA_MIN || (alpha < 0.05 && maxV2 < 0.0025)) { alpha = 0; DIAG("layout stabilny"); }
  }

  function buildTree(x, y, size) {
    const node = { x, y, size, cx: 0, cy: 0, mass: 0, kids: null, leaf: -1 };
    // wstawiamy wszystkie punkty — iteracyjnie
    for (const nd of nodes) insert(node, nd.idx, x, y, size, 0);
    return node;
  }
  function insert(t, i, x, y, size, depth) {
    if (t.leaf === -1 && !t.kids) { t.leaf = i; }
    else if (t.kids) { place(t, i, x, y, size, depth); }
    else {
      const j = t.leaf; t.leaf = -1;
      t.kids = [null, null, null, null];
      place(t, j, x, y, size, depth);
      place(t, i, x, y, size, depth);
    }
    // agregacja masy w górę
    t.mass += 1;
    t.cx += nodes[i].x; t.cy += nodes[i].y;
  }
  function place(t, i, x, y, size, depth) {
    const half = size / 2;
    const qx = nodes[i].x >= x + half ? 1 : 0;
    const qy = nodes[i].y >= y + half ? 1 : 0;
    const q = qy * 2 + qx;
    if (depth > 24 || half < 0.01) { // degeneracja — trzymaj w liściu zbiorczym
      if (!t.kids[q]) t.kids[q] = { x, y, size, cx: 0, cy: 0, mass: 0, kids: null, leaf: -1 };
      t.kids[q].mass += 1; t.kids[q].cx += nodes[i].x; t.kids[q].cy += nodes[i].y;
      return;
    }
    if (!t.kids[q]) t.kids[q] = mkChild(x + qx * half, y + qy * half, half);
    insert(t.kids[q], i, x + qx * half, y + qy * half, half, depth + 1);
  }
  function mkChild(x, y, size) { return { x, y, size, cx: 0, cy: 0, mass: 0, kids: null, leaf: -1 }; }
  function applyRepulsion(t, nd, theta, REP, out) {
    if (t.mass === 0) return;
    if (t.leaf >= 0) {
      const o = nodes[t.leaf];
      if (o.idx === nd.idx) return;
      repulse(o.x, o.y, nd, REP, out);
      return;
    }
    if (t.kids) {
      // wewnętrzny: środek masy liczony przy wstawianiu (cx,cy = suma → /mass)
      const mx = t.cx / t.mass, my = t.cy / t.mass;
      const dx = mx - nd.x, dy = my - nd.y;
      const d2 = dx * dx + dy * dy || 1;
      if (t.size / Math.sqrt(d2) < theta) {
        const d = Math.sqrt(d2);
        const f = (REP * t.mass) / (d2 * d);
        out([dx / d * f, dy / d * f]);
      } else {
        for (const k of t.kids) if (k) applyRepulsion(k, nd, theta, REP, out);
      }
      return;
    }
    // liść zbiorczy (degeneracja)
    if (t.mass > 0) {
      const mx = t.cx / t.mass, my = t.cy / t.mass;
      repulse(mx, my, nd, REP, out);
    }
  }
  function repulse(ox, oy, nd, REP, out) {
    let dx = nd.x - ox, dy = nd.y - oy;
    const d2 = dx * dx + dy * dy || 1;
    const d = Math.sqrt(d2);
    const f = REP / (d2 * d);
    out([dx / d * f, dy / d * f]);
  }

  /* ================================================================
     KAMERA
     ================================================================ */
  function worldToScreen(wx, wy) {
    return [(wx - cx) * scale * dpr + W / 2, (wy - cy) * scale * dpr + H / 2];
  }
  function screenToWorld(sx, sy) { // sx,sy w device px
    return [(sx - W / 2) / (scale * dpr) + cx, (sy - H / 2) / (scale * dpr) + cy];
  }
  function fitView(animate) {
    if (!nodes.length) return;
    let minX = 1e9, minY = 1e9, maxX = -1e9, maxY = -1e9;
    for (const n of nodes) {
      if (n.x < minX) minX = n.x; if (n.x > maxX) maxX = n.x;
      if (n.y < minY) minY = n.y; if (n.y > maxY) maxY = n.y;
    }
    const cw = W / dpr, ch = H / dpr;
    if (cw < 10 || ch < 10) return;
    const pad = 70;
    const s = Math.min((cw - pad * 2) / Math.max(maxX - minX, 1), (ch - pad * 2) / Math.max(maxY - minY, 1));
    const target = Math.max(0.05, Math.min(s, 2.2));
    const tcx = (minX + maxX) / 2, tcy = (minY + maxY) / 2;
    if (animate) {
      const s0 = scale, c0x = cx, c0y = cy, t0 = performance.now();
      const tick = (t) => {
        const p = Math.min(1, (t - t0) / 260);
        const e = 1 - Math.pow(1 - p, 3);
        scale = s0 + (target - s0) * e; cx = c0x + (tcx - c0x) * e; cy = c0y + (tcy - c0y) * e;
        needLabelDraw = true;
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    } else { scale = target; cx = tcx; cy = tcy; }
    needLabelDraw = true;
  }

  /* ================================================================
     RENDER
     ================================================================ */
  function syncBuffers() {
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i], o = i * 7;
      nodeArr[o] = n.x; nodeArr[o + 1] = n.y; nodeArr[o + 2] = n.size;
      nodeArr[o + 3] = n.colA[0]; nodeArr[o + 4] = n.colA[1]; nodeArr[o + 5] = n.colA[2];
      nodeArr[o + 6] = n.alpha;
    }
    for (let e = 0; e < edges.length; e++) {
      const ed = edges[e], A = nodes[ed.a], B = nodes[ed.b], o = e * 12;
      edgeArr[o] = A.x; edgeArr[o + 1] = A.y;
      edgeArr[o + 2] = ed.colA[0]; edgeArr[o + 3] = ed.colA[1]; edgeArr[o + 4] = ed.colA[2]; edgeArr[o + 5] = ed.colA[3];
      edgeArr[o + 6] = B.x; edgeArr[o + 7] = B.y;
      edgeArr[o + 8] = ed.colA[0]; edgeArr[o + 9] = ed.colA[1]; edgeArr[o + 10] = ed.colA[2]; edgeArr[o + 11] = ed.colA[3];
    }
  }

  function draw() {
    syncBuffers();
    if (!use2D) drawGL(); else draw2D();
    drawLabels();
  }

  function drawGL() {
    gl.viewport(0, 0, W, H);
    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    // ---- edges
    if (edges.length) {
      gl.useProgram(progLine);
      gl.uniform2f(gl.getUniformLocation(progLine, "u_view"), W, H);
      gl.uniform1f(gl.getUniformLocation(progLine, "u_dpr"), dpr);
      gl.uniform2f(gl.getUniformLocation(progLine, "u_center"), cx, cy);
      gl.uniform1f(gl.getUniformLocation(progLine, "u_scale"), scale);
      gl.bindBuffer(gl.ARRAY_BUFFER, bufLine);
      gl.bufferData(gl.ARRAY_BUFFER, edgeArr, gl.DYNAMIC_DRAW);
      const aP = gl.getAttribLocation(progLine, "a_pos");
      const aC = gl.getAttribLocation(progLine, "a_col");
      gl.enableVertexAttribArray(aP); gl.vertexAttribPointer(aP, 2, gl.FLOAT, false, 24, 0);
      gl.enableVertexAttribArray(aC); gl.vertexAttribPointer(aC, 4, gl.FLOAT, false, 24, 8);
      gl.drawArrays(gl.LINES, 0, edges.length * 2);
    }

    // ---- halo dla HOT (drugi pass, większy punkt, mała alfa)
    drawPoints(progNode, { halo: true });

    // ---- nodes
    drawPoints(progNode, { halo: false });

    // ---- ring hover / selection (osobny draw, uniform)
    for (const [idx, phase] of [[hovered, 0], [selected, 1]]) {
      if (idx < 0) continue;
      const n = nodes[idx];
      const [sx, sy] = worldToScreen(n.x, n.y);
      const r = n.size * scale * dpr * (phase ? 1.9 : 1.55) + (phase ? pulse() * 3 * dpr : 0);
      gl.useProgram(progNode);
      gl.uniform2f(gl.getUniformLocation(progNode, "u_view"), W, H);
      gl.uniform1f(gl.getUniformLocation(progNode, "u_dpr"), dpr);
      gl.uniform2f(gl.getUniformLocation(progNode, "u_center"), cx, cy);
      gl.uniform1f(gl.getUniformLocation(progNode, "u_scale"), scale);
      gl.uniform1f(gl.getUniformLocation(progNode, "u_ring"), 1);
      const col = phase ? [0.208, 0.878, 0.631, 0.9] : [0.85, 0.9, 1, 0.55];
      const arr = new Float32Array([n.x, n.y, r / (scale * dpr), col[0], col[1], col[2], col[3]]);
      gl.bindBuffer(gl.ARRAY_BUFFER, bufNode);
      gl.bufferData(gl.ARRAY_BUFFER, arr, gl.DYNAMIC_DRAW);
      const aP = gl.getAttribLocation(progNode, "a_pos");
      const aS = gl.getAttribLocation(progNode, "a_size");
      const aC = gl.getAttribLocation(progNode, "a_col");
      gl.enableVertexAttribArray(aP); gl.vertexAttribPointer(aP, 2, gl.FLOAT, false, 28, 0);
      gl.enableVertexAttribArray(aS); gl.vertexAttribPointer(aS, 1, gl.FLOAT, false, 28, 8);
      gl.enableVertexAttribArray(aC); gl.vertexAttribPointer(aC, 4, gl.FLOAT, false, 28, 12);
      gl.drawArrays(gl.POINTS, 0, 1);
      gl.uniform1f(gl.getUniformLocation(progNode, "u_ring"), 0);
    }
  }
  function pulse() { return Math.sin(performance.now() / 320) * 0.5 + 0.5; }

  function drawPoints(prog, o) {
    gl.uniform1f(gl.getUniformLocation(prog, "u_ring"), 0);
    gl.bindBuffer(gl.ARRAY_BUFFER, bufNode);
    gl.bufferData(gl.ARRAY_BUFFER, nodeArr, gl.DYNAMIC_DRAW);
    const aP = gl.getAttribLocation(prog, "a_pos");
    const aS = gl.getAttribLocation(prog, "a_size");
    const aC = gl.getAttribLocation(prog, "a_col");
    gl.enableVertexAttribArray(aP); gl.vertexAttribPointer(aP, 2, gl.FLOAT, false, 28, 0);
    gl.enableVertexAttribArray(aS); gl.vertexAttribPointer(aS, 1, gl.FLOAT, false, 28, 8);
    gl.enableVertexAttribArray(aC); gl.vertexAttribPointer(aC, 4, gl.FLOAT, false, 28, 12);
    if (o.halo) {
      // podbicie rozmiaru dla HOT-only halo: rysujemy wszystkie *1 passie —
      // prościej: drugi draw tych samych punktów z size x2.2 i alfa x0.10
      const n = nodes.length;
      if (!n) return;
      const tmp = new Float32Array(nodeArr);
      for (let i = 0; i < n; i++) {
        const nd = nodes[i];
        if (!nd.hot) continue;
        const off = i * 7;
        tmp[off + 2] = nd.size * 2.4;
        tmp[off + 6] = 0.10;
      }
      gl.bufferData(gl.ARRAY_BUFFER, tmp, gl.DYNAMIC_DRAW);
      gl.drawArrays(gl.POINTS, 0, n);
      gl.bufferData(gl.ARRAY_BUFFER, nodeArr, gl.DYNAMIC_DRAW);
    } else {
      gl.drawArrays(gl.POINTS, 0, nodes.length);
    }
  }

  /* ---------- fallback 2D ---------- */
  function draw2D() {
    ctx2d.setTransform(1, 0, 0, 1, 0, 0);
    ctx2d.clearRect(0, 0, W, H);
    ctx2d.lineWidth = dpr;
    ctx2d.strokeStyle = "rgba(28,42,68,0.5)";
    ctx2d.beginPath();
    for (const e of edges) {
      const A = nodes[e.a], B = nodes[e.b];
      const [ax, ay] = worldToScreen(A.x, A.y);
      const [bx, by] = worldToScreen(B.x, B.y);
      ctx2d.moveTo(ax, ay); ctx2d.lineTo(bx, by);
    }
    ctx2d.stroke();
    for (const n of nodes) {
      const [sx, sy] = worldToScreen(n.x, n.y);
      const r = Math.max(1.5, n.size * scale * dpr / 2);
      ctx2d.globalAlpha = n.alpha;
      ctx2d.fillStyle = n.color;
      ctx2d.beginPath(); ctx2d.arc(sx, sy, r, 0, Math.PI * 2); ctx2d.fill();
      if (n.hot) {
        ctx2d.globalAlpha = 0.12; ctx2d.beginPath(); ctx2d.arc(sx, sy, r * 2.4, 0, Math.PI * 2); ctx2d.fill();
      }
    }
    ctx2d.globalAlpha = 1;
    for (const [idx, phase] of [[hovered, 0], [selected, 1]]) {
      if (idx < 0) continue;
      const n = nodes[idx];
      const [sx, sy] = worldToScreen(n.x, n.y);
      ctx2d.strokeStyle = phase ? "rgba(53,224,161,.9)" : "rgba(217,230,255,.55)";
      ctx2d.lineWidth = 1.4 * dpr;
      ctx2d.beginPath(); ctx2d.arc(sx, sy, n.size * scale * dpr / 2 + 5 * dpr, 0, Math.PI * 2); ctx2d.stroke();
    }
  }

  /* ---------- labele (2D overlay) ---------- */
  const KIND_TH = { podmiot: 0.28, domena: 0.85, osoba: 1.5 };
  function drawLabels() {
    const cw = W / dpr, ch = H / dpr;
    lctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    lctx.clearRect(0, 0, cw, ch);
    lctx.textBaseline = "middle";
    let budget = 520;
    // podmioty najpierw (priorytet), potem domeny/osoby wg progu zoomu
    const order = nodes.slice().sort((a, b) => kindRank(b.kind) - kindRank(a.kind));
    for (const n of order) {
      if (budget <= 0) break;
      const th = KIND_TH[n.kind] || 1;
      if (scale < th) continue;
      const [sx, sy] = worldToScreen(n.x, n.y);
      const px = sx / dpr, py = sy / dpr;
      if (px < -80 || py < -20 || px > cw + 80 || py > ch + 20) continue;
      lctx.font = `${n.kind === "podmiot" ? 10.5 : 9}px "JetBrains Mono",monospace`;
      lctx.fillStyle = labelColor(n);
      lctx.globalAlpha = n.alpha * (n.kind === "podmiot" ? 0.95 : 0.8);
      lctx.fillText(n.label, px + n.size * scale + 6, py);
      budget--;
    }
    lctx.globalAlpha = 1;
  }
  function kindRank(k) { return k === "podmiot" ? 2 : k === "domena" ? 1 : 0; }
  function labelColor(n) {
    if (n.kind === "osoba") return n.alpha >= 1 && n.hot ? "#35e0a1" : "#42536d";
    if (n.hot) return "#ffb8a3";
    return n.kind === "domena" ? "#5d7089" : "#9fb0ca";
  }

  /* ================================================================
     PĘTLA
     ================================================================ */
  function frame() {
    raf = 0;
    if (alpha > 0) {
      stepPhysics();
      if (opts.onProgress) opts.onProgress(1 - alpha);
    }
    // follow: kamera dołapuje węzeł (ease) — działa też po stabilizacji
    if (followIdx >= 0 && nodes[followIdx]) {
      const n = nodes[followIdx];
      cx += (n.x - cx) * 0.14;
      cy += (n.y - cy) * 0.14;
    }
    draw();
    if (alpha > 0 || pendingFit || followIdx >= 0) {
      if (alpha === 0 && pendingFit) { pendingFit = false; fitView(true); }
      raf = requestAnimationFrame(frame);
    } else {
      if (opts.onProgress) opts.onProgress(null);
      if (pendingFit) { pendingFit = false; fitView(true); }
    }
  }
  let pendingFit = false;
  function wake() { if (!raf) raf = requestAnimationFrame(frame); }

  /* ================================================================
     RESIZE (ResizeObserver na kontenerze — nie window!)
     ================================================================ */
  function resize() {
    const cw = container.clientWidth, ch = container.clientHeight;
    if (cw < 10 || ch < 10) return;
    dpr = Math.max(1, window.devicePixelRatio || 1);
    W = Math.round(cw * dpr); H = Math.round(ch * dpr);
    for (const c of [glCanvas, labelCanvas]) { c.width = W; c.height = H; }
    needLabelDraw = true;
    wake();
    DIAG(`canvas: ${cw}×${ch} css · ${W}×${H} dev`);
  }
  const ro = new ResizeObserver(() => resize());
  ro.observe(container);

  /* ================================================================
     INTERAKCJA
     ================================================================ */
  let dragging = false, lastX = 0, lastY = 0, moved = 0;
  const evDev = (e) => {
    const r = glCanvas.getBoundingClientRect();
    return [(e.clientX - r.left) * dpr, (e.clientY - r.top) * dpr];
  };
  function pick(sx, sy) {
    let best = -1, bestD = 12 * dpr;
    for (const n of nodes) {
      const [x, y] = worldToScreen(n.x, n.y);
      const r = Math.max(n.size * scale * dpr / 2, 6 * dpr);
      const d = Math.hypot(x - sx, y - sy);
      if (d < Math.max(r, bestD) && d <= r + 6 * dpr && d < bestD + r) {
        if (d - r < bestD) { bestD = Math.max(d - r, 0); best = n.idx; }
      }
    }
    return best;
  }
  glCanvas.addEventListener("mousedown", (e) => {
    dragging = true; moved = 0;
    followIdx = -1; // użytkownik przejmuje kamerę
    [lastX, lastY] = evDev(e);
    glCanvas.setPointerCapture?.(e.pointerId);
  });
  glCanvas.addEventListener("mousemove", (e) => {
    const [sx, sy] = evDev(e);
    if (dragging) {
      const dx = sx - lastX, dy = sy - lastY;
      moved += Math.abs(dx) + Math.abs(dy);
      cx -= dx / (scale * dpr); cy -= dy / (scale * dpr);
      lastX = sx; lastY = sy;
      hideTip(); needLabelDraw = true; wake();
      return;
    }
    const h = pick(sx, sy);
    if (h !== hovered) {
      hovered = h;
      if (opts.onHover) opts.onHover(h >= 0 ? nodes[h] : null);
      wake();
    }
    if (h >= 0) showTip(nodes[h], e); else hideTip();
    glCanvas.style.cursor = h >= 0 ? "pointer" : "grab";
  });
  glCanvas.addEventListener("mouseup", (e) => {
    dragging = false;
    if (moved < 6) {
      const [sx, sy] = evDev(e);
      const h = pick(sx, sy);
      selected = h;
      if (opts.onSelect) opts.onSelect(h >= 0 ? nodes[h] : null);
      wake();
    }
  });
  glCanvas.addEventListener("mouseleave", () => { if (!dragging) { hovered = -1; hideTip(); if (opts.onHover) opts.onHover(null); wake(); } });
  glCanvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const [sx, sy] = evDev(e);
    const [wx, wy] = screenToWorld(sx, sy);
    const k = Math.exp(-e.deltaY * 0.0016);
    scale = Math.max(0.03, Math.min(12, scale * k));
    // utrzymaj punkt świata pod kursorem
    cx = wx - (sx - W / 2) / (scale * dpr);
    cy = wy - (sy - H / 2) / (scale * dpr);
    needLabelDraw = true; wake();
  }, { passive: false });
  // touch: pan 1 palec, pinch 2
  let tPinch = null;
  glCanvas.addEventListener("touchstart", (e) => {
    if (e.touches.length === 1) { dragging = true; [lastX, lastY] = evDev(e.touches[0]); }
    else if (e.touches.length === 2) {
      dragging = false;
      const [ax, ay] = evDev(e.touches[0]), [bx, by] = evDev(e.touches[1]);
      tPinch = { d: Math.hypot(ax - bx, ay - by), cx: (ax + bx) / 2, cy: (ay + by) / 2, scale };
    }
  }, { passive: true });
  glCanvas.addEventListener("touchmove", (e) => {
    if (e.touches.length === 1 && dragging) {
      const [sx, sy] = evDev(e.touches[0]);
      cx -= (sx - lastX) / (scale * dpr); cy -= (sy - lastY) / (scale * dpr);
      lastX = sx; lastY = sy; wake();
    } else if (e.touches.length === 2 && tPinch) {
      const [ax, ay] = evDev(e.touches[0]), [bx, by] = evDev(e.touches[1]);
      const d = Math.hypot(ax - bx, ay - by);
      scale = Math.max(0.03, Math.min(12, tPinch.scale * d / tPinch.d));
      const [wx, wy] = screenToWorld(tPinch.cx, tPinch.cy);
      cx = wx - (tPinch.cx - W / 2) / (scale * dpr);
      cy = wy - (tPinch.cy - H / 2) / (scale * dpr);
      wake();
    }
  }, { passive: true });
  glCanvas.addEventListener("touchend", () => { dragging = false; tPinch = null; }, { passive: true });

  function showTip(n, e) {
    tip.textContent = n.title;
    tip.style.display = "block";
    const r = container.getBoundingClientRect();
    let tx = e.clientX - r.left + 14, ty = e.clientY - r.top + 14;
    if (tx + 340 > r.width) tx = e.clientX - r.left - 350;
    if (ty + 90 > r.height) ty = e.clientY - r.top - 90;
    tip.style.left = tx + "px"; tip.style.top = ty + "px";
  }
  function hideTip() { tip.style.display = "none"; }

  /* ---------- API ---------- */
  return {
    setData,
    fitView: (animated) => { followIdx = -1; fitView(animated !== false); },
    // kamera śledzi węzeł (id z danych, np. "p123") aż do interakcji użytkownika
    follow(id) {
      followIdx = id !== null && byId.has(id) ? byId.get(id) : -1;
      if (followIdx >= 0) {
        // przybliż na cel
        const n = nodes[followIdx];
        const cw = W / dpr, ch = H / dpr;
        if (cw > 10) {
          const target = Math.min(1.1, scale * 2);
          const s0 = scale, c0x = cx, c0y = cy, t0 = performance.now();
          const tick = (t) => {
            const p = Math.min(1, (t - t0) / 320);
            const e = 1 - Math.pow(1 - p, 3);
            scale = s0 + (target - s0) * e;
            if (p < 1) requestAnimationFrame(tick);
          };
          requestAnimationFrame(tick);
        }
        wake();
      }
    },
    get following() { return followIdx >= 0; },
    select(id) { selected = id !== null && byId.has(id) ? byId.get(id) : -1; wake(); },
    hover(id) { hovered = id !== null && byId.has(id) ? byId.get(id) : -1; wake(); },
    destroy() {
      ro.disconnect();
      if (raf) cancelAnimationFrame(raf);
      for (const c of [glCanvas, labelCanvas, tip]) c.remove();
    },
    get scale() { return scale; },
  };
}
