/* Orch Dork local view.
 *
 * Packaged, offline, dependency-free. Every view is a one-way projection of
 * records the local helper already holds. The only writes this page can make
 * are to future settings: enrollment, standing authority, model onboarding,
 * and the one confirmed V1 change to the user's own Codex. Starting, stopping,
 * approving, steering, and revising a run stay in the chat.
 *
 * No element is ever built from HTML text. Every value that came from the
 * helper reaches the page through textContent or createTextNode.
 */

(function () {
  "use strict";

  var SVG_NS = "http://www.w3.org/2000/svg";
  var STATE_POLL_MS = 3000;
  var ONBOARD_POLL_MS = 2000;
  var ONBOARD_POLL_LIMIT = 150;

  var NODE_STATES = [
    "planned", "active", "waiting", "completed", "failed", "cancelled",
    "timed_out", "unreleased", "released", "integrating", "blocked"
  ];
  var EDGE_STATES = [
    "planned", "observed", "active", "satisfied", "released", "blocked", "failed"
  ];
  var EVIDENCE_CLASSES = ["observed", "inferred", "submitted", "unknown", "contradictory"];
  var EVIDENCE_TIERS = ["submitted", "runtime-observed", "sealed-runtime"];

  var NODE_STATE_TEXT = {
    planned: "In the frozen plan and not started.",
    active: "Running now.",
    waiting: "Admitted and waiting on capacity or a dependency.",
    completed: "Finished and reported a result.",
    failed: "Finished with a failure.",
    cancelled: "Stopped before it finished.",
    timed_out: "Stopped at its time limit.",
    unreleased: "Terminal but still holding its slot.",
    released: "Terminal and its slot is released.",
    integrating: "Its result is being folded into the run.",
    blocked: "Cannot proceed; the issues below say why."
  };
  var EDGE_STATE_TEXT = {
    planned: "In the plan and not yet seen in the record.",
    observed: "Seen in the record.",
    active: "Carrying work right now.",
    satisfied: "Its condition is met.",
    released: "Its slot is released.",
    blocked: "Held; the issues below say why.",
    failed: "Its work failed."
  };
  var CLASS_TEXT = {
    observed: "The runtime recorded it directly.",
    inferred: "Derived from recorded facts, not recorded directly.",
    submitted: "Reported by the worker and not independently confirmed.",
    unknown: "No evidence either way. Nothing is assumed.",
    contradictory: "Sources disagree. The raw evidence bundle decides."
  };
  var CLASS_GLYPH = {
    observed: "\u25CF",
    inferred: "\u25D0",
    submitted: "\u25A3",
    unknown: "?",
    contradictory: "\u26A0"
  };
  var TIER_TEXT = {
    submitted: "Model-authored. Lowest trust.",
    "runtime-observed": "Observed by the host runtime.",
    "sealed-runtime": "Observed by the runtime and sealed against change."
  };

  var LABELS = {
    planned: "Planned", active: "Active", waiting: "Waiting", completed: "Completed",
    failed: "Failed", cancelled: "Cancelled", timed_out: "Timed out",
    unreleased: "Unreleased", released: "Released", integrating: "Integrating",
    blocked: "Blocked", observed: "Observed", satisfied: "Satisfied",
    inferred: "Inferred", submitted: "Submitted", unknown: "Unknown",
    contradictory: "Contradictory", "runtime-observed": "Runtime observed",
    "sealed-runtime": "Sealed runtime", passed: "Passed",
    not_passed: "Did not pass", not_onboarded: "Not onboarded",
    local_only: "Local only", hosted_restricted: "Hosted, restricted",
    hosted_standard: "Hosted, standard", local: "Local",
    governed_runner: "Governed runner", own_codex: "Your own Codex"
  };

  /* ------------------------------------------------------------ dom */

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function add(parent) {
    for (var i = 1; i < arguments.length; i += 1) {
      var child = arguments[i];
      if (child) { parent.appendChild(child); }
    }
    return parent;
  }

  function attr(node, name, value) {
    node.setAttribute(name, String(value));
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
    return node;
  }

  function svgEl(tag, cls) {
    var node = document.createElementNS(SVG_NS, tag);
    if (cls) { node.setAttribute("class", cls); }
    return node;
  }

  function svgText(x, y, cls, text) {
    var node = svgEl("text", cls);
    node.setAttribute("x", String(x));
    node.setAttribute("y", String(y));
    node.textContent = String(text);
    return node;
  }

  function byId(id) { return document.getElementById(id); }

  /* ------------------------------------------------------------ values */

  function hasText(value) {
    return typeof value === "string" && value.replace(/\s+/g, "") !== "";
  }

  function label(value) {
    if (!hasText(value)) { return "unknown"; }
    if (LABELS[value]) { return LABELS[value]; }
    return value;
  }

  function textOf(value, fallback) {
    if (hasText(value)) { return value; }
    if (typeof value === "number" && isFinite(value)) { return String(value); }
    if (typeof value === "boolean") { return value ? "yes" : "no"; }
    return fallback === undefined ? "unknown" : fallback;
  }

  function valueNode(value) {
    if (hasText(value)) { return document.createTextNode(value); }
    if (typeof value === "number" && isFinite(value)) { return document.createTextNode(String(value)); }
    if (typeof value === "boolean") { return document.createTextNode(value ? "yes" : "no"); }
    return el("span", "unknown", "unknown");
  }

  function clip(value, max) {
    var text = String(value);
    if (text.length <= max) { return text; }
    return text.slice(0, max - 1) + "\u2026";
  }

  function formatCost(value) {
    if (typeof value === "number" && isFinite(value)) {
      return "$" + value.toFixed(2);
    }
    if (hasText(value)) { return value; }
    if (value && typeof value === "object" && hasText(value.text)) { return value.text; }
    return null;
  }

  function formatTime(value) {
    if (!hasText(value)) { return null; }
    var moment = new Date(value);
    if (isNaN(moment.getTime())) { return value; }
    try {
      return moment.toLocaleString();
    } catch (error) {
      return value;
    }
  }

  function shortDigest(value) {
    if (!hasText(value)) { return "unknown"; }
    if (value.length <= 16) { return value; }
    return value.slice(0, 12) + "\u2026";
  }

  function listOf(value) {
    return Object.prototype.toString.call(value) === "[object Array]" ? value : [];
  }

  function mapOf(value) {
    return value && typeof value === "object" && Object.prototype.toString.call(value) !== "[object Array]"
      ? value
      : {};
  }

  function keysOf(value) {
    var map = mapOf(value);
    var keys = [];
    var name;
    for (name in map) {
      if (Object.prototype.hasOwnProperty.call(map, name)) { keys.push(name); }
    }
    keys.sort();
    return keys;
  }

  /* ------------------------------------------------------------ pieces */

  function kv(rows) {
    var list = el("dl", "kv");
    for (var i = 0; i < rows.length; i += 1) {
      var row = rows[i];
      if (!row) { continue; }
      add(list, el("dt", null, row[0]));
      var dd = el("dd");
      if (row[1] && row[1].nodeType) { add(dd, row[1]); } else { add(dd, valueNode(row[1])); }
      add(list, dd);
    }
    return list;
  }

  function badge(value, kind) {
    var name = hasText(value) ? value : "unknown";
    var node = el("span", "badge badge-state-" + name + (kind ? " badge-" + kind : ""));
    add(node, attr(el("span", "badge-dot"), "aria-hidden", "true"));
    add(node, document.createTextNode(label(name)));
    return node;
  }

  function evidenceBadge(value) {
    var name = hasText(value) ? value : "unknown";
    var kind = name === "contradictory" ? "alert" : (name === "observed" ? "ok" : (name === "unknown" ? "warn" : null));
    var node = el("span", "badge" + (kind ? " badge-" + kind : ""));
    var glyph = el("span", "badge-glyph", CLASS_GLYPH[name] || "?");
    attr(glyph, "aria-hidden", "true");
    add(node, glyph);
    add(node, document.createTextNode(label(name)));
    return node;
  }

  function codeNode(value, cls) {
    if (!hasText(value)) { return el("span", "unknown", "unknown"); }
    return el("code", cls || "digest", value);
  }

  function card(titleText, subText, cls) {
    var node = el("section", "card" + (cls ? " " + cls : ""));
    if (titleText || subText) {
      var head = el("div", "card-head");
      var left = el("div");
      if (titleText) { add(left, el("h2", "card-title", titleText)); }
      if (subText) { add(left, el("p", "card-sub", subText)); }
      add(head, left);
      add(node, head);
    }
    return node;
  }

  function emptyState(titleText, bodyText) {
    var node = el("div", "empty");
    add(node, el("h2", null, titleText));
    add(node, el("p", null, bodyText));
    return node;
  }

  function table(caption, headers) {
    var wrap = el("div", "table-wrap");
    if (caption) {
      // The wrapper scrolls sideways on narrow screens, so it has to be
      // reachable and named for a keyboard or screen reader.
      attr(wrap, "tabindex", "0");
      attr(wrap, "role", "group");
      attr(wrap, "aria-label", caption);
    }
    var node = el("table");
    if (caption) { add(node, el("caption", null, caption)); }
    var head = el("thead");
    var row = el("tr");
    for (var i = 0; i < headers.length; i += 1) {
      add(row, attr(el("th", null, headers[i]), "scope", "col"));
    }
    add(head, row);
    add(node, head);
    var body = el("tbody");
    add(node, body);
    add(wrap, node);
    return { wrap: wrap, body: body };
  }

  function cell(value, cls) {
    var node = el("td", cls || null);
    if (value && value.nodeType) { add(node, value); } else { add(node, valueNode(value)); }
    return node;
  }

  function bulletList(values, emptyText) {
    if (!values.length) { return el("p", "hint", emptyText); }
    var list = el("ul");
    for (var i = 0; i < values.length; i += 1) {
      var value = values[i];
      add(list, el("li", null, typeof value === "string" ? value : JSON.stringify(value)));
    }
    return list;
  }

  /* ------------------------------------------------------------ session */

  var secret = null;
  var sessionLost = false;

  function captureSession() {
    var raw = window.location.hash || "";
    if (raw.charAt(0) === "#") { raw = raw.slice(1); }
    var found = null;
    var parts = raw.split("&");
    for (var i = 0; i < parts.length; i += 1) {
      var part = parts[i];
      if (!part) { continue; }
      var split = part.indexOf("=");
      var name = split < 0 ? part : part.slice(0, split);
      if (name !== "session") { continue; }
      var encoded = split < 0 ? "" : part.slice(split + 1);
      try {
        found = decodeURIComponent(encoded.replace(/\+/g, " "));
      } catch (error) {
        found = encoded;
      }
    }
    if (window.location.hash) {
      var bare = window.location.pathname + window.location.search;
      try {
        window.history.replaceState(null, document.title, bare);
      } catch (error) {
        window.location.replace(bare);
      }
    }
    return hasText(found) ? found : null;
  }

  /* ------------------------------------------------------------ api */

  function failure(reason, message) {
    var error = new Error(message || reason);
    error.reason = reason;
    error.text = message || "";
    return error;
  }

  function request(path, body) {
    if (!secret) {
      return Promise.reject(failure("session:missing", "This page has no session key."));
    }
    var options = {
      method: body === undefined ? "GET" : "POST",
      cache: "no-store",
      credentials: "omit",
      mode: "same-origin",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: { Authorization: "Bearer " + secret, Accept: "application/json" }
    };
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    return fetch(path, options).then(function (response) {
      return response.text().then(function (raw) {
        var data = null;
        if (raw) {
          try {
            data = JSON.parse(raw);
          } catch (error) {
            throw failure("response:not_json", "The helper sent a reply this page could not read.");
          }
        }
        var reason = data && hasText(data.reason) ? data.reason : null;
        var message = data && hasText(data.message) ? data.message : null;
        if (response.status === 403) {
          throw failure(reason || "session:refused",
            message || "The helper refused this session key, this origin, or an expired session.");
        }
        if (!response.ok) {
          throw failure(reason || ("http:" + response.status),
            message || ("The helper refused that request (HTTP " + response.status + ")."));
        }
        if (data && data.status === "REFUSED") {
          throw failure(reason || "refused", message || "The helper refused that request.");
        }
        return data;
      });
    }, function (error) {
      throw failure("transport:unreachable",
        "This page could not reach the helper on this machine. " + String(error && error.message ? error.message : error));
    });
  }

  function isSessionError(error) {
    var reason = error && error.reason ? String(error.reason) : "";
    return reason.indexOf("session") === 0 || reason === "http:403";
  }

  /* ------------------------------------------------------------ banners */

  var banners = {};

  function showBanner(key, kind, titleText, bodyText, codeText) {
    var host = byId("banners");
    var node = el("div", "banner" + (kind === "error" ? " banner-error" : ""));
    attr(node, "role", kind === "error" ? "alert" : "status");
    var body = el("div", "banner-body");
    add(body, el("p", "banner-title", titleText));
    if (bodyText) { add(body, el("p", "banner-text", bodyText)); }
    if (codeText) { add(body, el("p", "banner-code", codeText)); }
    add(node, body);
    var dismiss = el("button", "btn btn-quiet", "Dismiss");
    attr(dismiss, "type", "button");
    dismiss.onclick = function () { clearBanner(key); };
    add(node, dismiss);
    if (banners[key] && banners[key].parentNode) {
      host.replaceChild(node, banners[key]);
    } else {
      add(host, node);
    }
    banners[key] = node;
  }

  function clearBanner(key) {
    var node = banners[key];
    if (node && node.parentNode) { node.parentNode.removeChild(node); }
    delete banners[key];
  }

  function announce(text) {
    byId("sr-status").textContent = text;
  }

  function showGate(titleText, bodyText) {
    sessionLost = true;
    document.body.setAttribute("data-gate", "on");
    var gate = byId("gate");
    byId("gate-title").textContent = titleText;
    byId("gate-text").textContent = bodyText;
    gate.hidden = false;
    announce(titleText);
  }

  function handleSessionLoss(error) {
    showGate(
      "This session has ended",
      textOf(error && error.text,
        "The helper refused this page's session key. Open the local view again from the chat.")
    );
  }

  /* ------------------------------------------------------------ store */

  var app = {
    view: "runs",
    state: null,
    stateJson: "",
    stateError: null,
    selectedRunId: null,
    run: null,
    runJson: "",
    runError: null,
    runLoading: false,
    onlineDiagram: null,
    onlineDiagramJson: "",
    onlineDiagramError: null,
    onlineDiagramLoading: false,
    open: {}
  };

  function rememberOpen(key, node) {
    node.open = app.open[key] === true;
    node.setAttribute("data-key", key);
    node.addEventListener("toggle", function () {
      app.open[key] = node.open;
    });
    return node;
  }

  function details(key, summaryText) {
    var node = el("details");
    add(node, el("summary", null, summaryText));
    return rememberOpen(key, node);
  }

  /* ------------------------------------------------------------ runs view */

  function runStateBadge(value) { return badge(value); }

  function renderRunsView() {
    var host = clear(byId("runs-body"));
    if (app.stateError && !app.state) {
      add(host, errorCard("Orch Dork could not read your records", app.stateError));
      return;
    }
    if (!app.state) {
      add(host, emptyState("Reading your records", "The page is asking the local helper for its records."));
      return;
    }
    var state = app.state;
    var runs = listOf(state.runs);

    if (state.status !== "PASS") {
      var warn = card("The helper reported a status other than PASS", null, "card-warn");
      add(warn, kv([
        ["Reported status", valueNode(state.status)],
        ["Schema", valueNode(state.schema)],
        ["Generation", valueNode(state.generation)]
      ]));
      add(warn, el("p", "hint",
        "Treat the rows below as incomplete until the helper reports PASS. Ask in the chat for the record."));
      add(host, warn);
    }

    var summary = card("This machine", null, "card-accent");
    add(summary, kv([
      ["Generation", valueNode(state.generation)],
      ["Records shown", valueNode(runs.length)],
      ["Projects enrolled", valueNode(listOf(state.projects).length)],
      ["Models known", valueNode(listOf(state.models).length)],
      ["Governed runs run in", valueNode(mapOf(state.v1).location ? label(mapOf(state.v1).location) : null)]
    ]));
    add(host, summary);

    if (!runs.length) {
      add(host, emptyState(
        "No runs recorded yet",
        "When Orch Dork runs work for you, each run appears here with its verdict, cost, and canonical digest. Runs start in the chat."
      ));
      return;
    }

    var runsCard = card("Past and current runs",
      "Click a run to open its plan-versus-actual view. Nothing here can change a run.");
    var built = table(
      "Runs the helper holds on this machine, newest first as the helper ordered them.",
      ["Run", "State", "Verdict", "Project", "Started", "Ended", "Cost", "Canonical digest", ""]
    );
    for (var i = 0; i < runs.length; i += 1) {
      var run = mapOf(runs[i]);
      var row = el("tr");
      add(row, cell(codeNode(run.run_id, "mono")));
      add(row, cell(runStateBadge(run.state)));
      add(row, cell(run.verdict));
      add(row, cell(run.project));
      add(row, cell(formatTime(run.started_at), "num"));
      add(row, cell(formatTime(run.ended_at), "num"));
      add(row, cell(formatCost(run.cost), "num"));
      var digest = el("td");
      if (hasText(run.canonical_digest)) {
        var code = el("code", "digest", shortDigest(run.canonical_digest));
        attr(code, "title", run.canonical_digest);
        add(digest, code);
      } else {
        add(digest, el("span", "unknown", "unknown"));
      }
      add(row, digest);
      var action = el("td");
      if (hasText(run.run_id)) {
        var open = el("button", "btn btn-quiet", "Open");
        attr(open, "type", "button");
        attr(open, "aria-label", "Open the view for run " + run.run_id);
        open.onclick = makeRunOpener(run.run_id);
        add(action, open);
      }
      add(row, action);
      add(built.body, row);
    }
    add(runsCard, built.wrap);
    add(host, runsCard);
  }

  function makeRunOpener(runId) {
    return function () { selectRun(runId); };
  }

  function errorCard(titleText, error) {
    var node = card(titleText, null, "card-alert");
    add(node, el("p", null, textOf(error && error.text, "The helper refused that request.")));
    add(node, el("p", "banner-code", "reason: " + textOf(error && error.reason, "unknown")));
    add(node, el("p", "hint",
      "The chat path is unaffected: ask Orch Dork in the chat for the same record."));
    return node;
  }

  /* ------------------------------------------------------------ graph */

  var NODE_W = 212;
  var NODE_H = 104;
  var COL_W = 268;
  var ROW_H = 126;
  var PAD = 20;

  function graphLayout(graph) {
    var nodes = listOf(graph.nodes);
    var edges = listOf(graph.edges);
    var root = mapOf(graph.root);
    var placed = [];
    var index = {};
    var i;

    for (i = 0; i < nodes.length; i += 1) {
      var node = mapOf(nodes[i]);
      var id = hasText(node.id) ? node.id : "node-" + (i + 1);
      var entry = {
        id: id,
        objective: node.objective,
        state: hasText(node.state) ? node.state : "unknown",
        planned_model: node.planned_model,
        observed_model: node.observed_model,
        evidence_class: hasText(node.evidence_class) ? node.evidence_class : "unknown",
        evidence_tier: node.evidence_tier,
        isRoot: hasText(root.id) && root.id === id,
        depth: null
      };
      if (!index[id]) {
        index[id] = entry;
        placed.push(entry);
      }
    }
    var rootEntry = hasText(root.id) ? index[root.id] : null;
    if (hasText(root.id) && !rootEntry) {
      rootEntry = {
        id: root.id,
        objective: null,
        state: "root",
        planned_model: root.planned_model,
        observed_model: root.observed_model,
        evidence_class: "unknown",
        evidence_tier: null,
        isRoot: true,
        synthetic: true,
        depth: 0
      };
      index[root.id] = rootEntry;
      placed.unshift(rootEntry);
    }
    if (rootEntry) { rootEntry.depth = 0; }

    var links = [];
    for (i = 0; i < edges.length; i += 1) {
      var edge = mapOf(edges[i]);
      links.push({
        id: hasText(edge.id) ? edge.id : "edge-" + (i + 1),
        from: edge.from,
        to: edge.to,
        state: hasText(edge.state) ? edge.state : "unknown",
        evidence_class: hasText(edge.evidence_class) ? edge.evidence_class : "unknown",
        evidence_tier: edge.evidence_tier,
        source: hasText(edge.from) && index[edge.from] ? index[edge.from] : null,
        target: hasText(edge.to) && index[edge.to] ? index[edge.to] : null
      });
    }

    var rounds = placed.length + 1;

    function relax() {
      for (var pass = 0; pass < rounds; pass += 1) {
        var moved = false;
        for (var k = 0; k < links.length; k += 1) {
          var link = links[k];
          if (!link.source || !link.target || link.source.depth === null) { continue; }
          var want = link.source.depth + 1;
          if (link.target.depth === null || link.target.depth < want) {
            link.target.depth = want;
            moved = true;
          }
        }
        if (!moved) { return; }
      }
    }

    function deepest() {
      var best = -1;
      for (var k = 0; k < placed.length; k += 1) {
        if (placed[k].depth !== null && placed[k].depth > best) { best = placed[k].depth; }
      }
      return best;
    }

    // A node the root cannot reach still deserves its own column run, so an
    // unrooted branch is seeded one column past everything placed so far and
    // then relaxed like any other branch.
    relax();
    var orphans = 0;
    for (var guard = 0; guard <= placed.length; guard += 1) {
      var pending = [];
      for (i = 0; i < placed.length; i += 1) {
        if (placed[i].depth === null) { pending.push(placed[i]); }
      }
      if (!pending.length) { break; }
      var fed = {};
      for (i = 0; i < links.length; i += 1) {
        if (links[i].source && links[i].target && links[i].source !== links[i].target
          && links[i].source.depth === null && links[i].target.depth === null) {
          fed[links[i].target.id] = true;
        }
      }
      var seeds = [];
      for (i = 0; i < pending.length; i += 1) {
        if (!fed[pending[i].id]) { seeds.push(pending[i]); }
      }
      if (!seeds.length) { seeds = [pending[0]]; }
      var base = deepest() + 1;
      for (i = 0; i < seeds.length; i += 1) {
        seeds[i].depth = base;
        orphans += 1;
      }
      relax();
    }

    // Reachability is answered from the edges themselves, so "no path from the
    // root" is a fact about the record rather than a side effect of layout.
    var reachable = {};
    if (rootEntry) {
      var queue = [rootEntry.id];
      reachable[rootEntry.id] = true;
      while (queue.length) {
        var at = queue.shift();
        for (i = 0; i < links.length; i += 1) {
          if (links[i].from === at && links[i].target && !reachable[links[i].target.id]) {
            reachable[links[i].target.id] = true;
            queue.push(links[i].target.id);
          }
        }
      }
    }
    for (i = 0; i < placed.length; i += 1) {
      placed[i].unlinked = !reachable[placed[i].id];
    }

    var columns = {};
    var columnCount = 0;
    var rowMax = 0;
    for (i = 0; i < placed.length; i += 1) {
      var depth = placed[i].depth;
      if (columns[depth] === undefined) { columns[depth] = 0; columnCount += 1; }
      placed[i].row = columns[depth];
      columns[depth] += 1;
      if (columns[depth] > rowMax) { rowMax = columns[depth]; }
      placed[i].x = PAD + depth * COL_W;
      placed[i].y = PAD + placed[i].row * ROW_H;
    }
    var width = NODE_W + PAD * 2;
    var height = NODE_H + PAD * 2;
    for (i = 0; i < placed.length; i += 1) {
      var right = placed[i].x + NODE_W + PAD;
      var bottom = placed[i].y + NODE_H + PAD;
      if (right > width) { width = right; }
      if (bottom > height) { height = bottom; }
    }

    return {
      nodes: placed,
      links: links,
      width: width,
      height: height,
      orphans: orphans,
      root: rootEntry
    };
  }

  function drawNode(parent, node) {
    var group = svgEl("g", "gnode" + (node.isRoot ? " gnode-root" : ""));
    var title = svgEl("title");
    title.textContent = node.id + " - " + label(node.state) + " - evidence " + label(node.evidence_class)
      + (hasText(node.objective) ? " - " + node.objective : "");
    add(group, title);

    var box = svgEl("rect", "gnode-box gstate-" + node.state + " gclass-" + node.evidence_class);
    box.setAttribute("x", String(node.x));
    box.setAttribute("y", String(node.y));
    box.setAttribute("width", String(NODE_W));
    box.setAttribute("height", String(NODE_H));
    box.setAttribute("rx", "8");
    add(group, box);

    var bar = svgEl("rect", "gnode-bar gfill-" + node.state);
    bar.setAttribute("x", String(node.x + 1));
    bar.setAttribute("y", String(node.y + 1));
    bar.setAttribute("width", String(NODE_W - 2));
    bar.setAttribute("height", "5");
    add(group, bar);

    add(group, svgText(node.x + 12, node.y + 23, "gnode-id",
      (node.isRoot ? "\u2605 " : "") + clip(node.id, 24)));
    add(group, svgText(node.x + 12, node.y + 39, "gnode-state gfill-" + node.state,
      node.state === "root" ? "ROOT" : label(node.state).toUpperCase()));
    add(group, svgText(node.x + 12, node.y + 54, "gnode-line",
      hasText(node.objective) ? clip(node.objective, 34) : "no objective recorded"));
    add(group, svgText(node.x + 12, node.y + 68, "gnode-line",
      "plan: " + clip(textOf(node.planned_model), 28)));
    add(group, svgText(node.x + 12, node.y + 82, "gnode-line",
      "ran: " + clip(textOf(node.observed_model), 28)));
    add(group, svgText(node.x + 12, node.y + 96, "gnode-evidence",
      (CLASS_GLYPH[node.evidence_class] || "?") + " " + label(node.evidence_class)
        + " / " + textOf(node.evidence_tier)));
    add(parent, group);
  }

  function drawEdge(parent, link) {
    if (!link.source || !link.target) { return; }
    var group = svgEl("g", "gedge-group");
    var title = svgEl("title");
    title.textContent = link.id + ": " + textOf(link.from) + " to " + textOf(link.to)
      + " - " + label(link.state) + " - evidence " + label(link.evidence_class)
      + " / " + textOf(link.evidence_tier);
    add(group, title);

    var x1 = link.source.x + NODE_W;
    var y1 = link.source.y + NODE_H / 2;
    var x2 = link.target.x;
    var y2 = link.target.y + NODE_H / 2;
    var path = svgEl("path", "gedge gstate-" + link.state + " gclass-" + link.evidence_class);
    path.setAttribute("d",
      "M " + x1 + " " + y1 + " C " + (x1 + 58) + " " + y1 + ", " + (x2 - 58) + " " + y2 + ", " + x2 + " " + y2);
    add(group, path);

    var head = svgEl("polygon", "gfill-" + link.state);
    head.setAttribute("points",
      x2 + "," + y2 + " " + (x2 - 9) + "," + (y2 - 4.5) + " " + (x2 - 9) + "," + (y2 + 4.5));
    add(group, head);

    var text = (CLASS_GLYPH[link.evidence_class] || "?") + " " + label(link.state);
    var midX = (x1 + x2) / 2;
    var midY = (y1 + y2) / 2 - 7;
    var box = svgEl("rect", "gedge-label-bg");
    box.setAttribute("x", String(midX - (text.length * 2.7) - 3));
    box.setAttribute("y", String(midY - 9));
    box.setAttribute("width", String(text.length * 5.4 + 6));
    box.setAttribute("height", "12");
    box.setAttribute("rx", "3");
    add(group, box);
    var textNode = svgText(midX, midY, "gedge-label", text);
    textNode.setAttribute("text-anchor", "middle");
    add(group, textNode);
    add(parent, group);
  }

  function buildDiagram(layout, graph) {
    var frame = el("div", "graph-frame");
    var scroll = el("div", "graph-scroll");
    attr(scroll, "tabindex", "0");
    attr(scroll, "role", "group");
    attr(scroll, "aria-label", "Run graph. Scroll sideways to follow the lanes, or read the tables below.");
    var svg = svgEl("svg", "graph-svg");
    svg.setAttribute("viewBox", "0 0 " + layout.width + " " + layout.height);
    // The drawing keeps its natural size and the frame scrolls, so a wide run
    // never shrinks its own labels to the point of being unreadable.
    svg.setAttribute("width", String(layout.width));
    svg.setAttribute("height", String(layout.height));
    svg.setAttribute("preserveAspectRatio", "xMinYMin meet");
    svg.setAttribute("role", "img");
    svg.setAttribute("focusable", "false");
    var counts = countStates(layout);
    svg.setAttribute("aria-label",
      "Plan and actual graph: " + layout.nodes.length + " nodes and " + layout.links.length
      + " edges. " + counts.sentence + " The tables below carry the same facts in text.");
    var title = svgEl("title");
    title.textContent = "Orch Dork run graph";
    add(svg, title);
    var desc = svgEl("desc");
    desc.textContent = counts.sentence
      + " Canonical digest " + textOf(graph.canonical_digest) + ".";
    add(svg, desc);

    var edgeLayer = svgEl("g", "gedges");
    var nodeLayer = svgEl("g", "gnodes");
    var i;
    for (i = 0; i < layout.links.length; i += 1) { drawEdge(edgeLayer, layout.links[i]); }
    for (i = 0; i < layout.nodes.length; i += 1) { drawNode(nodeLayer, layout.nodes[i]); }
    add(svg, edgeLayer);
    add(svg, nodeLayer);
    add(scroll, svg);
    add(frame, scroll);
    return frame;
  }

  function countStates(layout) {
    var tally = {};
    var i;
    for (i = 0; i < layout.nodes.length; i += 1) {
      var state = layout.nodes[i].state;
      tally[state] = (tally[state] || 0) + 1;
    }
    var parts = [];
    var names = keysOf(tally);
    for (i = 0; i < names.length; i += 1) {
      parts.push(tally[names[i]] + " " + label(names[i]).toLowerCase());
    }
    return {
      tally: tally,
      sentence: parts.length ? "Node states: " + parts.join(", ") + "." : "No nodes recorded."
    };
  }

  function legendSample(className) {
    var svg = svgEl("svg", "legend-sample");
    svg.setAttribute("viewBox", "0 0 34 8");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    var line = svgEl("path", "gedge gstate-observed gclass-" + className);
    line.setAttribute("d", "M 1 4 L 33 4");
    add(svg, line);
    return svg;
  }

  function legendBlock(titleText, rows, kind) {
    var block = el("div");
    add(block, el("h3", null, titleText));
    var list = el("ul");
    for (var i = 0; i < rows.length; i += 1) {
      var name = rows[i][0];
      var item = el("li");
      var key = el("span", "legend-key");
      if (kind === "class") {
        add(key, legendSample(name));
        add(key, evidenceBadge(name));
      } else if (kind === "tier") {
        add(key, el("span", "badge", label(name)));
      } else {
        add(key, badge(name));
      }
      add(item, key);
      add(item, el("span", "legend-text", rows[i][1]));
      add(list, item);
    }
    add(block, list);
    return block;
  }

  function pairs(names, textMap) {
    var rows = [];
    for (var i = 0; i < names.length; i += 1) {
      rows.push([names[i], textMap[names[i]] || ""]);
    }
    return rows;
  }

  function buildLegend() {
    var legend = el("div", "legend");
    add(legend, legendBlock("Node states (all of them)", pairs(NODE_STATES, NODE_STATE_TEXT), "state"));
    add(legend, legendBlock("Edge states", pairs(EDGE_STATES, EDGE_STATE_TEXT), "state"));
    add(legend, legendBlock("Evidence class (line and glyph)", pairs(EVIDENCE_CLASSES, CLASS_TEXT), "class"));
    add(legend, legendBlock("Evidence tier", pairs(EVIDENCE_TIERS, TIER_TEXT), "tier"));
    return legend;
  }

  function nodeKind(state) {
    return state === "planned" ? "planned only" : (state === "root" ? "root" : "observed");
  }

  function modelMatch(node) {
    if (!hasText(node.planned_model) && !hasText(node.observed_model)) {
      return el("span", "unknown", "unknown");
    }
    if (!hasText(node.observed_model)) {
      var pending = el("span", "badge badge-warn");
      add(pending, document.createTextNode("nothing ran yet"));
      return pending;
    }
    if (!hasText(node.planned_model)) {
      return el("span", "unknown", "no planned model recorded");
    }
    if (node.planned_model === node.observed_model) {
      var same = el("span", "badge badge-ok");
      add(same, document.createTextNode("as planned"));
      return same;
    }
    var differs = el("span", "badge badge-alert");
    add(differs, document.createTextNode("differs"));
    return differs;
  }

  function nodesTable(layout) {
    var built = table(
      "Every node in the projection: its state, the model the plan named, the model that actually ran, and how the evidence was obtained.",
      ["Node", "Kind", "State", "Objective", "Planned model", "Observed model", "Model", "Evidence", "Evidence tier"]
    );
    for (var i = 0; i < layout.nodes.length; i += 1) {
      var node = layout.nodes[i];
      var row = el("tr");
      add(row, cell(codeNode(node.id, "mono")));
      add(row, cell(nodeKind(node.state) + (node.unlinked ? ", no path from the root" : "")));
      add(row, cell(node.state === "root" ? el("span", "badge", "Root") : badge(node.state)));
      add(row, cell(node.objective));
      add(row, cell(node.planned_model));
      add(row, cell(node.observed_model));
      add(row, cell(modelMatch(node)));
      add(row, cell(evidenceBadge(node.evidence_class)));
      add(row, cell(node.evidence_tier));
      add(built.body, row);
    }
    return built.wrap;
  }

  function edgesTable(layout) {
    var built = table(
      "Every edge in the projection, with planned edges kept alongside observed ones.",
      ["Edge", "From", "To", "Kind", "State", "Evidence", "Evidence tier", "Endpoints"]
    );
    for (var i = 0; i < layout.links.length; i += 1) {
      var link = layout.links[i];
      var row = el("tr");
      add(row, cell(codeNode(link.id, "mono")));
      add(row, cell(codeNode(link.from, "mono")));
      add(row, cell(codeNode(link.to, "mono")));
      add(row, cell(link.state === "planned" ? "planned only" : "observed"));
      add(row, cell(badge(link.state)));
      add(row, cell(evidenceBadge(link.evidence_class)));
      add(row, cell(link.evidence_tier));
      add(row, cell(link.source && link.target
        ? "both in the projection"
        : el("span", "unknown", "an endpoint is missing from the node list")));
      add(built.body, row);
    }
    return built.wrap;
  }

  function planVersusActual(layout, graph) {
    var node = card("Plan versus actual",
      "Planned nodes and edges are kept, not replaced, so the difference stays visible.");
    var plannedNodes = [];
    var observedNodes = [];
    var drift = [];
    var unlinked = [];
    var i;
    for (i = 0; i < layout.nodes.length; i += 1) {
      var entry = layout.nodes[i];
      if (entry.state === "planned") { plannedNodes.push(entry.id); } else if (entry.state !== "root") { observedNodes.push(entry.id); }
      if (hasText(entry.planned_model) && hasText(entry.observed_model) && entry.planned_model !== entry.observed_model) {
        drift.push(entry.id + ": plan " + entry.planned_model + ", ran " + entry.observed_model);
      }
      if (entry.unlinked) { unlinked.push(entry.id); }
    }
    var plannedEdges = [];
    var observedEdges = [];
    for (i = 0; i < layout.links.length; i += 1) {
      if (layout.links[i].state === "planned") {
        plannedEdges.push(layout.links[i].id);
      } else {
        observedEdges.push(layout.links[i].id);
      }
    }
    var root = layout.root;
    add(node, kv([
      ["Nodes still planned only", valueNode(plannedNodes.length)],
      ["Nodes with an observed state", valueNode(observedNodes.length)],
      ["Edges still planned only", valueNode(plannedEdges.length)],
      ["Edges observed", valueNode(observedEdges.length)],
      ["Root planned model", root ? valueNode(root.planned_model) : el("span", "unknown", "no root recorded")],
      ["Root observed model", root ? valueNode(root.observed_model) : el("span", "unknown", "no root recorded")],
      ["Graph canonical digest", codeNode(graph.canonical_digest)],
      ["Graph evidence tier", valueNode(graph.evidence_tier)]
    ]));
    var drifted = details("plan-drift", "Model differences between plan and run (" + drift.length + ")");
    add(drifted, bulletList(drift, "No node recorded a model different from the one the plan named."));
    add(node, drifted);
    if (unlinked.length) {
      var stray = details("plan-unlinked", "Nodes with no path from the root (" + unlinked.length + ")");
      add(stray, bulletList(unlinked, ""));
      add(node, stray);
    }
    return node;
  }

  function findingsCard(run, graph) {
    var issues = listOf(run.issues).concat(listOf(graph.issues));
    var unknowns = listOf(run.unknowns).concat(listOf(graph.unknowns));
    var contradictions = listOf(graph.contradictions);
    var node = card("Issues, unknowns, and contradictions",
      "Nothing here is filled in by the page. An empty list means the record held none.");
    var issuesBlock = el("div");
    add(issuesBlock, el("h3", null, "Issues (" + issues.length + ")"));
    add(issuesBlock, bulletList(issues, "The record listed no issues."));
    var unknownBlock = el("div");
    add(unknownBlock, el("h3", null, "Unknowns (" + unknowns.length + ")"));
    add(unknownBlock, bulletList(unknowns, "The record listed no unknowns."));
    var contraBlock = el("div");
    add(contraBlock, el("h3", null, "Contradictions (" + contradictions.length + ")"));
    add(contraBlock, bulletList(contradictions, "The record listed no contradictions."));
    var grid = el("div", "grid");
    add(grid, issuesBlock, unknownBlock, contraBlock);
    add(node, grid);
    return node;
  }

  function runText(run, graph, layout) {
    var lines = [];
    var i;
    lines.push("ORCH DORK RUN - TEXT VERSION");
    lines.push("This block holds every fact the graph above shows.");
    lines.push("");
    lines.push("Run id:            " + textOf(run.run_id));
    lines.push("State:             " + textOf(run.state));
    lines.push("Verdict:           " + textOf(run.verdict));
    lines.push("Reason:            " + textOf(run.reason));
    lines.push("You steered it:    " + textOf(run.steered_by_you));
    lines.push("Revision:          " + textOf(run.revision));
    lines.push("Cost:              " + textOf(formatCost(run.cost)));
    lines.push("Runs in:           " + textOf(run.location));
    lines.push("Canonical digest:  " + textOf(run.canonical_digest));
    lines.push("Evidence tier:     " + textOf(run.evidence_tier));
    lines.push("");
    lines.push("GRAPH");
    lines.push("Canonical digest:  " + textOf(graph.canonical_digest));
    lines.push("Evidence tier:     " + textOf(graph.evidence_tier));
    var root = mapOf(graph.root);
    lines.push("Root:              " + textOf(root.id)
      + "  plan: " + textOf(root.planned_model) + "  ran: " + textOf(root.observed_model));
    lines.push("");
    lines.push("NODES (" + layout.nodes.length + ")");
    lines.push("  id | kind | state | planned model | observed model | evidence class | evidence tier | objective");
    for (i = 0; i < layout.nodes.length; i += 1) {
      var node = layout.nodes[i];
      lines.push("  " + [
        textOf(node.id),
        nodeKind(node.state) + (node.unlinked ? ", no path from root" : ""),
        textOf(node.state),
        textOf(node.planned_model),
        textOf(node.observed_model),
        textOf(node.evidence_class),
        textOf(node.evidence_tier),
        textOf(node.objective)
      ].join(" | "));
    }
    lines.push("");
    lines.push("EDGES (" + layout.links.length + ")");
    lines.push("  id | from | to | kind | state | evidence class | evidence tier");
    for (i = 0; i < layout.links.length; i += 1) {
      var link = layout.links[i];
      lines.push("  " + [
        textOf(link.id),
        textOf(link.from),
        textOf(link.to),
        link.state === "planned" ? "planned only" : "observed",
        textOf(link.state),
        textOf(link.evidence_class),
        textOf(link.evidence_tier)
      ].join(" | "));
    }
    lines.push("");
    lines.push("ISSUES (" + (listOf(run.issues).length + listOf(graph.issues).length) + ")");
    var issues = listOf(run.issues).concat(listOf(graph.issues));
    if (!issues.length) { lines.push("  none recorded"); }
    for (i = 0; i < issues.length; i += 1) { lines.push("  - " + String(issues[i])); }
    lines.push("");
    lines.push("UNKNOWNS (" + (listOf(run.unknowns).length + listOf(graph.unknowns).length) + ")");
    var unknowns = listOf(run.unknowns).concat(listOf(graph.unknowns));
    if (!unknowns.length) { lines.push("  none recorded"); }
    for (i = 0; i < unknowns.length; i += 1) { lines.push("  - " + String(unknowns[i])); }
    lines.push("");
    lines.push("CONTRADICTIONS (" + listOf(graph.contradictions).length + ")");
    var contradictions = listOf(graph.contradictions);
    if (!contradictions.length) { lines.push("  none recorded"); }
    for (i = 0; i < contradictions.length; i += 1) { lines.push("  - " + String(contradictions[i])); }
    lines.push("");
    lines.push("RAW EVIDENCE");
    lines.push("  " + textOf(graph.raw_evidence));
    lines.push("  The raw evidence bundle is the authority wherever sources disagree.");
    lines.push("");
    lines.push("LEGEND");
    lines.push("  Node states:");
    for (i = 0; i < NODE_STATES.length; i += 1) {
      lines.push("    " + NODE_STATES[i] + " - " + NODE_STATE_TEXT[NODE_STATES[i]]);
    }
    lines.push("  Edge states:");
    for (i = 0; i < EDGE_STATES.length; i += 1) {
      lines.push("    " + EDGE_STATES[i] + " - " + EDGE_STATE_TEXT[EDGE_STATES[i]]);
    }
    lines.push("  Evidence classes:");
    for (i = 0; i < EVIDENCE_CLASSES.length; i += 1) {
      lines.push("    " + CLASS_GLYPH[EVIDENCE_CLASSES[i]] + " " + EVIDENCE_CLASSES[i]
        + " - " + CLASS_TEXT[EVIDENCE_CLASSES[i]]);
    }
    lines.push("  Evidence tiers:");
    for (i = 0; i < EVIDENCE_TIERS.length; i += 1) {
      lines.push("    " + EVIDENCE_TIERS[i] + " - " + TIER_TEXT[EVIDENCE_TIERS[i]]);
    }
    lines.push("");
    lines.push("This view is one-way. Stopping, approving, steering, and revising a run stay in the chat.");
    return lines.join("\n");
  }

  function fallbackCard(run, graph, layout) {
    var node = card("Text version",
      "The complete projection as text, with the canonical digest, issues, unknowns, evidence tiers, and the legend.");
    node.className += " fallback";
    var holder = details("run-text", "Show the text version");
    var pre = el("pre");
    pre.textContent = runText(run, graph, layout);
    attr(pre, "tabindex", "0");
    var row = el("div", "btn-row");
    var copy = el("button", "btn", "Copy the text version");
    attr(copy, "type", "button");
    copy.onclick = function () { copyText(pre.textContent, copy); };
    add(row, copy);
    add(holder, row);
    add(holder, pre);
    add(node, holder);
    return node;
  }

  function copyText(text, button) {
    var done = function (ok) {
      button.textContent = ok ? "Copied" : "Select the text and copy it";
      window.setTimeout(function () { button.textContent = "Copy the text version"; }, 4000);
    };
    if (window.navigator && window.navigator.clipboard && window.navigator.clipboard.writeText) {
      window.navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
      return;
    }
    done(false);
  }

  function renderRunView() {
    var host = clear(byId("run-body"));
    if (!app.selectedRunId) {
      add(host, emptyState(
        "No run selected",
        "Open a run from the Runs view to see its plan, what actually happened, and the evidence behind each claim."
      ));
      return;
    }
    if (app.runError && !app.run) {
      add(host, errorCard("Orch Dork could not read run " + app.selectedRunId, app.runError));
      return;
    }
    if (!app.run) {
      add(host, emptyState("Reading run " + app.selectedRunId, "The page is asking the local helper for this run."));
      return;
    }
    var run = mapOf(app.run);
    var graph = mapOf(run.graph);
    var layout = graphLayout(graph);

    var head = card("Run " + textOf(run.run_id), null, "card-accent");
    add(head, kv([
      ["State", badge(run.state)],
      ["Verdict", valueNode(run.verdict)],
      ["Reason", valueNode(run.reason)],
      ["You steered it", valueNode(run.steered_by_you)],
      ["Revision", valueNode(run.revision)],
      ["Cost", valueNode(formatCost(run.cost))],
      ["Runs in", valueNode(hasText(run.location) ? label(run.location) : null)],
      ["Evidence tier", valueNode(run.evidence_tier)],
      ["Canonical digest", codeNode(run.canonical_digest)]
    ]));
    add(head, el("p", "hint",
      "This view is one-way. To stop, approve, steer, or revise this run, use the chat."));
    add(host, head);

    if (hasText(run.canonical_digest) && hasText(graph.canonical_digest)
      && run.canonical_digest !== graph.canonical_digest) {
      var mismatch = card("The run record and its graph report different canonical digests", null, "card-alert");
      add(mismatch, kv([
        ["Run canonical digest", codeNode(run.canonical_digest)],
        ["Graph canonical digest", codeNode(graph.canonical_digest)]
      ]));
      add(mismatch, el("p", null,
        "The page shows both and settles neither. The raw evidence bundle is the authority."));
      add(host, mismatch);
    }

    var diagram = card("Plan and actual graph",
      "Every state, and how each fact was obtained, with planned nodes and edges kept beside observed ones.");
    if (layout.nodes.length) {
      add(diagram, buildDiagram(layout, graph));
    } else {
      add(diagram, emptyState("This projection holds no nodes yet",
        "The record carries no node for this run so far. The digest and findings below still come from the record."));
    }
    add(diagram, kv([
      ["Canonical digest", codeNode(graph.canonical_digest)],
      ["Evidence tier", valueNode(graph.evidence_tier)],
      ["Nodes", valueNode(layout.nodes.length)],
      ["Edges", valueNode(layout.links.length)]
    ]));
    var legendHolder = details("run-legend", "Legend: states, evidence classes, and evidence tiers");
    add(legendHolder, buildLegend());
    add(diagram, legendHolder);
    var nodesHolder = details("run-nodes", "Node table (" + layout.nodes.length + ")");
    add(nodesHolder, nodesTable(layout));
    add(diagram, nodesHolder);
    var edgesHolder = details("run-edges", "Edge table (" + layout.links.length + ")");
    add(edgesHolder, edgesTable(layout));
    add(diagram, edgesHolder);
    add(host, diagram);

    add(host, planVersusActual(layout, graph));
    add(host, findingsCard(run, graph));

    add(host, shareSection(run, app.onlineDiagram, app.onlineDiagramError));

    var raw = card("Raw evidence", null, "card-sunk");
    add(raw, kv([["Bundle", valueNode(graph.raw_evidence)]]));
    add(raw, el("p", "hint",
      "The raw evidence bundle stays on this machine and is the authority wherever this view and a report disagree."));
    add(host, raw);

    add(host, fallbackCard(run, graph, layout));
  }

  /* ------------------------------------------------------------ share */

  var SHARE_INCLUDED = [
    "The diagram shape: the root, every lane with its state, evidence class and planned or observed model.",
    "The cost row per role with token counts and a labeled token estimate; billing and actual cost read unknown.",
    "The verdict, state and revision, plus a count of issues, unknowns and contradictions.",
    "The record digest; a hash that names which run is on display, not its content."
  ];
  var SHARE_EXCLUDED = [
    "Code, prompts, file paths, project names, objectives, reasons, host paths, run / task / lane identifiers, plan and free text.",
    "Any data the chat or chat-owned tools can read; the helper copy is a one-way projection from records this page already holds."
  ];

  function shareSection(run, offer, error) {
    var panel = card("Share outside this machine",
      "A sanitized copy of this view opens on the Site you publish. Sign in there, click Save to keep it. Nothing leaves this machine until you click a link.",
      "card-share");
    var rows = [
      ["The copy includes", bulletList(SHARE_INCLUDED, "")],
      ["The copy excludes", bulletList(SHARE_EXCLUDED, "")]
    ];
    add(panel, kv(rows));
    if (error) {
      add(panel, el("p", "field-error",
        "Orch Dork could not build a shareable copy for this view: " + textOf(error.text, "the helper refused this run.")));
      return panel;
    }
    if (!offer) {
      add(panel, emptyState("Building the shareable copy",
        "The page is asking the local helper to sanitize this view. Nothing leaves this machine."));
      return panel;
    }
    var payload = mapOf(offer);
    var diagram = mapOf(payload.diagram);
    var rows2 = [
      ["Diagram digest", codeNode(textOf(diagram.source_digest), "digest digest-short")],
      ["Size", valueNode(payload.bytes + " bytes")],
      ["Filename", codeNode(textOf(payload.file_name), "digest")]
    ];
    add(panel, kv(rows2));
    var controls = el("div", "btn-row share-controls");
    add(controls, saveFileButton(payload));
    var site = payload.site;
    if (typeof payload.link === "string" && payload.link.length > 0) {
      add(controls, viewOnlineAnchor(payload));
    } else if (typeof site === "string" && site.length > 0) {
      var note = el("p", "hint",
        "The diagram is larger than one URL fragment; the Site is published, but the link form cannot carry it. Save the file below and upload it on the Site once you sign in.");
      add(panel, note);
    } else {
      var note = el("p", "hint",
        "Online history is not published yet. Save the file below and re-open this page after the Site is published to gain a link.");
      add(panel, note);
    }
    add(panel, controls);
    return panel;
  }

  function viewOnlineAnchor(payload) {
    var anchor = el("a", "btn", "View online");
    // An anchor has no element type; the link is a navigation.
    attr(anchor, "href", String(payload.link || ""));
    attr(anchor, "target", "_blank");
    attr(anchor, "rel", "noopener noreferrer");
    attr(anchor, "referrerpolicy", "no-referrer");
    attr(anchor, "data-role", "view-online");
    return anchor;
  }

  function saveFileButton(payload) {
    var button = el("button", "btn btn-primary", "Save diagram file");
    attr(button, "type", "button");
    attr(button, "data-role", "save-diagram");
    button.onclick = function () { downloadDiagram(payload, button); };
    return button;
  }

  function downloadDiagram(payload, button) {
    var json = decodeDiagram(payload);
    if (json === null) { return; }
    // Blob URLs are same-origin to this page, so the packaged CSP admits the
    // download click; the hidden anchor carries the filename.
    var blob = new Blob([json], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var link = el("a");
    attr(link, "href", url);
    attr(link, "download", String(payload.file_name || "orch-dork-diagram.json"));
    document.body.appendChild(link);
    link.click();
    setTimeout(function () {
      URL.revokeObjectURL(url);
      if (link.parentNode) { link.parentNode.removeChild(link); }
    }, 1000);
    if (button) {
      var saved = button.textContent;
      button.textContent = "Saved " + String(payload.file_name || "");
      setTimeout(function () { button.textContent = saved; }, 4000);
    }
  }


  function decodeDiagram(payload) {
    try {
      // atob() accepts unpadded base64url; the canonical JSON is ASCII.
      var raw = String(payload.payload || "");
      var b64 = raw.replace(/-/g, "+").replace(/_/g, "/");
      return window.atob(b64);
    } catch (err) {
      return null;
    }
  }

  function refreshOnlineDiagram() {
    if (sessionLost || !app.selectedRunId) { return Promise.resolve(); }
    var wanted = app.selectedRunId;
    return request("/api/online-diagram?run_id=" + encodeURIComponent(wanted)).then(function (data) {
      if (app.selectedRunId !== wanted) { return; }
      var offer = mapOf(data);
      var json = JSON.stringify(offer);
      app.onlineDiagramError = null;
      clearBanner("online-diagram");
      if (json !== app.onlineDiagramJson) {
        app.onlineDiagramJson = json;
        app.onlineDiagram = offer;
        if (app.view === "run") { renderRunView(); }
      }
    }, function (error) {
      if (app.selectedRunId !== wanted) { return; }
      if (isSessionError(error)) { handleSessionLoss(error); return; }
      app.onlineDiagramError = error;
      if (!app.onlineDiagram && app.view === "run") { renderRunView(); }
    });
  }

  /* ------------------------------------------------------------ values tree */

  function valueTree(value) {
    if (value === null || value === undefined) { return el("span", "unknown", "unknown"); }
    if (typeof value !== "object") { return document.createTextNode(String(value)); }
    if (Object.prototype.toString.call(value) === "[object Array]") {
      if (!value.length) { return el("span", "unknown", "empty list"); }
      var list = el("ul");
      for (var i = 0; i < value.length; i += 1) {
        add(list, add(el("li"), valueTree(value[i])));
      }
      return list;
    }
    var names = keysOf(value);
    if (!names.length) { return el("span", "unknown", "no fields"); }
    var rows = [];
    for (var j = 0; j < names.length; j += 1) {
      rows.push([names[j], valueTree(value[names[j]])]);
    }
    return kv(rows);
  }

  function splitArgv(text) {
    var out = [];
    var current = "";
    var quote = null;
    var started = false;
    for (var i = 0; i < text.length; i += 1) {
      var ch = text.charAt(i);
      if (quote) {
        if (ch === quote) { quote = null; } else { current += ch; }
        continue;
      }
      if (ch === "\"" || ch === "'") { quote = ch; started = true; continue; }
      if (ch === " " || ch === "\t") {
        if (started) { out.push(current); current = ""; started = false; }
        continue;
      }
      current += ch;
      started = true;
    }
    if (started) { out.push(current); }
    return out;
  }

  function joinArgv(argv) {
    var parts = listOf(argv);
    var out = [];
    for (var i = 0; i < parts.length; i += 1) {
      var token = String(parts[i]);
      out.push(token.indexOf(" ") < 0 ? token : "\"" + token + "\"");
    }
    return out.join(" ");
  }

  function dollars(value) {
    if (typeof value === "number" && isFinite(value)) { return value; }
    if (!hasText(value)) { return null; }
    var cleaned = value.replace(/[^0-9.]/g, "");
    var number = Number(cleaned);
    return isFinite(number) && cleaned !== "" ? number : null;
  }

  /* ------------------------------------------------------------ setup */

  var setup = {
    stage: "none",
    projectRoot: "",
    proposal: null,
    result: null,
    error: null,
    busy: false,
    custom: false,
    checkRows: null,
    renderedKey: "",
    projectsJson: ""
  };

  function checksTable(rows, sourceText) {
    var built = table(sourceText, ["Check", "Command", "Timeout (seconds)"]);
    var list = listOf(rows);
    for (var i = 0; i < list.length; i += 1) {
      var row = mapOf(list[i]);
      var tr = el("tr");
      add(tr, cell(codeNode(row.id, "mono")));
      add(tr, cell(codeNode(joinArgv(row.argv), "mono")));
      add(tr, cell(row.timeout_seconds, "num"));
      add(built.body, tr);
    }
    if (!list.length) {
      var none = el("tr");
      var td = el("td");
      attr(td, "colspan", "3");
      add(td, el("span", "unknown", "no checks recorded"));
      add(none, td);
      add(built.body, none);
    }
    return built.wrap;
  }

  function projectCard(project) {
    var root = textOf(project.project_root, "unknown project");
    var node = card(root, null, "card-sunk");
    var models = mapOf(project.models);
    add(node, kv([
      ["Model you chat with", valueNode(models.chat_model)],
      ["Second model", valueNode(models.second_model)],
      ["Keep on this machine", valueNode(project.keep_local)],
      ["Workers at once", valueNode(project.workers_max)],
      ["Per-run limit", valueNode(project.per_run_cost)],
      ["Daily limit", valueNode(project.daily_cost)],
      ["Approve every run", valueNode(project.per_run_approval)],
      ["Workflow profiles allowed", listOf(project.allowed_workflow_profiles).length
        ? document.createTextNode(listOf(project.allowed_workflow_profiles).join(", "))
        : el("span", "unknown", "none recorded")],
      ["Enrollment record", codeNode(project.record_sha256)]
    ]));
    var checksHolder = details("project-checks-" + root, "Checks this project runs ("
      + listOf(project.checks).length + ")");
    add(checksHolder, checksTable(project.checks, "The checks recorded in this project's enrollment."));
    add(node, checksHolder);
    var row = el("div", "btn-row");
    var edit = el("button", "btn", "Edit settings");
    attr(edit, "type", "button");
    attr(edit, "aria-label", "Edit settings for " + root);
    edit.onclick = function () { startProposal(project.project_root); };
    add(row, edit);
    add(node, row);
    return node;
  }

  function renderSetupProjects(force) {
    var host = byId("setup-projects");
    var projects = app.state ? listOf(app.state.projects) : [];
    var json = JSON.stringify(projects);
    if (!force && json === setup.projectsJson) { return; }
    setup.projectsJson = json;

    var input = byId("new-project-root");
    var keptValue = input ? input.value : setup.projectRoot;
    var hadFocus = input && document.activeElement === input;

    clear(host);
    if (!app.state) {
      add(host, emptyState("Reading your records", "The page is asking the local helper for its records."));
      return;
    }
    if (!projects.length) {
      add(host, emptyState(
        "No project is enrolled yet",
        "Name a project directory below and Orch Dork will inspect it, show what it found, and ask before it writes anything."
      ));
    } else {
      var list = card("Enrolled projects",
        "These settings govern later runs. An active run keeps its frozen settings, but saving changes can prevent it from accepting a revision. Finish it first if you expect to revise it.");
      for (var i = 0; i < projects.length; i += 1) {
        add(list, projectCard(mapOf(projects[i])));
      }
      add(host, list);
    }

    var form = el("form");
    attr(form, "novalidate", "novalidate");
    var newCard = card("Enroll another project",
      "Orch Dork inspects the directory and proposes settings. Nothing is saved until you confirm.");
    var field = el("div", "field");
    var labelNode = el("label", null, "Project directory (full path)");
    attr(labelNode, "for", "new-project-root");
    add(field, labelNode);
    var text = el("input");
    attr(text, "type", "text");
    attr(text, "id", "new-project-root");
    attr(text, "name", "project_root");
    attr(text, "spellcheck", "false");
    attr(text, "autocapitalize", "off");
    attr(text, "autocomplete", "off");
    text.value = textOf(keptValue, "");
    add(field, text);
    add(field, el("p", "hint", "The path stays on this machine. Inspecting a project reads it and writes nothing."));
    add(newCard, field);
    var row = el("div", "btn-row");
    var submit = el("button", "btn btn-primary", "Inspect this project");
    attr(submit, "type", "submit");
    add(row, submit);
    add(newCard, row);
    add(form, newCard);
    form.onsubmit = function (event) {
      event.preventDefault();
      setup.projectRoot = text.value;
      startProposal(text.value);
    };
    add(host, form);
    if (hadFocus) {
      try {
        text.focus();
        text.setSelectionRange(text.value.length, text.value.length);
      } catch (error) { /* focus is a convenience, never a requirement */ }
    }
  }

  function startProposal(projectRoot) {
    if (!hasText(projectRoot)) {
      setup.stage = "error";
      setup.error = failure("project_root:missing", "Name the project directory first.");
      renderSetupStage(true);
      return;
    }
    setup.stage = "loading";
    setup.projectRoot = projectRoot;
    setup.proposal = null;
    setup.result = null;
    setup.error = null;
    setup.custom = false;
    setup.checkRows = null;
    setView("setup");
    renderSetupStage(true);
    request("/api/propose", { project_root: projectRoot }).then(function (data) {
      setup.proposal = mapOf(data);
      setup.stage = "proposal";
      renderSetupStage(true);
      announce("Orch Dork proposed settings for " + projectRoot + ".");
    }, function (error) {
      if (isSessionError(error)) { handleSessionLoss(error); return; }
      setup.stage = "error";
      setup.error = error;
      renderSetupStage(true);
    });
  }

  function setupKey() {
    var proposal = mapOf(setup.proposal);
    return [setup.stage, textOf(setup.projectRoot, ""), textOf(proposal.draft_sha256, ""),
      setup.result ? "result" : "", setup.custom ? "custom" : ""].join("|");
  }

  function renderSetupStage(force) {
    var key = setupKey();
    if (!force && key === setup.renderedKey) { return; }
    setup.renderedKey = key;
    var host = clear(byId("setup-stage"));
    if (setup.stage === "none") { return; }
    if (setup.stage === "loading") {
      add(host, emptyState("Inspecting " + textOf(setup.projectRoot),
        "Orch Dork is reading the project and preparing a proposal."));
      return;
    }
    if (setup.stage === "error") {
      add(host, errorCard("Orch Dork could not propose settings", setup.error));
      return;
    }
    if (setup.stage === "result") {
      add(host, confirmResultCard());
      return;
    }
    add(host, proposalCard());
  }

  function questionCard(question, extraText) {
    var node = card("Orch Dork needs an answer first", null, "card-warn");
    var map = mapOf(question);
    add(node, el("p", null, textOf(map.text, extraText || "")));
    if (hasText(map.code)) { add(node, el("p", "banner-code", "question: " + map.code)); }
    var options = listOf(map.options);
    if (options.length) {
      add(node, el("p", "hint", "Answers Orch Dork can take:"));
      add(node, bulletList(options, ""));
    }
    return node;
  }

  function proposalCard() {
    var proposal = mapOf(setup.proposal);
    var current = mapOf(proposal.current_enrollment);
    var defaults = mapOf(proposal.defaults);
    var isEdit = proposal.current_enrollment ? true : false;
    var wrap = el("div");
    var errors = {};

    var head = card(isEdit ? "Change settings for this project" : "Enroll this project",
      "Nothing below is saved until you confirm. Saved settings apply to later runs.", "card-accent");
    add(head, kv([
      ["Project", valueNode(proposal.project_root)],
      ["Project type", valueNode(proposal.project_type)],
      ["Proposal status", valueNode(proposal.status)],
      ["Proposal draft", codeNode(proposal.draft_sha256)],
      ["Models come from", valueNode(proposal.models_source)]
    ]));
    var detected = details("proposal-detected", "What Orch Dork detected in this project");
    add(detected, valueTree(proposal.detected_from));
    add(head, detected);
    var ground = mapOf(proposal.project_ground);
    if (listOf(ground.writes).length) {
      var groundNote = el("div", "notice");
      add(groundNote, el("p", null, "Enrolling writes these files inside the project:"));
      add(groundNote, bulletList(listOf(ground.writes), ""));
      add(head, groundNote);
    }
    add(wrap, head);

    if (hasText(mapOf(proposal.question).text)) {
      add(wrap, questionCard(proposal.question));
    }

    var checksCard = card("Checks", "These are the commands Orch Dork would run to verify work on this project.");
    add(checksCard, checksTable(proposal.checks, "Checks detected in the project."));
    var customToggle = el("div", "choice");
    var customBox = el("input");
    attr(customBox, "type", "checkbox");
    attr(customBox, "id", "checks-custom");
    customBox.checked = setup.custom;
    customBox.onchange = function () {
      setup.custom = customBox.checked;
      if (setup.custom && !setup.checkRows) {
        setup.checkRows = [];
        var detectedChecks = listOf(proposal.checks);
        for (var i = 0; i < detectedChecks.length; i += 1) {
          var row = mapOf(detectedChecks[i]);
          setup.checkRows.push({
            id: textOf(row.id, ""),
            command: joinArgv(row.argv),
            timeout: textOf(row.timeout_seconds, "")
          });
        }
        if (!setup.checkRows.length) { setup.checkRows.push({ id: "", command: "", timeout: "" }); }
      }
      renderSetupStage(true);
    };
    add(customToggle, customBox);
    var customText = el("span", "choice-text");
    var customLabel = el("label", null, "Enter the checks myself");
    attr(customLabel, "for", "checks-custom");
    add(customText, customLabel);
    add(customText, el("span", "choice-note",
      "Leave this off and Orch Dork records exactly the checks it detected."));
    add(customToggle, customText);
    add(checksCard, customToggle);

    if (setup.custom) {
      var rowsHost = el("div");
      var rows = setup.checkRows || [];
      for (var r = 0; r < rows.length; r += 1) {
        add(rowsHost, checkRowFields(rows[r], r));
      }
      add(checksCard, rowsHost);
      var addRow = el("button", "btn", "Add another check");
      attr(addRow, "type", "button");
      addRow.onclick = function () {
        setup.checkRows.push({ id: "", command: "", timeout: "" });
        renderSetupStage(true);
      };
      add(checksCard, add(el("div", "btn-row"), addRow));
    }
    add(wrap, checksCard);

    var form = el("form");
    attr(form, "novalidate", "novalidate");

    var modelsCard = card("Models", "ADR 0012 asks for a second model from a different family where one exists.");
    var chatInput = null;
    if (!mapOf(proposal.chat_model).model) {
      var chatField = el("div", "field");
      var chatLabel = el("label", null, "The model you chat with");
      attr(chatLabel, "for", "chat-model");
      add(chatField, chatLabel);
      chatInput = el("input");
      attr(chatInput, "type", "text");
      attr(chatInput, "id", "chat-model");
      attr(chatInput, "spellcheck", "false");
      attr(chatInput, "autocomplete", "off");
      chatInput.value = textOf(mapOf(current.models).chat_model, "");
      add(chatField, chatInput);
      add(chatField, el("p", "hint", textOf(proposal.chat_model_question,
        "Codex did not record this task's model where Orch Dork can read it.")));
      errors.chat = el("p", "field-error");
      add(chatField, errors.chat);
      add(modelsCard, chatField);
    } else {
      add(modelsCard, kv([["Model you chat with", valueNode(mapOf(proposal.chat_model).model)]]));
    }

    var secondField = el("div", "field");
    var secondLabel = el("label", null, "Second model");
    attr(secondLabel, "for", "second-model");
    add(secondField, secondLabel);
    var second = el("select");
    attr(second, "id", "second-model");
    var blank = el("option", null, "Choose a model");
    attr(blank, "value", "");
    add(second, blank);
    var modelRows = listOf(proposal.models);
    var chosenSecond = textOf(mapOf(current.models).second_model, textOf(proposal.suggested_second_model, ""));
    for (var m = 0; m < modelRows.length; m += 1) {
      var row = mapOf(modelRows[m]);
      if (!hasText(row.model)) { continue; }
      var option = el("option", null, row.model + "  (" + textOf(row.family, "family unknown")
        + ", " + label(row.onboarding) + ", " + textOf(row.location, "location unknown") + ")");
      attr(option, "value", row.model);
      if (row.model === chosenSecond) { option.selected = true; }
      add(second, option);
    }
    add(secondField, second);
    add(secondField, el("p", "hint", hasText(proposal.suggested_second_model)
      ? "Orch Dork suggests " + proposal.suggested_second_model + "."
      : "Orch Dork has no suggestion from the models Codex reported."));
    errors.second = el("p", "field-error");
    add(secondField, errors.second);
    add(modelsCard, secondField);
    add(modelsCard, el("p", "hint", textOf(proposal.onboarding_notice, "")));
    add(form, modelsCard);

    var localSet = el("fieldset");
    add(localSet, el("legend", null, "Where this project's work may go"));
    var localGroup = radioGroup("keep-local", [
      ["true", "Keep it on this machine", "Only local models may see this project. Hosted models are refused."],
      ["false", "Hosted models may be used", "Work from this project may be sent to the hosted models you onboarded."]
    ], typeof current.keep_local === "boolean" ? String(current.keep_local) : null);
    add(localSet, localGroup.node);
    errors.local = el("p", "field-error");
    add(localSet, errors.local);
    add(form, localSet);

    var limits = el("fieldset");
    add(limits, el("legend", null, "Standing limits"));
    var lineups = keysOf(defaults.lineups);
    var lineupField = null;
    if (lineups.length) {
      lineupField = selectField("lineup-preset", "Role lineup", lineups,
        textOf(mapOf(current.role_lineup).preset, textOf(defaults.lineup_preset, lineups[0])),
        "Each lineup names the planner, implementer, and reviewer models.");
      add(limits, lineupField.field);
      var lineupDetails = details("lineup-detail", "What each lineup uses");
      add(lineupDetails, valueTree(defaults.lineups));
      add(limits, lineupDetails);
    }
    var workers = numberField("workers-max", "Workers at once",
      textOf(current.workers_max, textOf(defaults.workers_max, "")), "1", "1");
    add(limits, workers.field);
    var perRun = numberField("per-run-cost", "Per-run spending limit (US dollars)",
      textOf(dollars(current.per_run_cost), textOf(defaults.per_run_cost_usd, "")), "0", "0.01");
    add(limits, perRun.field);
    var daily = numberField("daily-cost", "Daily spending limit (US dollars)",
      textOf(dollars(current.daily_cost), textOf(defaults.daily_cost_usd, "")), "0", "0.01");
    add(limits, daily.field);
    errors.limits = el("p", "field-error");
    add(limits, errors.limits);
    add(form, limits);

    var profiles = el("fieldset");
    add(profiles, el("legend", null, "Workflow profiles this project may use"));
    var allowed = listOf(current.allowed_workflow_profiles).length
      ? listOf(current.allowed_workflow_profiles)
      : listOf(defaults.allowed_workflow_profiles);
    var profileBoxes = [];
    var profileNames = listOf(proposal.workflow_profiles);
    for (var p = 0; p < profileNames.length; p += 1) {
      var name = String(profileNames[p]);
      var choice = el("div", "choice");
      var box = el("input");
      attr(box, "type", "checkbox");
      attr(box, "id", "profile-" + p);
      attr(box, "value", name);
      box.checked = allowed.indexOf(name) >= 0;
      add(choice, box);
      var boxText = el("span", "choice-text");
      var boxLabel = el("label", null, name);
      attr(boxLabel, "for", "profile-" + p);
      add(boxText, boxLabel);
      add(choice, boxText);
      add(profiles, choice);
      profileBoxes.push(box);
    }
    errors.profiles = el("p", "field-error");
    add(profiles, errors.profiles);
    add(form, profiles);

    var approvals = el("fieldset");
    add(approvals, el("legend", null, "Approval"));
    var approvalChoice = el("div", "choice");
    var approvalBox = el("input");
    attr(approvalBox, "type", "checkbox");
    attr(approvalBox, "id", "per-run-approval");
    approvalBox.checked = current.per_run_approval === true
      || (current.per_run_approval === undefined && defaults.per_run_approval === true);
    add(approvalChoice, approvalBox);
    var approvalText = el("span", "choice-text");
    var approvalLabel = el("label", null, "Ask me before every run");
    attr(approvalLabel, "for", "per-run-approval");
    add(approvalText, approvalLabel);
    add(approvalText, el("span", "choice-note",
      "Approval happens in the chat. This page never approves a run."));
    add(approvalChoice, approvalText);
    add(approvals, approvalChoice);
    add(form, approvals);

    var offer = mapOf(mapOf(proposal.v1).opt_in_offer);
    var v1Group = null;
    if (hasText(offer.plan_sha256)) {
      var v1Set = el("fieldset");
      add(v1Set, el("legend", null, "A change to your own Codex"));
      var strong = el("div", "notice notice-strong");
      add(strong, el("p", null, textOf(offer.text, "")));
      add(strong, el("p", null,
        "This is the only change Orch Dork can make to your own Codex. It also moves your own chats to V1, and it takes effect after Codex restarts."));
      add(v1Set, strong);
      add(v1Set, kv([["Plan", codeNode(offer.plan_sha256)]]));
      var editsHolder = details("v1-offer-edits", "The exact edits this would make");
      add(editsHolder, valueTree(offer.edits));
      editsHolder.open = true;
      add(v1Set, editsHolder);
      v1Group = radioGroup("v1-opt-in", [
        ["accept", "Make this change to my Codex", "Every model runs on V1, including your own chats, after Codex restarts."],
        ["decline", "Leave my Codex alone", "Governed runs keep using the separate Orch Dork runner."]
      ], null);
      add(v1Set, v1Group.node);
      errors.v1 = el("p", "field-error");
      add(v1Set, errors.v1);
      add(form, v1Set);
    } else {
      var noOffer = card("V1 status for this project", null, "card-sunk");
      add(noOffer, kv([
        ["Governed runs run in", valueNode(label(textOf(mapOf(proposal.v1).location, "unknown")))],
        ["Rows not on V1", listOf(mapOf(proposal.v1).rows_not_v1).length
          ? document.createTextNode(listOf(mapOf(proposal.v1).rows_not_v1).join(", "))
          : el("span", "unknown", "none reported")]
      ]));
      add(noOffer, el("p", "hint", "Orch Dork is not offering a change to your Codex here."));
      add(form, noOffer);
    }

    var confirmCard = card("Confirm", null, "card-accent");
    add(confirmCard, el("p", null,
      "Saving records the same enrollment the chat path records. It applies to later runs. An active run keeps its frozen settings, but saving changes can prevent it from accepting a revision."));
    var ack = el("div", "choice");
    var ackBox = el("input");
    attr(ackBox, "type", "checkbox");
    attr(ackBox, "id", "confirm-ack");
    add(ack, ackBox);
    var ackText = el("span", "choice-text");
    var ackLabel = el("label", null, "I have read these settings and want them saved");
    attr(ackLabel, "for", "confirm-ack");
    add(ackText, ackLabel);
    add(ack, ackText);
    add(confirmCard, ack);
    errors.ack = el("p", "field-error");
    add(confirmCard, errors.ack);
    var buttons = el("div", "btn-row");
    var save = el("button", "btn btn-primary", isEdit ? "Save these settings" : "Enroll and save");
    attr(save, "type", "submit");
    add(buttons, save);
    var cancel = el("button", "btn", "Discard this proposal");
    attr(cancel, "type", "button");
    cancel.onclick = function () {
      setup.stage = "none";
      setup.proposal = null;
      renderSetupStage(true);
    };
    add(buttons, cancel);
    add(confirmCard, buttons);
    errors.submit = el("p", "field-error");
    add(confirmCard, errors.submit);
    add(form, confirmCard);

    form.onsubmit = function (event) {
      event.preventDefault();
      submitConfirm({
        proposal: proposal,
        errors: errors,
        chatInput: chatInput,
        second: second,
        localGroup: localGroup,
        lineupField: lineupField,
        workers: workers,
        perRun: perRun,
        daily: daily,
        profileBoxes: profileBoxes,
        approvalBox: approvalBox,
        v1Group: v1Group,
        ackBox: ackBox,
        save: save
      });
    };
    add(wrap, form);
    return wrap;
  }

  function checkRowFields(row, index) {
    var set = el("fieldset");
    add(set, el("legend", null, "Check " + (index + 1)));
    var idField = textField("check-id-" + index, "Name", row.id, "A short name such as tests or lint.");
    idField.input.oninput = function () { row.id = idField.input.value; };
    add(set, idField.field);
    var commandField = textField("check-cmd-" + index, "Command", row.command,
      "Exactly as it runs in a shell. Quote any argument that contains a space.");
    commandField.input.oninput = function () { row.command = commandField.input.value; };
    add(set, commandField.field);
    var timeoutField = numberField("check-timeout-" + index, "Timeout (seconds)", row.timeout, "1", "1");
    timeoutField.input.oninput = function () { row.timeout = timeoutField.input.value; };
    add(set, timeoutField.field);
    var remove = el("button", "btn", "Remove this check");
    attr(remove, "type", "button");
    remove.onclick = function () {
      setup.checkRows.splice(index, 1);
      if (!setup.checkRows.length) { setup.checkRows.push({ id: "", command: "", timeout: "" }); }
      renderSetupStage(true);
    };
    add(set, add(el("div", "btn-row"), remove));
    return set;
  }

  function textField(id, labelText, value, hint) {
    var field = el("div", "field");
    var labelNode = el("label", null, labelText);
    attr(labelNode, "for", id);
    add(field, labelNode);
    var input = el("input");
    attr(input, "type", "text");
    attr(input, "id", id);
    attr(input, "spellcheck", "false");
    attr(input, "autocomplete", "off");
    input.value = textOf(value, "");
    add(field, input);
    if (hint) { add(field, el("p", "hint", hint)); }
    return { field: field, input: input };
  }

  function numberField(id, labelText, value, min, step) {
    var field = el("div", "field");
    var labelNode = el("label", null, labelText);
    attr(labelNode, "for", id);
    add(field, labelNode);
    var input = el("input");
    attr(input, "type", "number");
    attr(input, "id", id);
    attr(input, "inputmode", "decimal");
    if (min !== undefined) { attr(input, "min", min); }
    if (step !== undefined) { attr(input, "step", step); }
    input.value = textOf(value, "");
    add(field, input);
    return { field: field, input: input };
  }

  function selectField(id, labelText, options, selected, hint) {
    var field = el("div", "field");
    var labelNode = el("label", null, labelText);
    attr(labelNode, "for", id);
    add(field, labelNode);
    var select = el("select");
    attr(select, "id", id);
    for (var i = 0; i < options.length; i += 1) {
      var option = el("option", null, String(options[i]));
      attr(option, "value", String(options[i]));
      if (String(options[i]) === String(selected)) { option.selected = true; }
      add(select, option);
    }
    add(field, select);
    if (hint) { add(field, el("p", "hint", hint)); }
    return { field: field, select: select };
  }

  function radioGroup(name, options, selected) {
    var node = el("div");
    var inputs = [];
    for (var i = 0; i < options.length; i += 1) {
      var choice = el("div", "choice");
      var input = el("input");
      attr(input, "type", "radio");
      attr(input, "name", name);
      attr(input, "id", name + "-" + i);
      attr(input, "value", options[i][0]);
      if (selected !== null && selected !== undefined && String(selected) === String(options[i][0])) {
        input.checked = true;
      }
      add(choice, input);
      var text = el("span", "choice-text");
      var labelNode = el("label", null, options[i][1]);
      attr(labelNode, "for", name + "-" + i);
      add(text, labelNode);
      if (options[i][2]) { add(text, el("span", "choice-note", options[i][2])); }
      add(choice, text);
      add(node, choice);
      inputs.push(input);
    }
    return {
      node: node,
      value: function () {
        for (var j = 0; j < inputs.length; j += 1) {
          if (inputs[j].checked) { return inputs[j].value; }
        }
        return null;
      }
    };
  }

  function submitConfirm(form) {
    var errors = form.errors;
    var names = keysOf(errors);
    var i;
    for (i = 0; i < names.length; i += 1) { errors[names[i]].textContent = ""; }
    var problems = 0;
    var args = { draft_sha256: mapOf(form.proposal).draft_sha256 };

    if (form.chatInput) {
      if (!hasText(form.chatInput.value)) {
        errors.chat.textContent = "Name the model you chat with.";
        problems += 1;
      } else {
        args.chat_model = form.chatInput.value;
      }
    }
    if (!hasText(form.second.value)) {
      errors.second.textContent = "Choose the second model.";
      problems += 1;
    } else {
      args.second_model = form.second.value;
    }
    var keepLocal = form.localGroup.value();
    if (keepLocal === null) {
      errors.local.textContent = "Say whether this project's work may leave this machine.";
      problems += 1;
    } else {
      args.keep_local = keepLocal === "true";
    }
    if (form.lineupField) { args.lineup_preset = form.lineupField.select.value; }
    var workers = Number(form.workers.input.value);
    var perRun = Number(form.perRun.input.value);
    var daily = Number(form.daily.input.value);
    if (!isFinite(workers) || workers < 1 || Math.floor(workers) !== workers) {
      errors.limits.textContent = "Workers at once must be a whole number of at least 1.";
      problems += 1;
    } else if (!isFinite(perRun) || perRun < 0 || !isFinite(daily) || daily < 0) {
      errors.limits.textContent = "Both spending limits must be numbers of at least 0.";
      problems += 1;
    } else if (perRun > daily) {
      errors.limits.textContent = "The per-run limit cannot be larger than the daily limit.";
      problems += 1;
    } else {
      args.workers_max = workers;
      args.per_run_cost_usd = perRun;
      args.daily_cost_usd = daily;
    }
    var chosen = [];
    for (i = 0; i < form.profileBoxes.length; i += 1) {
      if (form.profileBoxes[i].checked) { chosen.push(form.profileBoxes[i].value); }
    }
    if (!chosen.length) {
      errors.profiles.textContent = "Allow at least one workflow profile.";
      problems += 1;
    } else {
      args.allowed_workflow_profiles = chosen;
    }
    args.per_run_approval = form.approvalBox.checked;
    if (form.v1Group) {
      var answer = form.v1Group.value();
      if (answer === null) {
        errors.v1.textContent = "Say whether Orch Dork should change your Codex. There is no default.";
        problems += 1;
      } else {
        args.v1_opt_in = answer;
      }
    }
    if (setup.custom) {
      var rows = [];
      var bad = 0;
      var source = setup.checkRows || [];
      for (i = 0; i < source.length; i += 1) {
        var row = source[i];
        var argv = splitArgv(textOf(row.command, ""));
        var timeout = Number(row.timeout);
        if (!hasText(row.id) || !argv.length || !isFinite(timeout) || timeout < 1) { bad += 1; continue; }
        rows.push({ id: row.id, argv: argv, timeout_seconds: Math.floor(timeout) });
      }
      if (bad || !rows.length) {
        errors.submit.textContent = "Every check you enter needs a name, a command, and a timeout of at least 1 second.";
        problems += 1;
      } else {
        args.checks = rows;
      }
    }
    if (!form.ackBox.checked) {
      errors.ack.textContent = "Confirm that you want these settings saved.";
      problems += 1;
    }
    if (problems) {
      announce("The settings form has " + problems + " item" + (problems === 1 ? "" : "s") + " to fix.");
      return;
    }

    form.save.disabled = true;
    form.save.textContent = "Saving";
    request("/api/confirm", { confirmed: true, arguments: args }).then(function (data) {
      setup.result = mapOf(data);
      setup.stage = "result";
      renderSetupStage(true);
      var onboarding = mapOf(setup.result.onboarding);
      if (hasText(onboarding.job_id)) { watchOnboarding(onboarding.job_id); }
      announce("Settings saved. They apply to later runs.");
      refreshState();
    }, function (error) {
      form.save.disabled = false;
      form.save.textContent = "Try saving again";
      if (isSessionError(error)) { handleSessionLoss(error); return; }
      errors.submit.textContent = textOf(error.text, "The helper refused that change.")
        + " (" + textOf(error.reason, "unknown") + ")";
      announce("The helper refused that change.");
    });
  }

  function confirmResultCard() {
    var result = mapOf(setup.result);
    var node = card("Saved", null, "card-accent");
    add(node, kv([
      ["Status", valueNode(result.status)],
      ["Project", valueNode(result.project_root)],
      ["Enrollment record", codeNode(result.record_sha256)],
      ["Governed runs", valueNode(result.governed_runs)],
      ["V1 change", valueNode(result.v1_opt_in)]
    ]));
    add(node, el("p", "notice",
      "These settings apply to later runs. An active run keeps its frozen settings, but saving changes can prevent it from accepting a revision."));
    var refused = listOf(result.governed_runs_refused_for);
    if (refused.length) {
      var block = card("Governed runs are refused for now", null, "card-warn");
      add(block, bulletList(refused, ""));
      add(node, block);
    }
    var written = listOf(result.written_to_project);
    var writtenHolder = details("confirm-written", "Files written inside the project (" + written.length + ")");
    add(writtenHolder, bulletList(written, "Nothing new was written inside the project."));
    add(node, writtenHolder);
    var enrollmentHolder = details("confirm-enrollment", "The enrollment Orch Dork recorded");
    add(enrollmentHolder, valueTree(result.enrollment));
    add(node, enrollmentHolder);
    var onboarding = mapOf(result.onboarding);
    if (hasText(onboarding.job_id)) {
      var job = card("Onboarding started", null, "card-sunk");
      add(job, kv([
        ["Job", codeNode(onboarding.job_id)],
        ["Models", listOf(onboarding.models).length
          ? document.createTextNode(listOf(onboarding.models).join(", "))
          : el("span", "unknown", "none listed")]
      ]));
      add(job, el("p", "hint", textOf(onboarding.notice, "")));
      add(job, el("p", "hint", "Progress appears on the Models view."));
      add(node, job);
    }
    var row = el("div", "btn-row");
    var back = el("button", "btn", "Back to the project list");
    attr(back, "type", "button");
    back.onclick = function () {
      setup.stage = "none";
      setup.result = null;
      setup.proposal = null;
      renderSetupStage(true);
      renderSetupProjects(true);
    };
    add(row, back);
    add(node, row);
    return node;
  }

  /* ------------------------------------------------------------ models */

  var ONBOARD_NOTICE = "Onboarding runs one short probe per model in a private Codex home that uses your login: the "
    + "model spawns itself once on a trivial task and the result is recorded. It takes about a "
    + "minute per hosted model, spends a few thousand tokens, and changes nothing in your own Codex.";

  var models = {
    stage: "none",
    model: "",
    reonboard: false,
    typed: "",
    error: null,
    job: null,
    jobId: null,
    polls: 0,
    pollTimer: null,
    pollBusy: false,
    renderedKey: "",
    tableJson: ""
  };

  function onboardingBadge(value) {
    var name = hasText(value) ? value : "unknown";
    var kind = name === "passed" ? "ok" : (name === "not_passed" ? "alert" : "warn");
    var node = el("span", "badge badge-" + kind);
    add(node, document.createTextNode(label(name)));
    return node;
  }

  function renderModelsTable(force) {
    var host = byId("models-body");
    var state = app.state;
    var rows = state ? listOf(state.models) : [];
    var json = JSON.stringify([rows, state ? state.models_source : null, state ? state.v1 : null]);
    if (!force && json === models.tableJson) { return; }
    models.tableJson = json;
    clear(host);
    if (!state) {
      add(host, emptyState("Reading your records", "The page is asking the local helper for its records."));
      return;
    }

    var head = card("Where this list comes from", null, "card-sunk");
    add(head, kv([
      ["Reported by", valueNode(state.models_source)],
      ["Models listed", valueNode(rows.length)],
      ["Governed runs run in", valueNode(hasText(mapOf(state.v1).location)
        ? label(mapOf(state.v1).location) : null)],
      [hasText(mapOf(state.v1).reason) ? "Reason" : "Catalog rows not on V1",
       valueNode(mapOf(state.v1).reason || listOf(mapOf(state.v1).rows_not_v1).join(", ") || "none reported")]
    ]));
    add(host, head);

    var listCard = card("Models", "Onboarding sends one brief message to a model. It never sends project content.");
    if (!rows.length) {
      add(listCard, emptyState("Codex reported no models here",
        "You can still name a model yourself below. Orch Dork will check it the same way."));
    } else {
      var built = table(
        "Every model Codex reports on this machine, with its onboarding result and V1 status.",
        ["Model", "Family", "Privacy", "Onboarding", "V1 status", "Why", "Location", "Profile", ""]
      );
      for (var i = 0; i < rows.length; i += 1) {
        var row = mapOf(rows[i]);
        var tr = el("tr");
        add(tr, cell(codeNode(row.model, "mono")));
        add(tr, cell(row.family));
        add(tr, cell(hasText(row.privacy) ? label(row.privacy) : null));
        add(tr, cell(onboardingBadge(row.onboarding)));
        add(tr, cell(row.v1_status));
        add(tr, cell(row.v1_reason));
        add(tr, cell(hasText(row.location) ? label(row.location) : null));
        var profile = el("td");
        if (hasText(row.profile_sha256)) {
          var code = el("code", "digest", shortDigest(row.profile_sha256));
          attr(code, "title", row.profile_sha256);
          add(profile, code);
        } else {
          add(profile, el("span", "unknown", "none"));
        }
        add(tr, profile);
        var action = el("td");
        if (hasText(row.model)) {
          var passed = row.onboarding === "passed";
          var button = el("button", "btn", passed ? "Re-onboard" : "Onboard");
          attr(button, "type", "button");
          attr(button, "aria-label", (passed ? "Re-onboard " : "Onboard ") + row.model);
          button.onclick = makeOnboardOpener(row.model, passed);
          add(action, button);
        }
        add(tr, action);
        add(built.body, tr);
      }
      add(listCard, built.wrap);
    }

    var form = el("form");
    attr(form, "novalidate", "novalidate");
    var typed = textField("typed-model", "Check a model Codex did not list",
      models.typed, "Type the model name exactly as your provider spells it.");
    add(form, typed.field);
    var row2 = el("div", "btn-row");
    var go = el("button", "btn", "Continue");
    attr(go, "type", "submit");
    add(row2, go);
    add(form, row2);
    form.onsubmit = function (event) {
      event.preventDefault();
      models.typed = typed.input.value;
      if (!hasText(models.typed)) {
        models.stage = "error";
        models.error = failure("model:missing", "Type a model name first.");
        renderModelsStage(true);
        return;
      }
      openOnboard(models.typed, false);
    };
    add(listCard, form);
    add(host, listCard);
  }

  function makeOnboardOpener(model, passed) {
    return function () { openOnboard(model, passed); };
  }

  function openOnboard(model, passed) {
    models.stage = "confirm";
    models.model = model;
    models.reonboard = passed === true;
    models.error = null;
    setView("models");
    renderModelsStage(true);
  }

  function modelsStageKey() {
    return [models.stage, models.model, models.reonboard ? "again" : "first",
      models.jobId || "", models.job ? textOf(mapOf(models.job).state, "") : "",
      models.job ? String(models.polls) : ""].join("|");
  }

  function renderModelsStage(force) {
    var key = modelsStageKey();
    if (!force && key === models.renderedKey) { return; }
    models.renderedKey = key;
    var host = clear(byId("models-stage"));
    if (models.stage === "error") {
      add(host, errorCard("Orch Dork could not check that model", models.error));
    } else if (models.stage === "confirm") {
      add(host, onboardConfirmCard());
    } else if (models.stage === "sending") {
      add(host, emptyState("Starting the check for " + models.model,
        "Orch Dork is asking the helper to start one onboarding probe."));
    }
    if (models.job || models.jobId) {
      add(host, onboardingJobCard());
    }
  }

  function onboardConfirmCard() {
    var node = card(models.reonboard
      ? "Onboard " + models.model + " again"
      : "Onboard " + models.model, null, "card-accent");
    var notice = el("div", "notice");
    add(notice, el("p", null, ONBOARD_NOTICE));
    add(node, notice);
    if (models.reonboard) {
      add(node, el("p", null,
        "This model already passed. Onboarding it again runs a real probe and records a fresh result, replacing the old one."));
    }
    add(node, kv([["Model", codeNode(models.model, "mono")]]));
    var row = el("div", "btn-row");
    var send = el("button", "btn btn-primary", models.reonboard
      ? "Send the message again"
      : "Send the message");
    attr(send, "type", "button");
    send.onclick = function () {
      send.disabled = true;
      sendOnboard(models.model);
    };
    add(row, send);
    var cancel = el("button", "btn", "Not now");
    attr(cancel, "type", "button");
    cancel.onclick = function () {
      models.stage = "none";
      renderModelsStage(true);
    };
    add(row, cancel);
    add(node, row);
    add(node, el("p", "hint",
      "Nothing is sent until you choose. This page cannot send project content."));
    return node;
  }

  function sendOnboard(model) {
    models.stage = "sending";
    renderModelsStage(true);
    request("/api/onboard", { model: model, confirmed: true }).then(function (data) {
      var result = mapOf(data);
      models.stage = "none";
      models.error = null;
      if (hasText(result.job_id)) {
        watchOnboarding(result.job_id);
      } else {
        models.stage = "error";
        models.error = failure("onboarding:no_job", "The helper did not return a job to follow.");
      }
      renderModelsStage(true);
      announce("Onboarding started for " + model + ".");
      refreshState();
    }, function (error) {
      if (isSessionError(error)) { handleSessionLoss(error); return; }
      models.stage = "error";
      models.error = error;
      renderModelsStage(true);
    });
  }

  function onboardingJobCard() {
    var job = mapOf(models.job);
    var node = card("Onboarding progress", null, "card-sunk");
    add(node, kv([
      ["Job", codeNode(textOf(job.job_id, models.jobId))],
      ["State", valueNode(job.state)],
      ["Checks made", valueNode(models.polls)]
    ]));
    var rows = mapOf(job.models);
    var names = keysOf(rows);
    if (names.length) {
      var built = table("Each model in this onboarding job.", ["Model", "State", "Detail"]);
      for (var i = 0; i < names.length; i += 1) {
        var entry = mapOf(rows[names[i]]);
        var tr = el("tr");
        add(tr, cell(codeNode(names[i], "mono")));
        add(tr, cell(onboardingBadge(entry.state)));
        var detail = el("td");
        var extra = [];
        var fields = keysOf(entry);
        for (var f = 0; f < fields.length; f += 1) {
          if (fields[f] === "state") { continue; }
          extra.push(fields[f] + ": " + (typeof entry[fields[f]] === "object"
            ? JSON.stringify(entry[fields[f]])
            : String(entry[fields[f]])));
        }
        if (extra.length) {
          add(detail, document.createTextNode(extra.join("; ")));
        } else {
          add(detail, el("span", "unknown", "nothing else recorded"));
        }
        add(tr, detail);
        add(built.body, tr);
      }
      add(node, built.wrap);
    } else {
      add(node, el("p", "hint", "The helper has not reported per-model progress yet."));
    }
    if (models.pollTimer === null && isPendingJob(job)) {
      add(node, el("p", "hint",
        "This page stopped following the job after " + ONBOARD_POLL_LIMIT
        + " checks. Reopen the Models view or ask in the chat for the result."));
      var again = el("button", "btn", "Follow it again");
      attr(again, "type", "button");
      again.onclick = function () { watchOnboarding(textOf(job.job_id, models.jobId)); };
      add(node, add(el("div", "btn-row"), again));
    }
    return node;
  }

  function isPendingJob(job) {
    var state = mapOf(job).state;
    if (!hasText(state)) { return true; }
    return state !== "DONE" && state !== "FAILED"
      && state !== "passed" && state !== "failed" && state !== "completed"
      && state !== "not_passed" && state !== "error" && state !== "cancelled";
  }

  function watchOnboarding(jobId) {
    if (!hasText(jobId)) { return; }
    models.jobId = jobId;
    models.polls = 0;
    if (models.pollTimer !== null) {
      window.clearTimeout(models.pollTimer);
      models.pollTimer = null;
    }
    pollOnboarding();
  }

  function pollOnboarding() {
    models.pollTimer = null;
    if (sessionLost || !hasText(models.jobId)) { return; }
    if (models.pollBusy) { return; }
    if (models.polls >= ONBOARD_POLL_LIMIT) {
      renderModelsStage(true);
      return;
    }
    if (document.hidden) {
      models.pollTimer = window.setTimeout(pollOnboarding, ONBOARD_POLL_MS);
      return;
    }
    models.pollBusy = true;
    models.polls += 1;
    request("/api/onboarding?job_id=" + encodeURIComponent(models.jobId)).then(function (data) {
      models.pollBusy = false;
      models.job = mapOf(data);
      renderModelsStage(true);
      if (isPendingJob(models.job)) {
        models.pollTimer = window.setTimeout(pollOnboarding, ONBOARD_POLL_MS);
      } else {
        announce("Onboarding finished with state " + textOf(mapOf(models.job).state) + ".");
        refreshState();
      }
    }, function (error) {
      models.pollBusy = false;
      if (isSessionError(error)) { handleSessionLoss(error); return; }
      models.stage = "error";
      models.error = error;
      renderModelsStage(true);
    });
  }

  /* ------------------------------------------------------------ v1 change */

  var v1 = { stage: "none", plan: null, result: null, error: null, renderedKey: "" };

  function v1Key() {
    return [v1.stage, v1.plan ? textOf(mapOf(v1.plan).plan_sha256, "") : "",
      v1.result ? textOf(mapOf(v1.result).status, "") : ""].join("|");
  }

  function renderV1(force) {
    var key = v1Key();
    if (!force && key === v1.renderedKey) { return; }
    v1.renderedKey = key;
    var host = clear(byId("v1-body"));
    var state = app.state;
    var node = card("The one change Orch Dork can make to your own Codex",
      "Orch Dork can set your Codex so every model runs on V1. That also moves your own chats to V1, and it takes effect after Codex restarts.");
    add(node, kv([
      ["Governed runs run in", valueNode(state && hasText(mapOf(state.v1).location)
        ? label(mapOf(state.v1).location) : null)],
      [state && hasText(mapOf(state.v1).reason) ? "Reason" : "Catalog rows not on V1",
       valueNode(state ? mapOf(state.v1).reason || listOf(mapOf(state.v1).rows_not_v1).join(", ") || "none reported" : null)]
    ]));

    if (v1.stage === "proposing") {
      add(node, el("p", "hint", "Asking the helper what the change would do."));
    } else if (v1.stage === "none" || v1.stage === "error") {
      var row = el("div", "btn-row");
      var check = el("button", "btn", "Show me what this change would do");
      attr(check, "type", "button");
      check.onclick = function () { proposeV1(); };
      add(row, check);
      add(node, row);
      add(node, el("p", "hint", "This only reads your Codex configuration and shows the edits."));
    }
    if (v1.stage === "error") {
      add(node, errorCard("Orch Dork could not prepare that change", v1.error));
    }
    if (v1.stage === "plan" && v1.plan) {
      add(node, v1PlanBlock());
    }
    if (v1.stage === "applying") {
      add(node, el("p", "hint", "Applying the change to your Codex configuration."));
    }
    if (v1.stage === "applied" && v1.result) {
      var done = card("Applied", null, "card-accent");
      add(done, kv([["Status", valueNode(mapOf(v1.result).status)]]));
      add(done, el("p", null,
        "Your Codex runs every model on V1 after Codex restarts. Your own chats move to V1 as well."));
      var detail = details("v1-applied", "What the helper reported");
      add(detail, valueTree(v1.result));
      add(done, detail);
      add(node, done);
    }
    add(host, node);
  }

  function v1PlanBlock() {
    var plan = mapOf(v1.plan);
    if (plan.status !== "CONFIRMATION_REQUIRED") {
      var nothing = card("No change is needed", null, "card-sunk");
      add(nothing, kv([["Status", valueNode(plan.status)]]));
      add(nothing, valueTree(plan));
      return nothing;
    }
    var node = card("Review this change to your Codex", null, "card-warn");
    var notice = el("div", "notice notice-strong");
    add(notice, el("p", null,
      "Applying this edits your own Codex configuration so every model runs on V1. Your own chats move to V1 too, and the change takes effect after Codex restarts."));
    add(notice, el("p", null, "Nothing is applied until you confirm below."));
    add(node, notice);
    add(node, kv([["Plan", codeNode(plan.plan_sha256)], ["Status", valueNode(plan.status)]]));
    var editsHolder = details("v1-plan-edits", "The exact edits");
    add(editsHolder, valueTree(plan.edits));
    editsHolder.open = true;
    add(node, editsHolder);

    var form = el("form");
    attr(form, "novalidate", "novalidate");
    var ack = el("div", "choice");
    var ackBox = el("input");
    attr(ackBox, "type", "checkbox");
    attr(ackBox, "id", "v1-ack");
    add(ack, ackBox);
    var ackText = el("span", "choice-text");
    var ackLabel = el("label", null, "I want these edits made to my Codex, including the move of my own chats to V1");
    attr(ackLabel, "for", "v1-ack");
    add(ackText, ackLabel);
    add(ack, ackText);
    add(form, ack);
    var problem = el("p", "field-error");
    add(form, problem);
    var row = el("div", "btn-row");
    var apply = el("button", "btn btn-primary", "Apply this change");
    attr(apply, "type", "submit");
    add(row, apply);
    var cancel = el("button", "btn", "Leave my Codex alone");
    attr(cancel, "type", "button");
    cancel.onclick = function () {
      v1.stage = "none";
      v1.plan = null;
      renderV1(true);
    };
    add(row, cancel);
    add(form, row);
    form.onsubmit = function (event) {
      event.preventDefault();
      problem.textContent = "";
      if (!ackBox.checked) {
        problem.textContent = "Confirm the change before Orch Dork applies it. There is no default.";
        return;
      }
      applyV1(plan.plan_sha256);
    };
    add(node, form);
    return node;
  }

  function proposeV1() {
    v1.stage = "proposing";
    v1.error = null;
    renderV1(true);
    request("/api/v1/propose", {}).then(function (data) {
      v1.plan = mapOf(data);
      v1.stage = "plan";
      renderV1(true);
      announce("Orch Dork prepared the V1 change for your review.");
    }, function (error) {
      if (isSessionError(error)) { handleSessionLoss(error); return; }
      v1.stage = "error";
      v1.error = error;
      renderV1(true);
    });
  }

  function applyV1(planDigest) {
    v1.stage = "applying";
    renderV1(true);
    request("/api/v1/apply", { plan_sha256: planDigest, confirmed: true }).then(function (data) {
      v1.result = mapOf(data);
      v1.stage = "applied";
      renderV1(true);
      announce("The V1 change was applied. It takes effect after Codex restarts.");
      refreshState();
    }, function (error) {
      if (isSessionError(error)) { handleSessionLoss(error); return; }
      v1.stage = "error";
      v1.error = error;
      renderV1(true);
    });
  }

  /* ------------------------------------------------------------ views */

  var VIEWS = ["runs", "run", "setup", "models"];

  function setView(name) {
    if (VIEWS.indexOf(name) < 0) { name = "runs"; }
    app.view = name;
    for (var i = 0; i < VIEWS.length; i += 1) {
      var section = byId("view-" + VIEWS[i]);
      var button = byId("nav-" + VIEWS[i]);
      var active = VIEWS[i] === name;
      section.hidden = !active;
      if (active) {
        button.setAttribute("aria-current", "page");
      } else {
        button.removeAttribute("aria-current");
      }
    }
    render();
  }

  function selectRun(runId) {
    app.selectedRunId = runId;
    app.run = null;
    app.runJson = "";
    app.runError = null;
    // Never show or save another run's sanitized copy while this run's loads.
    app.onlineDiagram = null;
    app.onlineDiagramJson = "";
    app.onlineDiagramError = null;
    setView("run");
    announce("Opened run " + runId + ".");
    refreshRun();
  }

  function renderNav() {
    var state = app.state;
    var view = state ? textOf(state.view) : "local";
    var sub = byId("brand-sub");
    if (sub) {
      sub.textContent = view === "tailnet"
        ? "Tailnet view, your devices only"
        : "Local view, this machine only";
    }
    byId("nav-runs-meta").textContent = state
      ? listOf(state.runs).length + " recorded"
      : "reading";
    byId("nav-run-meta").textContent = app.selectedRunId
      ? clip(app.selectedRunId, 22)
      : "none selected";
    byId("nav-setup-meta").textContent = state
      ? listOf(state.projects).length + " project" + (listOf(state.projects).length === 1 ? "" : "s")
      : "reading";
    byId("nav-models-meta").textContent = state
      ? listOf(state.models).length + " listed"
      : "reading";
    var stats = clear(byId("nav-stats"));
    var rows = [
      ["Generation", state ? textOf(state.generation) : "unknown"],
      ["Helper status", state ? textOf(state.status) : "unknown"],
      ["Session", "in memory only"]
    ];
    for (var i = 0; i < rows.length; i += 1) {
      add(stats, el("dt", null, rows[i][0]));
      add(stats, el("dd", null, rows[i][1]));
    }
  }

  function render() {
    renderNav();
    if (app.view === "runs") { renderRunsView(); }
    if (app.view === "run") { renderRunView(); }
    if (app.view === "setup") {
      renderSetupProjects(false);
      renderSetupStage(false);
    }
    if (app.view === "models") {
      renderModelsTable(false);
      renderModelsStage(false);
      renderV1(false);
    }
  }

  /* ------------------------------------------------------------ polling */

  var poll = { timer: null, busy: false };

  function schedulePoll(delay) {
    if (poll.timer !== null) { window.clearTimeout(poll.timer); }
    poll.timer = window.setTimeout(tick, delay);
  }

  function tick() {
    poll.timer = null;
    if (sessionLost) { return; }
    if (document.hidden || poll.busy) {
      schedulePoll(STATE_POLL_MS);
      return;
    }
    poll.busy = true;
    refreshState().then(function () {
      return app.selectedRunId ? refreshRun() : null;
    }).then(function () {
      poll.busy = false;
      schedulePoll(STATE_POLL_MS);
    }, function () {
      poll.busy = false;
      schedulePoll(STATE_POLL_MS);
    });
  }

  function refreshState() {
    if (sessionLost) { return Promise.resolve(); }
    return request("/api/state").then(function (data) {
      var state = mapOf(data);
      var json = JSON.stringify(state);
      app.stateError = null;
      clearBanner("state");
      if (json !== app.stateJson) {
        app.stateJson = json;
        app.state = state;
        render();
      } else {
        renderNav();
      }
    }, function (error) {
      if (isSessionError(error)) { handleSessionLoss(error); return; }
      app.stateError = error;
      showBanner("state", "error", "Orch Dork lost contact with the helper on this machine",
        textOf(error.text, "The page will keep trying."), "reason: " + textOf(error.reason, "unknown"));
      if (!app.state) { render(); }
    });
  }

  function refreshRun() {
    if (sessionLost || !app.selectedRunId) { return Promise.resolve(); }
    var wanted = app.selectedRunId;
    return request("/api/run?run_id=" + encodeURIComponent(wanted)).then(function (data) {
      if (app.selectedRunId !== wanted) { return; }
      var run = mapOf(data);
      var json = JSON.stringify(run);
      app.runError = null;
      clearBanner("run");
      if (json !== app.runJson) {
        app.runJson = json;
        app.run = run;
        if (app.view === "run") { renderRunView(); }
      }
      refreshOnlineDiagram();
    }, function (error) {
      if (app.selectedRunId !== wanted) { return; }
      if (isSessionError(error)) { handleSessionLoss(error); return; }
      app.runError = error;
      showBanner("run", "error", "Orch Dork could not read run " + wanted,
        textOf(error.text, "The page will keep trying."), "reason: " + textOf(error.reason, "unknown"));
      if (!app.run && app.view === "run") { renderRunView(); }
    });
  }

  /* ------------------------------------------------------------ start */

  function wireNav() {
    var buttons = document.querySelectorAll(".nav-item");
    for (var i = 0; i < buttons.length; i += 1) {
      (function (button) {
        button.onclick = function () {
          setView(button.getAttribute("data-view"));
          var main = byId("main");
          if (main && main.focus) { main.focus(); }
        };
      }(buttons[i]));
    }
  }

  function init() {
    secret = captureSession();
    wireNav();
    if (!secret) {
      showGate(
        "This page needs a link from the chat",
        "The local view opens with a one-session key in the link. This page found none, so it has asked the helper for nothing. Ask Orch Dork in the chat to open the local view again."
      );
      return;
    }
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden && !sessionLost) {
        schedulePoll(0);
        if (models.pollTimer === null && hasText(models.jobId) && isPendingJob(models.job)
          && models.polls < ONBOARD_POLL_LIMIT) {
          pollOnboarding();
        }
      }
    });
    setView("runs");
    refreshState().then(function () {
      schedulePoll(STATE_POLL_MS);
    }, function () {
      schedulePoll(STATE_POLL_MS);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
}());
