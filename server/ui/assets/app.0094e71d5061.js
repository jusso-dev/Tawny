(function () {
  var csrf = null;
  var me = null;

  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function api(method, path, body) {
    var headers = { accept: "application/json" };
    if (body != null) headers["content-type"] = "application/json";
    if (csrf && method !== "GET" && method !== "HEAD") headers["X-CSRF-Token"] = csrf;
    return fetch(path, {
      method: method,
      credentials: "same-origin",
      headers: headers,
      body: body == null ? undefined : JSON.stringify(body),
    }).then(function (res) {
      return res.text().then(function (text) {
        var parsed = null;
        if (text) {
          try { parsed = JSON.parse(text); } catch (e) { parsed = text; }
        }
        return { status: res.status, body: parsed, raw: text };
      });
    });
  }

  function nav(active) {
    var groups = [
      ["Operations", [["/", "Dashboard"], ["/incidents", "Incidents"], ["/agents", "Agents"], ["/alerts", "Alerts"]]],
      ["Analysis", [["/hunt", "Hunt"], ["/attack", "ATT&CK coverage"]]],
      ["Detection", [["/detections", "Detections"], ["/threat-intel", "Threat intel"], ["/suppressions", "Suppressions"]]],
      ["System", [["/audit", "Audit"], ["/api-tokens", "Tokens"], ["/enrollment", "Enrollment"], ["/users", "Users"], ["/admin/jobs", "Jobs"]]],
    ];
    var aside = el("nav");
    aside.appendChild(el("p", "Tawny", "brand"));
    groups.forEach(function (group) {
      aside.appendChild(el("div", group[0], "group"));
      group[1].forEach(function (item) {
        var link = el("a", item[1]);
        link.href = item[0];
        if (item[0] === active) link.className = "active";
        aside.appendChild(link);
      });
    });
    var out = el("button", "Sign out", "linkish");
    out.type = "button";
    out.addEventListener("click", function () {
      api("POST", "/api/auth/logout", {}).then(function () { location.assign("/login"); });
    });
    aside.appendChild(el("div", "", "group"));
    aside.appendChild(out);
    return aside;
  }

  function shell(active, title, note) {
    var root = el("div", null, "shell");
    root.appendChild(nav(active));
    var main = el("main");
    var top = el("div", null, "top");
    var titles = el("div");
    titles.appendChild(el("h1", title));
    if (note) titles.appendChild(el("p", note, "muted"));
    top.appendChild(titles);
    main.appendChild(top);
    root.appendChild(main);
    return { root: root, main: main };
  }

  function table(headers, rows) {
    var wrap = el("div", null, "card");
    var t = document.createElement("table");
    var head = document.createElement("tr");
    headers.forEach(function (h) { head.appendChild(el("th", h)); });
    t.appendChild(head);
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      row.forEach(function (cell) {
        var td = document.createElement("td");
        if (cell && cell.nodeType) td.appendChild(cell);
        else td.textContent = cell == null ? "" : String(cell);
        tr.appendChild(td);
      });
      t.appendChild(tr);
    });
    wrap.appendChild(t);
    return wrap;
  }

  function showError(main, res) {
    var msg = (res.body && res.body.title) || (res.body && res.body.error) || res.raw || ("HTTP " + res.status);
    main.appendChild(el("p", msg, "error"));
  }

  function loginView() {
    var box = el("div", null, "login");
    var form = el("form", null, "card");
    form.appendChild(el("h1", "Sign in"));
    form.appendChild(el("p", "Inspect agents and telemetry.", "muted"));
    var email = document.createElement("input");
    email.type = "email";
    email.required = true;
    email.autocomplete = "username";
    var password = document.createElement("input");
    password.type = "password";
    password.required = true;
    password.autocomplete = "current-password";
    var emailLabel = el("label", "Email");
    emailLabel.appendChild(email);
    var passwordLabel = el("label", "Password");
    passwordLabel.appendChild(password);
    form.appendChild(emailLabel);
    form.appendChild(passwordLabel);
    var err = el("p", "", "error");
    err.hidden = true;
    form.appendChild(err);
    var submit = el("button", "Sign in", "primary");
    submit.type = "submit";
    form.appendChild(submit);
    var github = el("a", "Continue with GitHub");
    github.href = "/api/auth/github/start";
    form.appendChild(github);
    var entra = el("a", "Sign in with Microsoft Entra ID");
    entra.href = "/api/auth/oidc/start";
    entra.hidden = true;
    form.appendChild(entra);
    var note = el("p", "", "muted");
    note.hidden = true;
    form.appendChild(note);
    fetch("/api/auth/methods", { credentials: "same-origin", headers: { accept: "application/json" } })
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (m) {
        if (!m) return;
        if (m.entra) entra.hidden = false;
        if (m.password === "break_glass") {
          note.hidden = false;
          note.textContent = "Password sign-in is for break-glass admins only.";
        }
      })
      .catch(function () {});
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      submit.disabled = true;
      fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ email: email.value, password: password.value }),
      }).then(function (res) {
        return res.text().then(function (text) { return { status: res.status, text: text }; });
      }).then(function (res) {
        submit.disabled = false;
        if (res.status !== 200) {
          err.hidden = false;
          err.textContent = "Sign-in failed.";
          return;
        }
        location.assign("/agents");
      });
    });
    box.appendChild(form);
    return box;
  }

  function renderAgents(view) {
    api("GET", "/api/agents").then(function (res) {
      if (res.status !== 200 || !Array.isArray(res.body)) return showError(view.main, res);
      var rows = res.body.map(function (agent) {
        var link = el("a", agent.hostname || agent.id);
        link.href = "/agents/" + agent.id;
        return [link, agent.status, agent.operating_system, agent.agent_version, agent.last_heartbeat_at];
      });
      view.main.appendChild(table(["Host", "Status", "OS", "Version", "Last heartbeat"], rows));
    });
  }

  function renderAgent(view, id) {
    api("GET", "/api/agents/" + id).then(function (res) {
      if (res.status !== 200) return showError(view.main, res);
      view.main.appendChild(el("p", (res.body.hostname || id) + " · " + (res.body.status || ""), "muted"));
    });
    renderProcessTree(view, id);
    renderActions(view, id);
    var live = el("div", null, "card");
    live.appendChild(el("p", "Live events", "muted"));
    var list = el("div");
    live.appendChild(list);
    view.main.appendChild(live);
    if (typeof EventSource !== "function") {
      list.textContent = "This browser has no EventSource.";
      return;
    }
    var source = new EventSource("/api/agents/" + id + "/events/stream", { withCredentials: true });
    source.onmessage = function (ev) {
      list.textContent = "";
      var events = [];
      try { events = JSON.parse(ev.data); } catch (e) { list.textContent = ev.data; return; }
      if (!events.length) list.textContent = "No events yet.";
      events.forEach(function (item) {
        list.appendChild(el("div", (item.occurred_at || "") + "  " + (item.type || "")));
      });
    };
    source.onerror = function () {
      if (!list.textContent) list.textContent = "Event stream reconnecting.";
    };
  }

  // Response actions. Lists recent actions and, for admins, lets one create
  // a signed action. The server signs each action; the agent verifies it.
  var ACTION_TYPES = [
    "kill_process",
    "suspend_process",
    "resume_process",
    "quarantine_file",
    "restore_file",
    "isolate_host",
    "release",
  ];

  function renderActions(view, id) {
    var card = el("div", null, "card");
    card.appendChild(el("p", "Response actions", "muted"));
    var listing = el("div");
    card.appendChild(listing);

    function reload() {
      api("GET", "/api/agents/" + id + "/actions").then(function (res) {
        listing.textContent = "";
        var rows = (res.status === 200 && Array.isArray(res.body)) ? res.body : [];
        if (!rows.length) {
          listing.appendChild(el("p", "No actions yet.", "muted"));
          return;
        }
        listing.appendChild(table(
          ["Type", "Status", "Requested"],
          rows.map(function (a) {
            var status = a.status || "";
            if (status === "awaiting_approval" && isAdmin()) {
              var approve = el("button", "Approve", "linkish");
              approve.type = "button";
              approve.addEventListener("click", function () {
                api("POST", "/api/agents/" + id + "/actions/" + a.id + "/approve", {}).then(function (res) {
                  if (res.status !== 200) return alert((res.body && res.body.title) || ("HTTP " + res.status));
                  reload();
                });
              });
              status = approve;
            }
            return [a.action_type || "", status, a.requested_at || ""];
          })
        ));
      });
    }

    if (canTriage()) {
      var form = el("div");
      var select = document.createElement("select");
      ACTION_TYPES.forEach(function (t) {
        var opt = document.createElement("option");
        opt.value = t;
        opt.textContent = t;
        select.appendChild(opt);
      });
      var payload = textInput("");
      payload.placeholder = '{"pid":1234} or {"path":"...","sha256":"..."}';
      var run = el("button", "Create");
      run.addEventListener("click", function () {
        var body = {};
        var raw = (payload.value || "").trim();
        if (raw.length) {
          try { body = JSON.parse(raw); } catch (e) {
            alert("Payload must be valid JSON.");
            return;
          }
        }
        api("POST", "/api/agents/" + id + "/actions", {
          action_type: select.value,
          payload: body,
        }).then(function (res) {
          if (res.status !== 201) return alert("Action failed: HTTP " + res.status);
          if (res.body && res.body.status === "awaiting_approval") alert("Queued. An admin must approve this action before the agent receives it.");
          payload.value = "";
          reload();
        });
      });
      form.appendChild(select);
      form.appendChild(payload);
      form.appendChild(run);
      card.appendChild(form);
    }

    view.main.appendChild(card);
    reload();
  }

  // Process tree from GET /api/agents/{id}/process-tree. Picking a process
  // shows its ancestors (oldest first), the process, and its descendants,
  // indented by depth.
  function processLabel(p) {
    var image = p.image || "";
    var name = image.split(/[\\/]/).pop() || ("pid " + p.pid);
    var text = name + "  (pid " + p.pid + ")";
    if (p.start_time) text += "  " + p.start_time;
    if (p.end_time) text += "  exited " + p.end_time;
    return text;
  }

  function renderProcessTree(view, id, initialEntity) {
    var card = el("div", null, "card");
    card.appendChild(el("p", "Process tree", "muted"));
    var picker = document.createElement("select");
    picker.setAttribute("aria-label", "Process");
    var tree = el("div", null, "process-tree");
    card.appendChild(picker);
    card.appendChild(tree);
    view.main.appendChild(card);

    function show(entityId) {
      tree.textContent = "";
      if (!entityId) return;
      api("GET", "/api/agents/" + id + "/process-tree?entity_id=" + encodeURIComponent(entityId)).then(function (res) {
        if (res.status !== 200 || !res.body) {
          tree.appendChild(el("p", (res.body && res.body.title) || "Process not found.", "error"));
          return;
        }
        var rows = [];
        var ancestors = (res.body.ancestors || []).slice().reverse();
        ancestors.forEach(function (p, i) { rows.push({ p: p, depth: i, kind: "ancestor" }); });
        var base = ancestors.length;
        rows.push({ p: res.body.process, depth: base, kind: "self" });
        (res.body.children || []).forEach(function (p) { rows.push({ p: p, depth: base + (p.depth || 1), kind: "child" }); });
        rows.forEach(function (row) {
          var line = el("div", null, "process-node " + row.kind);
          line.style.paddingLeft = (row.depth * 20) + "px";
          var link = el("a", processLabel(row.p));
          link.href = "#";
          link.title = (row.p.command_line || "") + (row.p.user_name ? "  user " + row.p.user_name : "");
          link.addEventListener("click", function (event) {
            event.preventDefault();
            picker.value = row.p.entity_id;
            show(row.p.entity_id);
          });
          if (row.kind === "self") link.style.fontWeight = "600";
          line.appendChild(el("span", row.depth > 0 ? "\u2514 " : "", "muted"));
          line.appendChild(link);
          tree.appendChild(line);
        });
      });
    }

    api("GET", "/api/agents/" + id + "/process-tree").then(function (res) {
      var list = (res.status === 200 && res.body && res.body.processes) || [];
      if (!list.length) {
        tree.textContent = "No processes recorded yet.";
        picker.hidden = true;
        return;
      }
      list.forEach(function (p) {
        var opt = document.createElement("option");
        opt.value = p.entity_id;
        opt.textContent = processLabel(p);
        picker.appendChild(opt);
      });
      picker.addEventListener("change", function () { show(picker.value); });
      if (initialEntity) {
        if (!list.some(function (p) { return p.entity_id === initialEntity; })) {
          var opt = document.createElement("option");
          opt.value = initialEntity;
          opt.textContent = "Incident root " + initialEntity;
          picker.insertBefore(opt, picker.firstChild);
        }
        picker.value = initialEntity;
        show(initialEntity);
      } else show(list[0].entity_id);
    });
  }

  function triageButtons(alertRow, done) {
    var box = el("span", null, "row");
    if (!canTriage() || alertRow.status === "resolved") return box;
    [["acknowledge", "Acknowledge"], ["resolve", "Resolve"]].forEach(function (pair) {
      if (pair[0] === "acknowledge" && alertRow.status === "acknowledged") return;
      var b = el("button", pair[1], "linkish");
      b.type = "button";
      b.addEventListener("click", function () {
        api("POST", "/api/alerts/" + alertRow.id + "/" + pair[0], {}).then(function (res) {
          if (res.status !== 200) return alert((res.body && res.body.title) || ("HTTP " + res.status));
          done();
        });
      });
      box.appendChild(b);
    });
    return box;
  }

  function renderAlerts(view) {
    var slot = el("div");
    view.main.appendChild(slot);
    function load() {
      api("GET", "/api/alerts?limit=100").then(function (res) {
        slot.textContent = "";
        if (res.status !== 200 || !Array.isArray(res.body)) return showError(slot, res);
        slot.appendChild(table(
          ["Id", "Severity", "Status", "Title", "Host", "Created", ""],
          res.body.map(function (row) {
            return [row.id, row.severity, row.status, row.title, row.hostname, row.created_at, triageButtons(row, load)];
          })
        ));
      });
    }
    load();
  }

  // Incidents (target-edr sections 7, 8 and 12).
  var INCIDENT_STATUSES = ["new", "investigating", "resolved", "false_positive"];

  function renderIncidents(view) {
    var filter = document.createElement("select");
    filter.setAttribute("aria-label", "Status");
    [["open", "Open"], ["", "All"]].concat(INCIDENT_STATUSES.map(function (s) { return [s, s.replace("_", " ")]; })).forEach(function (pair) {
      var opt = document.createElement("option");
      opt.value = pair[0];
      opt.textContent = pair[1];
      filter.appendChild(opt);
    });
    var bar = el("div", null, "row");
    bar.appendChild(filter);
    view.main.appendChild(bar);
    var slot = el("div");
    view.main.appendChild(slot);
    function load() {
      var q = filter.value ? "?status=" + encodeURIComponent(filter.value) : "";
      api("GET", "/api/incidents" + q).then(function (res) {
        slot.textContent = "";
        if (res.status !== 200 || !Array.isArray(res.body)) return showError(slot, res);
        if (!res.body.length) {
          slot.appendChild(el("p", "No incidents.", "card muted"));
          return;
        }
        slot.appendChild(table(
          ["Risk", "Severity", "Status", "Title", "Alerts", "Owner", "Techniques", "Last seen"],
          res.body.map(function (inc) {
            var link = el("a", inc.title);
            link.href = "/incidents/" + inc.id;
            return [String(inc.risk), inc.severity, inc.status.replace("_", " "), link, String(inc.alert_count),
              inc.owner_email || "", (inc.techniques || []).join(", "), inc.last_seen_at];
          })
        ));
      });
    }
    filter.addEventListener("change", load);
    load();
  }

  function renderIncident(view, id) {
    api("GET", "/api/incidents/" + id).then(function (res) {
      if (res.status !== 200 || !res.body) return showError(view.main, res);
      var inc = res.body;
      var head = el("div", null, "card");
      head.appendChild(el("h2", inc.title));
      head.appendChild(el("p", "Risk " + inc.risk + " (" + inc.severity + ") · " + inc.status.replace("_", " ") +
        " · grouped by " + inc.grouping + " · " + inc.alert_count + " alerts", "muted"));
      head.appendChild(el("p", "First seen " + inc.first_seen_at + " · last seen " + inc.last_seen_at, "muted"));
      if (inc.users && inc.users.length) head.appendChild(el("p", "Users: " + inc.users.join(", "), "muted"));
      view.main.appendChild(head);

      if (canTriage()) {
        var controls = el("div", null, "card row");
        var status = document.createElement("select");
        status.setAttribute("aria-label", "Incident status");
        INCIDENT_STATUSES.forEach(function (s) {
          var opt = document.createElement("option");
          opt.value = s;
          opt.textContent = s.replace("_", " ");
          if (s === inc.status) opt.selected = true;
          status.appendChild(opt);
        });
        var setStatus = el("button", "Set status", "linkish");
        setStatus.type = "button";
        setStatus.addEventListener("click", function () {
          api("POST", "/api/incidents/" + id + "/status", { status: status.value }).then(function (r) {
            if (r.status !== 200) return alert((r.body && r.body.title) || ("HTTP " + r.status));
            location.reload();
          });
        });
        var mine = el("button", inc.owner_user_id === me.id ? "Unassign" : "Assign to me", "linkish");
        mine.type = "button";
        mine.addEventListener("click", function () {
          var owner = inc.owner_user_id === me.id ? null : me.id;
          api("POST", "/api/incidents/" + id + "/assign", { owner_user_id: owner }).then(function (r) {
            if (r.status !== 200) return alert((r.body && r.body.title) || ("HTTP " + r.status));
            location.reload();
          });
        });
        controls.appendChild(status);
        controls.appendChild(setStatus);
        controls.appendChild(mine);
        controls.appendChild(el("span", "Owner: " + (inc.owner_email || "none"), "muted"));
        view.main.appendChild(controls);
      }

      // Why: every evidence item and its points (target-edr section 7).
      view.main.appendChild(el("h2", "Risk breakdown"));
      view.main.appendChild(table(
        ["Evidence", "Kind", "Weight", "Confidence", "Context", "Points"],
        (inc.risk_items || []).map(function (i) {
          return [i.label, i.kind, String(i.weight), String(i.confidence), String(i.context), String(i.points)];
        })
      ));
      view.main.appendChild(el("p", "Risk = 100 × (1 − Π(1 − points/100)), each item counted once.", "muted"));

      view.main.appendChild(el("h2", "ATT&CK techniques"));
      var techs = el("div", null, "row");
      (inc.techniques || []).forEach(function (t) {
        var a = el("a", t, "chip");
        a.href = "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/";
        a.rel = "noopener noreferrer";
        a.target = "_blank";
        techs.appendChild(a);
      });
      if (!(inc.techniques || []).length) techs.appendChild(el("span", "None mapped.", "muted"));
      view.main.appendChild(techs);

      view.main.appendChild(el("h2", "Timeline"));
      var alerts = inc.alerts || [];
      view.main.appendChild(table(
        ["When", "Host", "Rule", "Severity", "Status", "Event", "Grouped by", ""],
        alerts.map(function (a) {
          var proc = (a.payload && a.payload.process) || {};
          var what = a.event_type || "";
          if (proc.image || proc.command_line) what += ": " + (proc.command_line || proc.image);
          return [a.occurred_at, a.hostname, a.rule_name, a.severity, a.status, what, a.reason,
            triageButtons(a, function () { location.reload(); })];
        })
      ));

      // Process tree and response panel for each agent in the incident.
      var agentIds = inc.agent_ids || [];
      agentIds.forEach(function (agentId) {
        var host = (alerts.find(function (a) { return a.agent_id === agentId; }) || {}).hostname || agentId;
        view.main.appendChild(el("h2", host));
        var link = el("a", "Open agent");
        link.href = "/agents/" + agentId;
        view.main.appendChild(link);
        renderProcessTree(view, agentId, inc.root_entity_id);
        renderActions(view, agentId);
      });
    });
  }

  // ATT&CK coverage matrix: three separate states per technique (section 6).
  function renderAttack(view) {
    var platform = document.createElement("select");
    platform.setAttribute("aria-label", "Platform");
    [["", "All platforms"], ["windows", "Windows"], ["linux", "Linux"], ["macos", "macOS"]].forEach(function (pair) {
      var opt = document.createElement("option");
      opt.value = pair[0];
      opt.textContent = pair[1];
      platform.appendChild(opt);
    });
    var only = document.createElement("input");
    only.type = "checkbox";
    var onlyLabel = el("label", "Mapped techniques only", "row");
    onlyLabel.appendChild(only);
    var bar = el("div", null, "row");
    bar.appendChild(platform);
    bar.appendChild(onlyLabel);
    view.main.appendChild(bar);
    view.main.appendChild(el("p", "T telemetry from a healthy agent · D an enabled rule · R a response action applies. Each is checked on its own.", "muted"));
    var slot = el("div", null, "attack-matrix");
    view.main.appendChild(slot);
    function load() {
      var q = platform.value ? "?platform=" + platform.value : "";
      api("GET", "/api/attack/coverage" + q).then(function (res) {
        slot.textContent = "";
        if (res.status !== 200 || !res.body) return showError(slot, res);
        var data = res.body;
        slot.appendChild(el("p", "ATT&CK Enterprise " + data.attack_version, "muted"));
        var grid = el("div", null, "attack-grid");
        (data.tactics || []).forEach(function (tactic) {
          var col = el("div", null, "attack-col");
          col.appendChild(el("h3", tactic.name));
          (data.techniques || []).filter(function (t) {
            return t.tactics.indexOf(tactic.shortname) >= 0 && (!only.checked || t.mapped || t.detection.available);
          }).forEach(function (t) {
            var cell = el("div", null, "attack-cell");
            cell.title = t.id + " " + t.name +
              "\nTelemetry: " + (t.telemetry.available ? t.telemetry.sources.join(", ") : "none (expects " + (t.telemetry.expected.join(", ") || "unmapped") + ")") +
              "\nDetection: " + (t.detection.available ? t.detection.rules.join(", ") : "no enabled rule") +
              "\nResponse: " + (t.response.available ? t.response.actions.join(", ") : "none");
            cell.appendChild(el("span", t.id, "attack-id"));
            cell.appendChild(el("span", t.name, "attack-name"));
            var states = el("span", null, "attack-states");
            [["T", t.telemetry.available], ["D", t.detection.available], ["R", t.response.available]].forEach(function (st) {
              states.appendChild(el("span", st[0], st[1] ? "state on" : "state off"));
            });
            cell.appendChild(states);
            col.appendChild(cell);
          });
          grid.appendChild(col);
        });
        slot.appendChild(grid);
      });
    }
    platform.addEventListener("change", load);
    only.addEventListener("change", load);
    load();
  }

  function renderAudit(view) {
    api("GET", "/api/audit-logs?limit=100").then(function (res) {
      if (res.status !== 200 || !Array.isArray(res.body)) return showError(view.main, res);
      view.main.appendChild(table(
        ["When", "Action", "Target"],
        res.body.map(function (row) { return [row.occurred_at, row.action, row.target]; })
      ));
    });
  }

  function renderTokens(view) {
    var form = el("form", null, "row");
    var name = document.createElement("input");
    name.required = true;
    name.placeholder = "Token name";
    var button = el("button", "Create token", "primary");
    button.type = "submit";
    form.appendChild(name);
    form.appendChild(button);
    view.main.appendChild(form);
    var slot = el("div");
    view.main.appendChild(slot);
    function load() {
      api("GET", "/api/api-tokens").then(function (res) {
        slot.textContent = "";
        if (res.status !== 200 || !Array.isArray(res.body)) return showError(slot, res);
        slot.appendChild(table(
          ["Name", "Prefix", "Role", "Created"],
          res.body.map(function (token) { return [token.name, token.token_prefix, token.role, token.created_at]; })
        ));
      });
    }
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      api("POST", "/api/api-tokens", { name: name.value, role: "viewer" }).then(function (res) {
        if (res.status !== 200 && res.status !== 201) return showError(slot, res);
        var secret = res.body && (res.body.token || res.body.secret);
        if (secret) slot.appendChild(el("p", "Copy this token now. It is not shown again. " + secret));
        name.value = "";
        load();
      });
    });
    load();
  }

  function renderEnrollment(view) {
    var form = el("form", null, "row");
    var hours = document.createElement("input");
    hours.type = "number";
    hours.min = "1";
    hours.value = "24";
    var button = el("button", "Create enrollment token", "primary");
    button.type = "submit";
    form.appendChild(hours);
    form.appendChild(button);
    view.main.appendChild(form);
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      api("POST", "/api/enrollment-tokens", { lifetime_hours: Number(hours.value) }).then(function (res) {
        if (res.status !== 200 && res.status !== 201) return showError(view.main, res);
        var secret = res.body && (res.body.token || res.body.enrollment_token);
        view.main.appendChild(el("p", secret ? ("Token: " + secret) : "Token created."));
      });
    });
  }

  function renderUsers(view) {
    if (!me || me.role !== "admin") {
      view.main.appendChild(el("p", "Admin role required.", "error"));
      return;
    }
    var form = el("form", null, "row");
    var email = document.createElement("input");
    email.type = "email";
    email.required = true;
    email.placeholder = "email";
    var password = document.createElement("input");
    password.type = "password";
    password.required = true;
    password.placeholder = "password";
    var role = document.createElement("select");
    role.setAttribute("aria-label", "Role");
    ["viewer", "analyst", "admin"].forEach(function (r) {
      var opt = document.createElement("option");
      opt.value = r;
      opt.textContent = r;
      role.appendChild(opt);
    });
    var button = el("button", "Add user", "primary");
    button.type = "submit";
    form.appendChild(email);
    form.appendChild(password);
    form.appendChild(role);
    form.appendChild(button);
    view.main.appendChild(form);
    var slot = el("div");
    view.main.appendChild(slot);
    function load() {
      api("GET", "/api/users").then(function (res) {
        slot.textContent = "";
        if (res.status !== 200 || !Array.isArray(res.body)) return showError(slot, res);
        slot.appendChild(table(
          ["Email", "Name", "Role", "Disabled"],
          res.body.map(function (user) { return [user.email, user.name, user.role, user.disabled]; })
        ));
      });
    }
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      api("POST", "/api/users", { email: email.value, password: password.value, role: role.value }).then(function (res) {
        if (res.status !== 200 && res.status !== 201) return showError(slot, res);
        email.value = "";
        password.value = "";
        load();
      });
    });
    load();
  }

  function renderJobs(view) {
    api("GET", "/api/admin/jobs").then(function (res) {
      if (res.status !== 200 || !Array.isArray(res.body)) return showError(view.main, res);
      view.main.appendChild(table(
        ["Job", "Schedule", "Last status", "Last error"],
        res.body.map(function (job) { return [job.name, job.schedule, job.last_status, job.last_error]; })
      ));
    });
  }

  function renderMissing(view, text) {
    view.main.appendChild(el("p", text, "card"));
  }

  function isAdmin() {
    return me && me.role === "admin";
  }

  // Analysts and admins triage, hunt, respond and add exceptions (docs/api.md).
  function canTriage() {
    return me && (me.role === "admin" || me.role === "analyst");
  }

  function textInput(value) {
    var node = document.createElement("input");
    node.type = "text";
    node.value = value || "";
    node.style.width = "100%";
    return node;
  }

  function areaInput(value, rows) {
    var node = document.createElement("textarea");
    node.value = value || "";
    node.rows = rows || 8;
    node.style.width = "100%";
    node.spellcheck = false;
    return node;
  }

  function selectInput(options, value) {
    var node = document.createElement("select");
    options.forEach(function (opt) {
      var choice = document.createElement("option");
      choice.value = opt;
      choice.textContent = opt;
      if (opt === value) choice.selected = true;
      node.appendChild(choice);
    });
    return node;
  }

  function labeled(text, node) {
    var label = el("label", text);
    label.appendChild(node);
    return label;
  }

  function checkbox(text, checked) {
    var label = el("label", null);
    var box = document.createElement("input");
    box.type = "checkbox";
    box.checked = checked !== false;
    label.appendChild(box);
    label.appendChild(document.createTextNode(" " + text));
    return { label: label, box: box };
  }

  function formatName(format) {
    if (format === "sigma") return "Sigma";
    if (format === "ioc") return "IoC";
    return "Tawny";
  }

  function predicateText(rule) {
    return [rule.event_type, rule.payload_path, rule.operator, rule.match_value].filter(function (part) {
      return part != null && part !== "";
    }).join(" ");
  }

  var EXPOSURE_SAMPLE = [
    "{",
    "  \"id\": \"GHSA-example\",",
    "  \"summary\": \"Example compromise of left-pad\",",
    "  \"affected\": [",
    "    {",
    "      \"package\": { \"ecosystem\": \"npm\", \"name\": \"left-pad\" },",
    "      \"ranges\": [{ \"type\": \"ECOSYSTEM\", \"events\": [{ \"introduced\": \"1.0.0\" }, { \"fixed\": \"1.3.1\" }] }]",
    "    },",
    "    {",
    "      \"package\": { \"ecosystem\": \"editor-extension\", \"name\": \"evil.publisher.bad-ext\" },",
    "      \"versions\": [\"0.5.7\"]",
    "    }",
    "  ],",
    "  \"references\": [{ \"type\": \"ADVISORY\", \"url\": \"https://example.com/advisory\" }]",
    "}"
  ].join("\n");

  var HUNT_STARTERS = [
    ["PowerShell with EncodedCommand", "event_type:process_snapshot AND processes.command_line:\"-EncodedCommand\""],
    ["Connections to 1.1.1.1 in last 6h", "last:6h AND event_type:network_snapshot AND connections.remote_address:1.1.1.1"],
    ["Any cmd.exe or powershell.exe lineage", "processes.name:[cmd.exe, powershell.exe]"],
    ["FIM events on /etc/ in last 24h", "event_type:file_integrity AND path:/etc/"],
    ["Windows process starts from Office", "event_type:process_start AND parent.name:[winword.exe, excel.exe, outlook.exe]"],
    ["PowerShell script blocks with Invoke-Expression", "event_type:powershell_script_block AND script_block.text:*Invoke-Expression*"],
    ["Failed Windows logons in last 24h", "last:24h AND event_type:user_logon_failed"],
    ["Degraded Windows sensors", "event_type:sensor_health AND status:degraded"]
  ];

  function renderHunt(view) {
    var query = areaInput(HUNT_STARTERS[0][1], 6);
    var starters = el("div", null, "card");
    HUNT_STARTERS.forEach(function (item) {
      var button = el("button", item[0], "linkish");
      button.type = "button";
      button.addEventListener("click", function () { query.value = item[1]; });
      starters.appendChild(button);
    });
    view.main.appendChild(starters);
    var runForm = el("form", null, "card");
    runForm.appendChild(labeled("Query", query));
    var runButton = el("button", "Run hunt", "primary");
    runButton.type = "submit";
    runForm.appendChild(runButton);
    view.main.appendChild(runForm);
    var runStatus = el("div");
    view.main.appendChild(runStatus);
    runForm.addEventListener("submit", function (event) {
      event.preventDefault();
      runStatus.textContent = "";
      api("POST", "/api/hunts/run", { query: query.value, limit: 200 }).then(function (res) {
        if (res.status !== 200 || !res.body) return showError(runStatus, res);
        var warnings = res.body.warnings || [];
        warnings.forEach(function (warning) { runStatus.appendChild(el("p", warning, "muted")); });
        runStatus.appendChild(el("p", "Matches: " + res.body.match_count, "card"));
        var matches = res.body.matches || [];
        if (matches.length) {
          runStatus.appendChild(table(
            ["Host", "Type", "Occurred", "Payload"],
            matches.map(function (match) {
              return [match.hostname, match.event_type, match.occurred_at, JSON.stringify(match.payload)];
            })
          ));
        }
      });
    });

    var listSlot = el("div");
    view.main.appendChild(listSlot);
    var name = textInput("");
    if (isAdmin()) {
      var save = el("form", null, "card");
      save.appendChild(el("h2", "Save hunt"));
      save.appendChild(labeled("Name", name));
      var scheduled = checkbox("Scheduled", false);
      var alertOn = checkbox("Alert on match", false);
      var shared = checkbox("Shared", true);
      var severity = selectInput(["low", "medium", "high", "critical"], "medium");
      var cron = textInput("");
      var mitre = textInput("");
      save.appendChild(scheduled.label);
      save.appendChild(labeled("Schedule cron", cron));
      save.appendChild(alertOn.label);
      save.appendChild(labeled("Alert severity", severity));
      save.appendChild(labeled("MITRE techniques", mitre));
      save.appendChild(shared.label);
      var saveButton = el("button", "Save hunt", "primary");
      saveButton.type = "submit";
      save.appendChild(saveButton);
      view.main.appendChild(save);
      save.addEventListener("submit", function (event) {
        event.preventDefault();
        api("POST", "/api/hunts", {
          name: name.value,
          query: query.value,
          is_scheduled: scheduled.box.checked,
          schedule_cron: cron.value || null,
          alert_on_match: alertOn.box.checked,
          alert_severity: severity.value,
          mitre_techniques: mitre.value.split(",").map(function (part) { return part.trim(); }).filter(Boolean),
          is_shared: shared.box.checked
        }).then(function (res) {
          if (res.status !== 201) return showError(listSlot, res);
          name.value = "";
          loadHunts();
        });
      });
    }

    function loadHunts() {
      api("GET", "/api/hunts").then(function (res) {
        listSlot.textContent = "";
        if (res.status !== 200 || !Array.isArray(res.body)) return showError(listSlot, res);
        if (!res.body.length) {
          listSlot.appendChild(el("p", "No saved hunts.", "card"));
          return;
        }
        listSlot.appendChild(table(["Name", "Query", "Scheduled", "Last matches", ""], res.body.map(function (hunt) {
          var open = el("button", "Open", "linkish");
          open.type = "button";
          open.addEventListener("click", function () { query.value = hunt.query; });
          var cell = el("span");
          cell.appendChild(open);
          if (isAdmin()) {
            var remove = el("button", "Delete", "linkish");
            remove.type = "button";
            remove.addEventListener("click", function () {
              if (!window.confirm("Delete saved hunt " + hunt.name + "?")) return;
              api("DELETE", "/api/hunts/" + hunt.id, {}).then(function (del) {
                if (del.status !== 204) return showError(listSlot, del);
                loadHunts();
              });
            });
            cell.appendChild(remove);
          }
          return [hunt.name, hunt.query, hunt.is_scheduled ? "yes" : "no", hunt.last_match_count, cell];
        })));
      });
    }
    loadHunts();
  }

  function renderDetections(view) {
    var status = el("div");
    view.main.appendChild(status);
    var tableSlot = el("div");
    view.main.appendChild(tableSlot);
    function loadRules() {
      api("GET", "/api/alert-rules").then(function (res) {
        tableSlot.textContent = "";
        if (res.status !== 200 || !Array.isArray(res.body)) return showError(tableSlot, res);
        if (!res.body.length) {
          tableSlot.appendChild(el("p", "No detection rules have been imported yet.", "card"));
          return;
        }
        tableSlot.appendChild(table(["Rule", "Format", "Severity", "Predicate", "State"], res.body.map(function (rule) {
          var title = rule.name + (rule.external_id ? " (" + rule.external_id + ")" : " (" + rule.id + ")");
          return [title, formatName(rule.format), rule.severity, predicateText(rule), rule.is_enabled ? "Enabled" : "Disabled"];
        })));
      });
    }
    if (!isAdmin()) {
      view.main.appendChild(el("p", "Import is limited to admins.", "muted"));
      loadRules();
      return;
    }

    var sigma = el("form", null, "card");
    sigma.appendChild(el("h2", "Import Sigma"));
    var sigmaYaml = areaInput("", 8);
    sigmaYaml.placeholder = "Sigma rule YAML";
    var sigmaEnabled = checkbox("Enable after import", true);
    sigma.appendChild(labeled("Rule YAML", sigmaYaml));
    sigma.appendChild(sigmaEnabled.label);
    var sigmaButton = el("button", "Import Sigma", "primary");
    sigmaButton.type = "submit";
    sigma.appendChild(sigmaButton);
    sigma.addEventListener("submit", function (event) {
      event.preventDefault();
      status.textContent = "";
      api("POST", "/api/alert-rules/sigma", { rule_yaml: sigmaYaml.value, is_enabled: sigmaEnabled.box.checked }).then(function (res) {
        if (res.status !== 201) return showError(status, res);
        status.appendChild(el("p", "Imported Sigma rule " + ((res.body && res.body.name) || ""), "card"));
        loadRules();
      });
    });
    view.main.appendChild(sigma);

    var ioc = el("form", null, "card");
    ioc.appendChild(el("h2", "Import indicators"));
    var iocBody = areaInput("", 6);
    var iocFormat = selectInput(["auto", "stix", "raw"], "stix");
    var iocSeverity = selectInput(["low", "medium", "high", "critical"], "high");
    var iocEnabled = checkbox("Enable after import", true);
    ioc.appendChild(labeled("Definition", iocBody));
    ioc.appendChild(labeled("Source format", iocFormat));
    ioc.appendChild(labeled("Severity", iocSeverity));
    ioc.appendChild(iocEnabled.label);
    var iocButton = el("button", "Import indicators", "primary");
    iocButton.type = "submit";
    ioc.appendChild(iocButton);
    ioc.addEventListener("submit", function (event) {
      event.preventDefault();
      status.textContent = "";
      api("POST", "/api/alert-rules/iocs", {
        definition: iocBody.value,
        source_format: iocFormat.value,
        severity: iocSeverity.value,
        is_enabled: iocEnabled.box.checked
      }).then(function (res) {
        if (res.status !== 201 || !res.body) return showError(status, res);
        status.appendChild(el("p", "Imported " + res.body.rules.length + " indicator rule(s).", "card"));
        loadRules();
      });
    });
    view.main.appendChild(ioc);

    var exposure = el("form", null, "card");
    exposure.appendChild(el("h2", "Import package exposures"));
    exposure.appendChild(el("p", "Paste an OSV advisory or a simple [{ecosystem, name, version_pattern}] list. Each affected package becomes a rule.", "muted"));
    var definition = areaInput(EXPOSURE_SAMPLE, 14);
    var severity = selectInput(["low", "medium", "high", "critical"], "high");
    var enabled = checkbox("Enable after import", true);
    exposure.appendChild(labeled("Definition", definition));
    exposure.appendChild(labeled("Severity", severity));
    exposure.appendChild(enabled.label);
    var importButton = el("button", "Import exposures", "primary");
    importButton.type = "submit";
    exposure.appendChild(importButton);
    exposure.addEventListener("submit", function (event) {
      event.preventDefault();
      status.textContent = "";
      if (!definition.value.trim()) {
        status.appendChild(el("p", "Definition is empty.", "error"));
        return;
      }
      api("POST", "/api/alert-rules/exposures", {
        definition: definition.value,
        severity: severity.value,
        is_enabled: enabled.box.checked
      }).then(function (res) {
        if (res.status !== 201 || !res.body || !res.body.rules) return showError(status, res);
        var skipped = res.body.skipped_entries && res.body.skipped_entries.length
          ? " (" + res.body.skipped_entries.length + " skipped)"
          : "";
        status.appendChild(el("p", "Imported " + res.body.rules.length + " package exposure rule(s)" + skipped + ".", "card"));
        loadRules();
      });
    });
    view.main.appendChild(exposure);
    view.main.appendChild(tableSlot);
    loadRules();
  }

  function renderThreatIntel(view) {
    var status = el("div");
    view.main.appendChild(status);
    var listSlot = el("div");
    view.main.appendChild(listSlot);
    function loadFeeds() {
      api("GET", "/api/threat-intel-feeds").then(function (res) {
        listSlot.textContent = "";
        if (res.status !== 200 || !Array.isArray(res.body)) return showError(listSlot, res);
        if (!res.body.length) {
          listSlot.appendChild(el("p", "No threat intel feeds.", "card"));
          return;
        }
        listSlot.appendChild(table(
          ["Name", "Kind", "Status", "Imported", "Last error", ""],
          res.body.map(function (feed) {
            var actions = el("span");
            if (isAdmin()) {
              var run = el("button", "Run", "linkish");
              run.type = "button";
              run.addEventListener("click", function () {
                api("POST", "/api/threat-intel-feeds/" + feed.id + "/run", {}).then(function (done) {
                  if (done.status !== 200) return showError(status, done);
                  loadFeeds();
                });
              });
              var remove = el("button", "Delete", "linkish");
              remove.type = "button";
              remove.addEventListener("click", function () {
                if (!window.confirm("Delete feed " + feed.name + "? Existing imported IoCs will stay as alert rules.")) return;
                api("DELETE", "/api/threat-intel-feeds/" + feed.id, {}).then(function (done) {
                  if (done.status !== 204) return showError(status, done);
                  loadFeeds();
                });
              });
              actions.appendChild(run);
              actions.appendChild(remove);
            }
            return [feed.name, feed.kind, feed.status, feed.last_imported_count, feed.last_error, actions];
          })
        ));
      });
    }
    if (isAdmin()) {
      var form = el("form", null, "card");
      form.appendChild(el("h2", "Add feed"));
      var name = textInput("");
      var kind = selectInput(["generic_csv", "osv_vulnerabilities"], "generic_csv");
      var url = textInput("https://lists.blocklist.de/lists/all.txt");
      var headerName = textInput("");
      var headerValue = textInput("");
      var severity = selectInput(["low", "medium", "high", "critical"], "high");
      var interval = textInput("60");
      var enabled = checkbox("Enabled", true);
      form.appendChild(labeled("Name", name));
      form.appendChild(labeled("Kind", kind));
      form.appendChild(labeled("URL", url));
      form.appendChild(labeled("Auth header name", headerName));
      form.appendChild(labeled("Auth header value", headerValue));
      form.appendChild(labeled("Default severity", severity));
      form.appendChild(labeled("Interval minutes", interval));
      form.appendChild(enabled.label);
      var button = el("button", "Create feed", "primary");
      button.type = "submit";
      form.appendChild(button);
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        status.textContent = "";
        api("POST", "/api/threat-intel-feeds", {
          name: name.value,
          kind: kind.value,
          url: url.value,
          auth_header_name: headerName.value || null,
          auth_header_value: headerValue.value || null,
          default_severity: severity.value,
          interval_minutes: Number(interval.value),
          is_enabled: enabled.box.checked
        }).then(function (res) {
          if (res.status !== 201) return showError(status, res);
          name.value = "";
          headerValue.value = "";
          loadFeeds();
        });
      });
      view.main.appendChild(form);
    }
    view.main.appendChild(listSlot);
    loadFeeds();
  }

  function renderSuppressions(view) {
    var status = el("div");
    view.main.appendChild(status);
    var listSlot = el("div");
    view.main.appendChild(listSlot);
    var ruleSelect = selectInput([], "");
    var agentSelect = selectInput([""], "");
    function loadRulesAndAgents() {
      api("GET", "/api/alert-rules").then(function (res) {
        if (res.status !== 200 || !Array.isArray(res.body)) return;
        ruleSelect.textContent = "";
        res.body.forEach(function (rule) {
          var choice = document.createElement("option");
          choice.value = rule.id;
          choice.textContent = rule.name;
          ruleSelect.appendChild(choice);
        });
      });
      api("GET", "/api/agents").then(function (res) {
        if (res.status !== 200 || !Array.isArray(res.body)) return;
        agentSelect.textContent = "";
        var any = document.createElement("option");
        any.value = "";
        any.textContent = "Any agent";
        agentSelect.appendChild(any);
        res.body.forEach(function (agent) {
          var choice = document.createElement("option");
          choice.value = agent.id;
          choice.textContent = agent.hostname || agent.id;
          agentSelect.appendChild(choice);
        });
      });
    }
    function loadList() {
      api("GET", "/api/suppression-rules").then(function (res) {
        listSlot.textContent = "";
        if (res.status !== 200 || !Array.isArray(res.body)) return showError(listSlot, res);
        if (!res.body.length) {
          listSlot.appendChild(el("p", "No suppression rules.", "card"));
          return;
        }
        listSlot.appendChild(table(
          ["Name", "Scope", "Rule", "Agent", "Match", "State", ""],
          res.body.map(function (rule) {
            var remove = el("span");
            if (isAdmin()) {
              var button = el("button", "Delete", "linkish");
              button.type = "button";
              button.addEventListener("click", function () {
                if (!window.confirm("Delete suppression " + rule.name + "?")) return;
                api("DELETE", "/api/suppression-rules/" + rule.id, {}).then(function (done) {
                  if (done.status !== 204) return showError(status, done);
                  loadList();
                });
              });
              remove.appendChild(button);
            }
            var match = [rule.payload_path, rule.operator, rule.match_value].filter(Boolean).join(" ");
            return [rule.name, rule.scope, rule.alert_rule_name, rule.agent_hostname, match, rule.is_enabled ? "Enabled" : "Disabled", remove];
          })
        ));
      });
    }
    if (canTriage()) {
      var form = el("form", null, "card");
      form.appendChild(el("h2", "Add suppression"));
      var name = textInput("");
      var reason = textInput("");
      var scope = selectInput(["all_rules", "specific_rule"], "all_rules");
      var path = textInput("");
      var operator = selectInput(["contains", "equals", "exists", "greater_than", "less_than"], "contains");
      var match = textInput("");
      var enabled = checkbox("Enabled", true);
      form.appendChild(labeled("Name", name));
      form.appendChild(labeled("Reason", reason));
      form.appendChild(labeled("Scope", scope));
      form.appendChild(labeled("Alert rule", ruleSelect));
      form.appendChild(labeled("Agent", agentSelect));
      form.appendChild(labeled("Payload path", path));
      form.appendChild(labeled("Operator", operator));
      form.appendChild(labeled("Match value", match));
      form.appendChild(enabled.label);
      var button = el("button", "Create suppression", "primary");
      button.type = "submit";
      form.appendChild(button);
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        status.textContent = "";
        api("POST", "/api/suppression-rules", {
          name: name.value,
          reason: reason.value || null,
          scope: scope.value,
          alert_rule_id: scope.value === "specific_rule" ? ruleSelect.value : null,
          agent_id: agentSelect.value || null,
          payload_path: path.value || null,
          operator: operator.value,
          match_value: operator.value === "exists" ? null : match.value,
          is_enabled: enabled.box.checked,
          expires_at: null
        }).then(function (res) {
          if (res.status !== 201) return showError(status, res);
          name.value = "";
          loadList();
        });
      });
      view.main.appendChild(form);
      loadRulesAndAgents();
    }
    view.main.appendChild(listSlot);
    loadList();
  }

  function boot() {
    var path = location.pathname;
    if (path.length > 1 && path.charAt(path.length - 1) === "/") path = path.slice(0, -1);
    if (path === "/login") {
      document.getElementById("app").replaceWith(loginView());
      return;
    }
    api("GET", "/api/auth/session").then(function (res) {
      if (res.status !== 200) {
        location.assign("/login");
        return;
      }
      me = res.body;
      csrf = res.body.csrf_token || null;
      var view;
      var agent = path.match(/^\/agents\/([0-9a-f-]{36})$/i);
      var incident = path.match(/^\/incidents\/([0-9a-f-]{36})$/i);
      if (path === "/" || path === "") {
        view = shell("/", "Dashboard", "Agents and open alerts.");
        renderAgents(view);
        renderAlerts(view);
      } else if (path === "/agents") {
        view = shell("/agents", "Agents", null);
        renderAgents(view);
      } else if (agent) {
        view = shell("/agents", "Agent", "Live telemetry.");
        renderAgent(view, agent[1]);
      } else if (path === "/alerts") {
        view = shell("/alerts", "Alerts", null);
        renderAlerts(view);
      } else if (path === "/incidents") {
        view = shell("/incidents", "Incidents", "Related alerts grouped by host, lineage and shared artefacts.");
        renderIncidents(view);
      } else if (incident) {
        view = shell("/incidents", "Incident", null);
        renderIncident(view, incident[1]);
      } else if (path === "/attack") {
        view = shell("/attack", "ATT&CK coverage", "Telemetry, detection and response for each technique.");
        renderAttack(view);
      } else if (path === "/hunt") {
        view = shell("/hunt", "Hunt across telemetry", "Write a query, run it, then save or schedule it.");
        renderHunt(view);
      } else if (path === "/detections") {
        view = shell("/detections", "Detection imports", "Sigma, indicators, and package exposures.");
        renderDetections(view);
      } else if (path === "/threat-intel") {
        view = shell("/threat-intel", "Threat intel", "Starter feeds refresh every 10 minutes.");
        renderThreatIntel(view);
      } else if (path === "/suppressions") {
        view = shell("/suppressions", "Suppressions", "Matching runs during detection.");
        renderSuppressions(view);
      } else if (path === "/audit") {
        view = shell("/audit", "Audit", null);
        renderAudit(view);
      } else if (path === "/api-tokens") {
        view = shell("/api-tokens", "API tokens", null);
        renderTokens(view);
      } else if (path === "/enrollment") {
        view = shell("/enrollment", "Enrollment", "Single-use wte_ tokens.");
        renderEnrollment(view);
      } else if (path === "/users") {
        view = shell("/users", "Users", "Roles: admin, analyst, viewer. Default is viewer. No self-service signup.");
        renderUsers(view);
      } else if (path === "/admin/jobs") {
        view = shell("/admin/jobs", "Jobs", "In-process scheduler. Hangfire is gone.");
        renderJobs(view);
      } else {
        view = shell("/", "Not found", null);
        renderMissing(view, "No page for " + path);
      }
      document.getElementById("app").replaceWith(view.root);
    });
  }

  boot();
})();
