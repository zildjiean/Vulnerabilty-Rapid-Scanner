(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const store = { get: (k) => { try { return localStorage.getItem(k); } catch (e) { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) {} } };

  // ---------- Theme ----------
  const themeBtn = $("#theme-toggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const root = document.documentElement;
      const sysDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      const current = root.getAttribute("data-theme") || (sysDark ? "dark" : "light");
      const next = current === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      store.set("zdrs-theme", next);
    });
  }

  // ---------- Sidebar ----------
  const shell = $("#shell");
  if (shell) {
    if (document.documentElement.classList.contains("pre-collapsed")) shell.classList.add("collapsed");
    $("#collapse-btn")?.addEventListener("click", () => {
      shell.classList.toggle("collapsed");
      store.set("zdrs-sidebar", shell.classList.contains("collapsed") ? "collapsed" : "open");
    });
    const navToggle = $("#nav-toggle");
    const closeNav = () => { shell.classList.remove("nav-open"); navToggle?.setAttribute("aria-expanded", "false"); };
    navToggle?.addEventListener("click", () => {
      const open = shell.classList.toggle("nav-open");
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    $("#nav-overlay")?.addEventListener("click", closeNav);
    $$("[data-nav-group]").forEach((g) => {
      const btn = $(".nav-group-label", g);
      const key = "zdrs-nav-" + g.dataset.navGroup;
      const setOpen = (open) => { g.classList.toggle("closed", !open); btn.setAttribute("aria-expanded", open ? "true" : "false"); };
      const saved = store.get(key);
      if (saved && !g.hasAttribute("data-has-active")) setOpen(saved === "open");
      btn.addEventListener("click", () => { const open = g.classList.contains("closed"); setOpen(open); store.set(key, open ? "open" : "closed"); });
    });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeNav(); });
  }

  // ---------- Toasts ----------
  const toasts = $("#toasts");
  const toast = (text, kind = "ok") => {
    if (!toasts || !text) return;
    const el = document.createElement("div");
    el.className = "toast " + (kind === "error" ? "error" : "");
    el.setAttribute("role", "status");
    el.innerHTML = '<svg class="icon"><use href="#i-' + (kind === "error" ? "alert-circle" : "check-circle") + '"/></svg><div></div><button type="button" class="ghost sm icon-btn" aria-label="Dismiss"><svg class="icon sm"><use href="#i-x"/></svg></button>';
    el.querySelector("div").textContent = text;
    el.querySelector("button").addEventListener("click", () => el.remove());
    toasts.appendChild(el);
    setTimeout(() => el.remove(), 5000);
  };
  if (toasts && toasts.dataset.msg) {
    toast(toasts.dataset.msg);
    if (history.replaceState) { const u = new URL(location.href); u.searchParams.delete("msg"); history.replaceState(null, "", u.pathname + (u.search || "") + u.hash); }
  }
  window.zdrsToast = toast;

  // ---------- Confirm dialogs: <form data-confirm="..."> or <button type=submit data-confirm="..."> ----------
  const dlg = $("#confirm-dialog");
  let pending = null; // { form, submitter }
  const askConfirm = (message, form, submitter) => {
    pending = { form, submitter };
    $("#confirm-text").textContent = message;
    if (dlg && typeof dlg.showModal === "function") dlg.showModal();
    else if (window.confirm(message)) { form.dataset.confirmed = "1"; form.requestSubmit(submitter || undefined); }
  };
  $$("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (e) => {
      if (form.dataset.confirmed === "1") return;
      e.preventDefault();
      askConfirm(form.dataset.confirm, form, e.submitter || null);
    });
  });
  $$("button[type=submit][data-confirm]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const form = btn.form;
      if (!form || form.dataset.confirmed === "1") return;
      e.preventDefault();
      askConfirm(btn.dataset.confirm, form, btn);
    });
  });
  $("#confirm-cancel")?.addEventListener("click", () => { pending = null; dlg.close(); });
  $("#confirm-ok")?.addEventListener("click", () => {
    if (!pending) return;
    const { form, submitter } = pending; pending = null;
    form.dataset.confirmed = "1"; dlg.close(); form.requestSubmit(submitter || undefined);
    setTimeout(() => { delete form.dataset.confirmed; }, 0);
  });

  // ---------- Loading state on submit ----------
  $$("form").forEach((form) => {
    form.addEventListener("submit", (e) => {
      const sub = e.submitter || null;
      if ((form.dataset.confirm || (sub && sub.dataset.confirm)) && form.dataset.confirmed !== "1") return;
      const btn = sub || form.querySelector('button[type="submit"], button:not([type])');
      if (!btn) return;
      btn.classList.add("is-loading");
      btn.setAttribute("aria-busy", "true");
      const sp = document.createElement("span"); sp.className = "spinner"; btn.prepend(sp);
      setTimeout(() => { btn.disabled = true; }, 0);
      setTimeout(() => { btn.disabled = false; btn.classList.remove("is-loading"); sp.remove(); btn.removeAttribute("aria-busy"); }, 15000);
    });
  });

  // ---------- Sortable tables: <th data-sort="text|num"> ----------
  $$("table.data th[data-sort]").forEach((th) => {
    th.setAttribute("tabindex", "0");
    th.setAttribute("role", "columnheader");
    const run = () => {
      const table = th.closest("table");
      const tbody = table.tBodies[0];
      const idx = Array.from(th.parentNode.children).indexOf(th);
      const type = th.dataset.sort;
      const dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
      $$("th", table).forEach((o) => o.removeAttribute("aria-sort"));
      th.setAttribute("aria-sort", dir);
      const val = (r) => { const c = r.cells[idx]; const t = (c?.dataset.value ?? c?.textContent ?? "").trim(); return type === "num" ? parseFloat(t.replace(/[^0-9.\-]/g, "")) || 0 : t.toLowerCase(); };
      const cmp = (a, b) => { const x = val(a), y = val(b); return (x < y ? -1 : x > y ? 1 : 0) * (dir === "ascending" ? 1 : -1); };
      // Group header rows (tr.group-row) split the body into segments; each segment is sorted on its own.
      const segments = []; let cur = { head: null, rows: [] };
      Array.from(tbody.rows).forEach((r) => {
        if (r.dataset.empty) return;
        if (r.classList.contains("group-row")) { segments.push(cur); cur = { head: r, rows: [] }; } else cur.rows.push(r);
      });
      segments.push(cur);
      segments.forEach((seg) => { seg.rows.sort(cmp); if (seg.head) tbody.appendChild(seg.head); seg.rows.forEach((r) => tbody.appendChild(r)); });
    };
    th.addEventListener("click", run);
    th.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); run(); } });
  });

  // ---------- Select-all + selection counter ----------
  $$("[data-select-all]").forEach((cb) => {
    const name = cb.dataset.selectAll;
    const boxes = () => $$('input[name="' + name + '"]');
    const counter = $("[data-selected-count]");
    const update = () => { const n = boxes().filter((x) => x.checked).length; if (counter) counter.textContent = n; $$("[data-needs-selection]").forEach((b) => { b.disabled = n === 0; }); };
    cb.addEventListener("change", () => { boxes().forEach((x) => { x.checked = cb.checked; }); update(); });
    boxes().forEach((x) => x.addEventListener("change", update));
    update();
  });

  // ---------- Grouped tables: collapse/expand + group selection ----------
  $$("table.data").forEach((table) => {
    const groupRows = $$("tr.group-row", table);
    if (!groupRows.length) return;
    const rowsOf = (key) => $$('tr[data-group="' + CSS.escape(key) + '"]:not(.group-row)', table);
    const setOpen = (head, open) => {
      const btn = $("[data-group-toggle]", head);
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      head.classList.toggle("is-collapsed", !open);
      rowsOf(head.dataset.group).forEach((r) => { r.hidden = !open; });
    };
    groupRows.forEach((head) => {
      $("[data-group-toggle]", head).addEventListener("click", () => setOpen(head, $("[data-group-toggle]", head).getAttribute("aria-expanded") !== "true"));
    });
    $$("[data-groups-expand]").forEach((b) => b.addEventListener("click", () => groupRows.forEach((h) => setOpen(h, true))));
    $$("[data-groups-collapse]").forEach((b) => b.addEventListener("click", () => groupRows.forEach((h) => setOpen(h, false))));
    const syncGroupBoxes = () => groupRows.forEach((head) => {
      const gb = $("[data-group-select]", head); if (!gb) return;
      const boxes = rowsOf(head.dataset.group).map((r) => $('input[type="checkbox"]', r)).filter(Boolean);
      const n = boxes.filter((x) => x.checked).length;
      gb.checked = n > 0 && n === boxes.length; gb.indeterminate = n > 0 && n < boxes.length;
    });
    $$("[data-group-select]", table).forEach((gb) => gb.addEventListener("change", () => {
      const boxes = rowsOf(gb.dataset.groupSelect).map((r) => $('input[type="checkbox"]', r)).filter(Boolean);
      boxes.forEach((x) => { x.checked = gb.checked; });
      // let the select-all counter recompute, then settle the group checkbox state
      if (boxes.length) boxes[0].dispatchEvent(new Event("change", { bubbles: true }));
      syncGroupBoxes();
    }));
    table.addEventListener("change", (e) => { if (e.target.matches('input[type="checkbox"]:not([data-group-select])')) syncGroupBoxes(); });
    syncGroupBoxes();
  });

  // ---------- Copy to clipboard: <button data-copy="text"> ----------
  $$("[data-copy]").forEach((b) => b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy); toast("Copied to clipboard"); }
    catch (e) { toast("Copy failed: select the text and copy it manually", "error"); }
  }));

  // ---------- Proof: reveal the part cut at PROOF_LIMIT ----------
  $$("[data-proof-more]").forEach((b) => b.addEventListener("click", () => {
    const rest = b.parentElement.querySelector(".proof-rest");
    if (rest) rest.hidden = false;
    b.remove();
  }));

  // ---------- Issue page: search the template index to link a verification template ----------
  const vq = document.getElementById("verify-q"), vres = document.getElementById("verify-results");
  if (vq && vres) {
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    let timer;
    const run = async () => {
      const q = vq.value.trim();
      if (q.length < 2) { vres.innerHTML = ""; return; }
      try {
        const rows = await (await fetch("/templates/search?q=" + encodeURIComponent(q))).json();
        vres.innerHTML = rows.length ? "" : '<p class="small text-2">No templates match.</p>';
        rows.slice(0, 20).forEach((row, i) => {
          const l = document.createElement("label");
          l.className = "list-row row center";
          l.style.gap = "8px";
          l.innerHTML = `<input type="radio" name="template_id" value="${esc(row.template_id)}"${i === 0 ? " checked" : ""}>` +
            `<span class="cell-mono small">${esc(row.template_id)}</span><span class="small">${esc(row.name)}</span>` +
            `<span class="badge sev-${esc(row.severity)}">${esc(row.severity)}</span>`;
          vres.appendChild(l);
        });
      } catch (e) { vres.innerHTML = '<p class="small text-2">Search failed; try again.</p>'; }
    };
    vq.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(run, 250); });
  }

  // ---------- Schedule form: show the fields that apply to the chosen kind / frequency ----------
  $$(".schedule-form").forEach((form) => {
    const kind = $("[data-schedule-kind]", form);
    const freq = $("[data-schedule-frequency]", form);
    const sync = () => {
      $$("[data-show-kind]", form).forEach((el) => { el.hidden = !el.dataset.showKind.split(" ").includes(kind.value); });
      $$("[data-show-frequency]", form).forEach((el) => { el.hidden = !el.dataset.showFrequency.split(" ").includes(freq.value); });
    };
    kind?.addEventListener("change", sync);
    freq?.addEventListener("change", sync);
    sync();
  });

  // ---------- Live job log (SSE) ----------
  const log = $("#joblog");
  if (log && log.dataset.live === "yes") {
    const id = log.dataset.jobId;
    const statusEl = $("#job-status");
    const es = new EventSource("/jobs/" + id + "/stream");
    log.textContent = "";
    es.addEventListener("log", (e) => { log.textContent += e.data + "\n"; log.scrollTop = log.scrollHeight; });
    es.addEventListener("done", (e) => {
      es.close();
      if (statusEl) { statusEl.textContent = e.data; statusEl.className = "status st-" + e.data; }
      toast("Job #" + id + " " + e.data, e.data === "done" ? "ok" : "error");
      setTimeout(() => location.reload(), 900);
    });
    es.addEventListener("error", () => {});
  }

  // ---------- Nuclei mode panels + group filter ----------
  const modeRadios = $$('input[name="mode"]');
  if (modeRadios.length) {
    const apply = () => {
      const mode = modeRadios.find((r) => r.checked)?.value || "selected";
      $$("[data-mode-panel]").forEach((pnl) => { pnl.hidden = pnl.dataset.modePanel !== mode; });
      const chip = $("#tpl-selected-chip"); if (chip) chip.hidden = mode !== "selected";
    };
    modeRadios.forEach((r) => r.addEventListener("change", apply));
    apply();
    const gf = $("#group-filter"), gl = $("#group-list"), gc = $("#group-count");
    const countGroups = () => { if (gc) gc.textContent = $$('input[name="groups"]:checked').length; };
    if (gf && gl) {
      gf.addEventListener("input", () => {
        const term = gf.value.trim().toLowerCase();
        $$(".group-item", gl).forEach((it) => { it.hidden = term !== "" && !it.dataset.key.toLowerCase().includes(term); });
      });
      gl.addEventListener("change", countGroups);
      countGroups();
    }
  }

  // ---------- Nuclei scan profile -> rate limit / timeout defaults ----------
  $$('input[name="profile"]').forEach((r) => r.addEventListener("change", () => {
    if (!r.checked) return;
    const rate = $("#rate_limit"), to = $("#timeout");
    if (rate && r.dataset.rate) rate.value = r.dataset.rate;
    if (to && r.dataset.timeout) to.value = r.dataset.timeout;
  }));

  // ---------- Nuclei template picker ----------
  const q = $("#tpl-q");
  if (q) {
    const results = $("#tpl-results"), selected = $("#tpl-selected"), count = $("#tpl-count"), sev = $("#tpl-sev"), src = $("#tpl-src");
    let timer = null;
    const emptyEl = $(".tpl-empty");
    const refreshCount = () => { const n = selected.children.length; count.textContent = n; if (emptyEl) emptyEl.classList.toggle("show", n === 0); };
    const isSelected = (p) => !!selected.querySelector('li[data-path="' + CSS.escape(p) + '"]');
    const mkBadge = (s) => { const b = document.createElement("span"); b.className = "badge sev-" + s; b.textContent = s; return b; };
    const addSel = (t) => {
      if (isSelected(t.path)) return;
      const li = document.createElement("li");
      li.dataset.path = t.path;
      const inp = document.createElement("input"); inp.type = "hidden"; inp.name = "template_paths"; inp.value = t.path;
      const b = document.createElement("b"); b.textContent = t.template_id;
      const n = document.createElement("span"); n.className = "n"; n.textContent = t.name;
      const rm = document.createElement("button"); rm.type = "button"; rm.className = "ghost sm icon-btn rm"; rm.setAttribute("aria-label", "Remove " + t.template_id); rm.innerHTML = '<svg class="icon sm"><use href="#i-x"/></svg>';
      li.append(inp, mkBadge(t.severity), b, n, rm);
      selected.appendChild(li); refreshCount();
    };
    selected.addEventListener("click", (e) => { const btn = e.target.closest(".rm"); if (btn) { btn.closest("li").remove(); refreshCount(); } });
    const search = async () => {
      const term = q.value.trim();
      if (term.length < 2) { results.innerHTML = ""; return; }
      const r = await fetch("/templates/search?q=" + encodeURIComponent(term) + "&severity=" + encodeURIComponent(sev.value) + "&source=" + encodeURIComponent(src.value));
      const items = await r.json();
      results.innerHTML = "";
      if (!items.length) { const d = document.createElement("div"); d.className = "tpl-item muted"; d.textContent = "No templates match."; results.appendChild(d); return; }
      const head = document.createElement("div"); head.className = "tpl-item head";
      const info = document.createElement("span"); info.className = "small muted"; info.textContent = items.length + " result" + (items.length === 1 ? "" : "s");
      const all = document.createElement("button"); all.type = "button"; all.className = "sm"; all.textContent = "Add all"; all.addEventListener("click", () => items.forEach(addSel));
      head.append(info, all); results.appendChild(head);
      items.forEach((t) => {
        const d = document.createElement("div"); d.className = "tpl-item"; d.setAttribute("role", "button"); d.tabIndex = 0;
        const b = document.createElement("b"); b.textContent = t.template_id;
        const n = document.createElement("span"); n.className = "n text-2"; n.textContent = t.name;
        const tags = document.createElement("span"); tags.className = "muted small truncate"; tags.style.maxWidth = "160px"; tags.textContent = t.tags;
        const s = document.createElement("span"); s.className = "chip"; s.textContent = t.source;
        d.append(mkBadge(t.severity), b, n, tags, s);
        const pick = () => addSel(t);
        d.addEventListener("click", pick);
        d.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
        results.appendChild(d);
      });
    };
    q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 250); });
    sev.addEventListener("change", search); src.addEventListener("change", search);
    refreshCount();
  }
})();
