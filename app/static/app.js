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

  // ---------- Confirm dialogs: <form data-confirm="message"> ----------
  const dlg = $("#confirm-dialog");
  let pendingForm = null;
  $$("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (e) => {
      if (form.dataset.confirmed === "1") return;
      e.preventDefault();
      pendingForm = form;
      $("#confirm-text").textContent = form.dataset.confirm;
      if (dlg && typeof dlg.showModal === "function") dlg.showModal(); else if (window.confirm(form.dataset.confirm)) { form.dataset.confirmed = "1"; form.requestSubmit(); }
    });
  });
  $("#confirm-cancel")?.addEventListener("click", () => { pendingForm = null; dlg.close(); });
  $("#confirm-ok")?.addEventListener("click", () => { if (pendingForm) { pendingForm.dataset.confirmed = "1"; dlg.close(); pendingForm.requestSubmit(); } });

  // ---------- Loading state on submit ----------
  $$("form").forEach((form) => {
    form.addEventListener("submit", () => {
      if (form.dataset.confirm && form.dataset.confirmed !== "1") return;
      const btn = form.querySelector('button[type="submit"], button:not([type])');
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
      const rows = Array.from(tbody.rows).filter((r) => !r.dataset.empty);
      const val = (r) => { const c = r.cells[idx]; const t = (c?.dataset.value ?? c?.textContent ?? "").trim(); return type === "num" ? parseFloat(t.replace(/[^0-9.\-]/g, "")) || 0 : t.toLowerCase(); };
      rows.sort((a, b) => { const x = val(a), y = val(b); return (x < y ? -1 : x > y ? 1 : 0) * (dir === "ascending" ? 1 : -1); });
      rows.forEach((r) => tbody.appendChild(r));
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
