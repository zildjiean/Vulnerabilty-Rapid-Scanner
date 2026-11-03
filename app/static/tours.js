// Guided tours (app/tours.py): spotlight one element per step. Loaded by base.html only when the tours JSON is on the
// page. A tour only points: it never clicks, submits or fills anything. While it is open the page underneath ignores
// clicks (a transparent click-catcher) and everything outside the popover is inert.
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const t = (s, p) => (window.zdrsT ? window.zdrsT(s, p) : s);   // app.js: Thai values from base.html

  const src = document.getElementById("tours");
  let TOURS = [];
  try { TOURS = src ? JSON.parse(src.textContent) : []; } catch (e) { TOURS = []; }
  if (!Array.isArray(TOURS)) TOURS = [];
  TOURS = TOURS.filter((x) => x && typeof x.key === "string" && Array.isArray(x.steps) && x.steps.length);
  if (!TOURS.length) return;

  const KEY = "zdrs-tour", FOLLOW = "@follow";
  const SAME_SITE_PATH = /^\/(?!\/)/;
  const guide = $("#guide"), guideBtn = guide ? $("summary", guide) : null, shellEl = $("#shell");
  const find = (key) => TOURS.find((x) => x.key === key) || null;
  const mq = (q) => window.matchMedia(q).matches;
  const mobile = () => mq("(max-width: 520px)");
  const reduced = () => mq("(prefers-reduced-motion: reduce)");
  const ss = {
    get: () => { try { const v = JSON.parse(sessionStorage.getItem(KEY) || "null"); return v && typeof v === "object" ? v : null; } catch (e) { return null; } },
    set: (v) => { try { sessionStorage.setItem(KEY, JSON.stringify(v)); } catch (e) {} },
    clear: () => { try { sessionStorage.removeItem(KEY); } catch (e) {} },
  };
  const okFollow = (f) => (typeof f === "string" && SAME_SITE_PATH.test(f) ? f : null);
  const csrf = () => { const el = $('input[name="csrf"]'); return el ? el.value : ""; };
  const post = (url) => {   // fire and forget: failures are ignored, the tour closes anyway
    try {
      const fd = new FormData(); fd.append("csrf", csrf());
      fetch(url, { method: "POST", body: fd, credentials: "same-origin", headers: { "X-CSRF": csrf(), "X-Requested-With": "fetch" } }).catch(() => {});
    } catch (e) {}
  };
  let promptPending = !!(src && src.dataset.prompt);
  const dismissPrompt = () => {
    if (!promptPending) return;
    promptPending = false;
    post("/tours/prompt/dismiss");
    $("#tour-prompt")?.remove();
  };

  // Announcements: one polite region, present (and empty) from the start so the first step is announced too.
  const live = document.createElement("div");
  live.className = "sr-only"; live.setAttribute("aria-live", "polite"); live.setAttribute("aria-atomic", "true");
  document.body.appendChild(live);
  const announce = (text) => { if (live.textContent !== text) live.textContent = text; };

  // ----- Guide menu (a <details> in the top bar) -----
  if (guide) {
    document.addEventListener("click", (e) => { if (guide.open && !guide.contains(e.target)) guide.open = false; });
    guide.addEventListener("keydown", (e) => { if (e.key === "Escape" && guide.open) { e.stopPropagation(); guide.open = false; guideBtn?.focus(); } });
  }
  $$("[data-tour-start]").forEach((b) => {
    if (!find(b.dataset.tourStart)) return;
    b.hidden = false;   // the prompt's Start button exists only with JS
    b.addEventListener("click", (e) => { e.preventDefault(); if (guide) guide.open = false; start(b.dataset.tourStart); });
  });
  const markDone = (key) => {   // the Guide menu shows the ✓ at once, without a reload
    $$('.guide-list a[data-tour-start="' + CSS.escape(key) + '"]').forEach((a) => {
      if ($(".guide-done", a)) return;
      a.insertAdjacentHTML("beforeend", '<svg class="icon sm guide-done" aria-hidden="true"><use href="#i-check"/></svg><span class="sr-only"></span>');
      a.lastElementChild.textContent = t("Done");
    });
  };

  // ----- state -----
  let cur = null;      // { tour, i, follow, dir, el }
  let ui = null;       // { blocker, spot, pop, count, title, body, back, next, skip }
  let undo = [];       // closes what the tour opened (nav groups, the mobile drawer, <details>)
  let inerted = [];    // elements outside the popover made inert while the tour is open
  let drawerOpened = false;
  let raf = 0;

  const build = () => {
    const blocker = document.createElement("div");
    blocker.className = "tour-blocker";
    // touchstart stays passive so touch scrolling works; the click itself is what gets swallowed
    ["click", "mousedown", "mouseup", "pointerdown", "pointerup", "dblclick", "contextmenu"].forEach((ev) =>
      blocker.addEventListener(ev, (e) => { e.preventDefault(); e.stopPropagation(); }));
    const spot = document.createElement("div");
    spot.className = "tour-spot"; spot.setAttribute("aria-hidden", "true"); spot.hidden = true;
    const pop = document.createElement("div");
    pop.className = "tour-pop"; pop.tabIndex = -1;
    pop.setAttribute("role", "dialog"); pop.setAttribute("aria-modal", "true");
    pop.innerHTML = '<p class="tour-count"></p><h2 id="tour-title"></h2><p class="tour-body" id="tour-body"></p>' +
      '<div class="tour-actions"><button type="button" class="ghost sm tour-skip"></button><span class="spacer"></span>' +
      '<button type="button" class="sm tour-back"></button><button type="button" class="primary sm tour-next"></button></div>';
    document.body.append(blocker, spot, pop);
    const r = { blocker, spot, pop, count: $(".tour-count", pop), title: $("#tour-title", pop), body: $("#tour-body", pop),
      back: $(".tour-back", pop), next: $(".tour-next", pop), skip: $(".tour-skip", pop) };
    r.skip.textContent = t("Skip tour"); r.back.textContent = t("Back");
    r.skip.addEventListener("click", () => end(false));
    r.back.addEventListener("click", () => back());
    r.next.addEventListener("click", () => next());
    // everything but the popover and the announcer is inert: #shell, the skip link, toasts, the confirm dialog
    const keep = new Set([blocker, spot, pop, live]);
    inerted = Array.from(document.body.children).filter((el) => !keep.has(el) && el.tagName !== "SCRIPT" && !el.inert);
    inerted.forEach((el) => { el.inert = true; });
    document.addEventListener("keydown", onKey, true);
    window.addEventListener("resize", schedule);
    window.addEventListener("scroll", schedule, true);
    return r;
  };

  const focusables = () => (ui ? $$("button", ui.pop).filter((b) => !b.hidden && !b.disabled) : []);
  const onKey = (e) => {
    if (!cur || !ui) return;
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); end(false); }
    else if (e.key === "ArrowRight") { e.preventDefault(); next(); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); back(); }
    else if (e.key === "Tab") {   // keep focus inside the popover
      const f = focusables();
      if (!f.length) { e.preventDefault(); ui.pop.focus(); return; }
      const i = f.indexOf(document.activeElement);
      const to = e.shiftKey ? (i <= 0 ? f[f.length - 1] : f[i - 1]) : (i === -1 || i === f.length - 1 ? f[0] : f[i + 1]);
      e.preventDefault(); to.focus();
    }
  };

  // Remove the overlay and give the page back (also used when the page is hidden: bfcache must not keep it).
  const teardown = () => {
    if (ui) {
      document.removeEventListener("keydown", onKey, true);
      window.removeEventListener("resize", schedule);
      window.removeEventListener("scroll", schedule, true);
      ui.blocker.remove(); ui.spot.remove(); ui.pop.remove();
      ui = null;
    }
    inerted.forEach((el) => { el.inert = false; });
    inerted = [];
    closeDrawer();
    undo.reverse().forEach((f) => { try { f(); } catch (e) {} });
    undo = [];
  };
  const end = (done) => {
    const tour = cur && cur.tour;
    cur = null;
    ss.clear();
    if (done && tour) { post("/tours/" + encodeURIComponent(tour.key) + "/done"); tour.done = true; markDone(tour.key); }
    teardown();
    announce("");
    guideBtn?.focus();
  };
  window.addEventListener("pagehide", () => { if (ui) { cur = null; teardown(); } });
  window.addEventListener("pageshow", (e) => { if (e.persisted && (ui || cur)) end(false); });

  // ----- making a target visible (display only: open its nav group / the mobile drawer / a closed <details>) -----
  const openDrawer = () => {
    if (!shellEl || drawerOpened || shellEl.classList.contains("nav-open")) return;
    const tog = $("#nav-toggle");
    if (!tog || getComputedStyle(tog).display === "none") return;   // the drawer exists only when the hamburger shows
    shellEl.classList.add("nav-open"); tog.setAttribute("aria-expanded", "true"); drawerOpened = true;
    setTimeout(schedule, 280);   // the drawer slides in: measure again once it has arrived
  };
  const closeDrawer = () => {
    if (!drawerOpened || !shellEl) return;
    shellEl.classList.remove("nav-open"); $("#nav-toggle")?.setAttribute("aria-expanded", "false"); drawerOpened = false;
  };
  const prepare = (el) => {
    if (el.closest(".sidebar")) {
      openDrawer();
      const g = el.closest("[data-nav-group]");
      if (g && g.classList.contains("closed") && !el.matches(".nav-group-label")) {
        const btn = $(".nav-group-label", g);
        g.classList.remove("closed"); btn?.setAttribute("aria-expanded", "true");
        undo.push(() => { g.classList.add("closed"); btn?.setAttribute("aria-expanded", "false"); });
      }
    } else closeDrawer();
    for (let d = el.closest("details"); d; d = d.parentElement && d.parentElement.closest("details")) {
      if (d === guide || d.open) continue;
      d.open = true;
      const dd = d; undo.push(() => { dd.open = false; });
    }
  };
  const visible = (el) => { const r = el.getBoundingClientRect(); return el.getClientRects().length > 0 && (r.width > 0 || r.height > 0); };
  const targetEl = (step) => {
    let el = null;
    try { el = document.querySelector('[data-tour="' + CSS.escape(step.target) + '"]'); } catch (e) { el = null; }
    if (!el) return null;
    prepare(el);
    if (visible(el)) return el;
    // collapsed sidebar: group headers are hidden, the group's icons are not; highlight the whole group instead
    const group = el.matches(".nav-group-label") ? el.closest("[data-nav-group]") : null;
    return group && visible(group) ? group : null;
  };

  // ----- which page a step lives on -----
  const linkOf = (el) => { const a = el && (el.matches("a[href]") ? el : el.querySelector("a[href]")); return a ? a.getAttribute("href") : null; };
  const pageFor = (j) => {
    const steps = cur.tour.steps, s = steps[j];
    if (s.path !== FOLLOW) return s.path;
    const prev = steps[j - 1];
    if (prev && prev.path !== FOLLOW && prev.path === location.pathname) {
      let href = null;
      try { href = linkOf(document.querySelector('[data-tour="' + CSS.escape(prev.target) + '"]')); } catch (e) { href = null; }
      if (href) {
        try { const u = new URL(href, location.href); if (u.origin === location.origin) cur.follow = okFollow(u.pathname); } catch (e) {}
      }
    }
    return cur.follow || null;
  };

  const go = (j, page) => {
    ss.set({ key: cur.tour.key, step: j, follow: cur.follow, dir: cur.dir, at: page });
    location.href = page + "?tour=" + encodeURIComponent(cur.tour.key) + "&step=" + j;
  };

  // Show step i or the nearest reachable one in direction dir; navigate when it lives on another page.
  const show = (i, dir) => {
    const steps = cur.tour.steps;
    cur.dir = dir;
    for (let j = i; j >= 0 && j < steps.length; j += dir) {
      const page = pageFor(j);
      if (!page) continue;
      if (page !== location.pathname) { go(j, page); return; }
      if (!steps[j].target) { render(j, null); return; }
      const el = targetEl(steps[j]);
      if (el) { render(j, el); return; }
    }
    if (dir > 0) note();
    else if (cur.i !== undefined && cur.i >= 0) render(cur.i, cur.el);   // nothing earlier: stay on this step
    else show(i, 1);
  };
  const next = () => {
    if (!cur) return;
    if (cur.i === undefined || cur.i < 0) return end(false);   // the "nothing more" note
    if (cur.i >= cur.tour.steps.length - 1) return end(true);
    show(cur.i + 1, 1);
  };
  const back = () => { if (cur && cur.i > 0) show(cur.i - 1, -1); };

  const render = (j, el) => {
    if (!ui) ui = build();
    const steps = cur.tour.steps, s = steps[j], n = steps.length;
    cur.i = j; cur.el = el;
    ss.set({ key: cur.tour.key, step: j, follow: cur.follow, dir: 1, at: location.pathname });
    ui.pop.removeAttribute("aria-label");
    ui.pop.setAttribute("aria-labelledby", "tour-title");
    if (s.body) ui.pop.setAttribute("aria-describedby", "tour-body"); else ui.pop.removeAttribute("aria-describedby");
    ui.count.hidden = false; ui.count.textContent = (j + 1) + " / " + n;
    ui.title.textContent = s.title || "";
    ui.body.textContent = s.body || ""; ui.body.hidden = !s.body;
    ui.back.hidden = false; ui.back.disabled = j === 0; ui.skip.hidden = false;
    ui.next.textContent = j === n - 1 ? t("Done") : t("Next");
    announce(t("Step {n} of {total}", { n: j + 1, total: n }) + ": " + (s.title || ""));
    // sticky top bar / sidebar items are already on screen: "nearest" keeps the page from jumping
    if (el) el.scrollIntoView({ block: el.closest(".sidebar, .topbar") ? "nearest" : "center", inline: "nearest", behavior: reduced() ? "auto" : "smooth" });
    place();
    if (!ui.pop.contains(document.activeElement)) ui.pop.focus({ preventScroll: true });
  };
  const note = () => {
    if (!ui) ui = build();
    closeDrawer();
    cur.i = -1; cur.el = null;
    ss.clear();
    const text = t("Nothing more to show here yet");
    ui.pop.removeAttribute("aria-labelledby"); ui.pop.removeAttribute("aria-describedby");
    ui.pop.setAttribute("aria-label", text);
    ui.count.hidden = true; ui.body.hidden = true; ui.back.hidden = true; ui.skip.hidden = true;
    ui.title.textContent = text;
    ui.next.textContent = t("Done");
    announce(text);
    place();
    ui.next.focus({ preventScroll: true });
  };

  // ----- spotlight + popover geometry -----
  const schedule = () => { if (!raf) raf = requestAnimationFrame(() => { raf = 0; place(); }); };
  const place = () => {
    if (!ui || !cur) return;
    const { spot, pop, blocker } = ui, el = cur.el;
    pop.classList.remove("center", "sheet-top");
    pop.style.left = pop.style.top = "";
    if (!el || !el.isConnected || !visible(el)) {
      spot.hidden = true; blocker.classList.add("dim"); pop.classList.add("center");
      return;
    }
    blocker.classList.remove("dim");
    const r = el.getBoundingClientRect(), pad = 6, vw = window.innerWidth, vh = window.innerHeight;
    spot.hidden = false;
    spot.style.left = (r.left - pad) + "px"; spot.style.top = (r.top - pad) + "px";
    spot.style.width = (r.width + 2 * pad) + "px"; spot.style.height = (r.height + 2 * pad) + "px";
    if (mobile()) {   // bottom sheet (CSS); moved to the top when the target sits in the lower half
      if (r.top + r.height / 2 > vh / 2) pop.classList.add("sheet-top");
      return;
    }
    const pw = pop.offsetWidth, ph = pop.offsetHeight, gap = 12, m = 8;
    const clamp = (v, lo, hi) => Math.max(lo, Math.min(v, hi));
    let left, top;
    const below = r.bottom + pad + gap, above = r.top - pad - gap - ph, right = r.right + pad + gap;
    const sideFirst = !!el.closest(".sidebar");
    if (sideFirst && right + pw <= vw - m) { left = right; top = clamp(r.top, m, vh - ph - m); }
    else if (below + ph <= vh - m) { top = below; left = clamp(r.left, m, vw - pw - m); }
    else if (above >= m) { top = above; left = clamp(r.left, m, vw - pw - m); }
    else if (right + pw <= vw - m) { left = right; top = clamp(r.top, m, vh - ph - m); }
    else if (r.left - pad - gap - pw >= m) { left = r.left - pad - gap - pw; top = clamp(r.top, m, vh - ph - m); }
    else { left = clamp((vw - pw) / 2, m, vw - pw - m); top = clamp(vh - ph - m, m, vh - ph - m); }
    pop.style.left = left + "px"; pop.style.top = top + "px";
  };

  const start = (key, step = 0, follow = null, dir = 1) => {
    const tour = find(key);
    if (!tour || step < 0 || step >= tour.steps.length) return;
    if (cur) end(false);
    dismissPrompt();
    cur = { tour, i: undefined, el: undefined, follow: okFollow(follow), dir };
    if (tour.steps[step].path === FOLLOW && !cur.follow) cur.follow = okFollow(location.pathname);   // arrived by following
    show(step, dir === -1 ? -1 : 1);
  };

  // ----- resume: ?tour=<key>&step=<n> after a navigation, or the saved state after a reload of the same page -----
  let qKey = null, qStep = null;
  try {
    const u = new URL(location.href);
    qKey = u.searchParams.get("tour"); qStep = u.searchParams.get("step");
    if (qKey !== null || qStep !== null) {
      u.searchParams.delete("tour"); u.searchParams.delete("step");
      if (history.replaceState) history.replaceState(history.state, "", u.pathname + u.search + u.hash);
    }
  } catch (e) {}
  const saved = ss.get();
  if (qKey && find(qKey) && /^\d{1,3}$/.test(qStep || "")) {
    const n = parseInt(qStep, 10);
    const st = saved && saved.key === qKey && saved.step === n ? saved : null;
    start(qKey, n, st ? okFollow(st.follow) : null, st && st.dir === -1 ? -1 : 1);
  } else if (saved && typeof saved.key === "string" && find(saved.key) && Number.isInteger(saved.step) && saved.at === location.pathname) {
    start(saved.key, saved.step, okFollow(saved.follow), 1);
  } else if (saved) ss.clear();
})();
