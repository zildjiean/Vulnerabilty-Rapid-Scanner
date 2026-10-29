(function () {
  // Live job log over Server-Sent Events
  const log = document.getElementById("joblog");
  if (log && log.dataset.live === "yes") {
    const id = log.dataset.jobId;
    const statusEl = document.getElementById("job-status");
    const es = new EventSource(`/jobs/${id}/stream`);
    log.textContent = "";
    es.addEventListener("log", (e) => {
      log.textContent += e.data + "\n";
      log.scrollTop = log.scrollHeight;
    });
    es.addEventListener("done", (e) => {
      es.close();
      if (statusEl) { statusEl.textContent = e.data; statusEl.className = "st-" + e.data; }
      setTimeout(() => location.reload(), 800);
    });
    es.addEventListener("error", () => { /* browser retries automatically */ });
  }

  // "select all" checkboxes: <input type=checkbox data-select-all="name">
  document.querySelectorAll("[data-select-all]").forEach((cb) => {
    cb.addEventListener("change", () => {
      document.querySelectorAll(`input[name="${cb.dataset.selectAll}"]`).forEach((x) => { x.checked = cb.checked; });
    });
  });

  // Nuclei template picker (page: /nuclei)
  const q = document.getElementById("tpl-q");
  if (q) {
    const results = document.getElementById("tpl-results");
    const selected = document.getElementById("tpl-selected");
    const count = document.getElementById("tpl-count");
    const sev = document.getElementById("tpl-sev");
    const src = document.getElementById("tpl-src");
    let timer = null;
    const refreshCount = () => { count.textContent = selected.children.length; };
    const isSelected = (p) => !!selected.querySelector(`li[data-path="${CSS.escape(p)}"]`);
    const addSel = (t) => {
      if (isSelected(t.path)) return;
      const li = document.createElement("li");
      li.dataset.path = t.path;
      li.innerHTML = '<input type="hidden" name="template_paths"><span class="badge"></span> <b></b> <span class="n muted"></span> <button type="button" class="link rm" title="remove">✕</button>';
      li.querySelector("input").value = t.path;
      const badge = li.querySelector(".badge"); badge.textContent = t.severity; badge.classList.add("sev-" + t.severity);
      li.querySelector("b").textContent = t.template_id;
      li.querySelector(".n").textContent = t.name;
      selected.appendChild(li);
      refreshCount();
    };
    selected.addEventListener("click", (e) => {
      if (e.target.classList.contains("rm")) { e.target.closest("li").remove(); refreshCount(); }
    });
    const search = async () => {
      const term = q.value.trim();
      if (term.length < 2) { results.innerHTML = ""; return; }
      const url = `/templates/search?q=${encodeURIComponent(term)}&severity=${encodeURIComponent(sev.value)}&source=${encodeURIComponent(src.value)}`;
      const r = await fetch(url);
      const items = await r.json();
      results.innerHTML = "";
      if (!items.length) { results.innerHTML = '<div class="tpl-item muted">No templates match.</div>'; return; }
      const all = document.createElement("div");
      all.className = "tpl-item";
      all.innerHTML = '<button type="button" class="btn small">Add all</button><span class="muted small"></span>';
      all.querySelector("span").textContent = `${items.length} result(s)`;
      all.querySelector("button").addEventListener("click", () => items.forEach(addSel));
      results.appendChild(all);
      items.forEach((t) => {
        const d = document.createElement("div");
        d.className = "tpl-item";
        d.innerHTML = '<span class="badge"></span><b></b><span class="n"></span><span class="muted small tags"></span><span class="badge src"></span>';
        const badge = d.querySelector(".badge"); badge.textContent = t.severity; badge.classList.add("sev-" + t.severity);
        d.querySelector("b").textContent = t.template_id;
        d.querySelector(".n").textContent = t.name;
        d.querySelector(".tags").textContent = t.tags;
        d.querySelector(".src").textContent = t.source;
        d.addEventListener("click", () => addSel(t));
        results.appendChild(d);
      });
    };
    q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 250); });
    sev.addEventListener("change", search);
    src.addEventListener("change", search);
    refreshCount();
  }
})();
