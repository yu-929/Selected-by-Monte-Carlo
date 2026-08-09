(function () {
  "use strict";

  const $ = (sel) => document.querySelector(sel);

  // ---- 视图切换 ----
  const navBtns = {
    "nav-scan": "view-scan",
    "nav-hops": "view-hops",
    "nav-tasks": "view-tasks",
  };
  Object.keys(navBtns).forEach((btnId) => {
    document.getElementById(btnId).addEventListener("click", () => {
      Object.keys(navBtns).forEach((b) =>
        document.getElementById(b).classList.toggle("active", b === btnId)
      );
      Object.values(navBtns).forEach((v) =>
        document.getElementById(v).classList.add("hidden")
      );
      document.getElementById(navBtns[btnId]).classList.remove("hidden");
    });
  });

  // ---- SSE 日志流 ----
  const logBox = $("#log");
  const es = new EventSource("/api/stream");
  es.onmessage = (e) => {
    if (e.data && !e.data.startsWith(":")) {
      appendLog(e.data);
    }
  };
  function appendLog(line) {
    const div = document.createElement("div");
    div.textContent = line;
    logBox.appendChild(div);
    logBox.scrollTop = logBox.scrollHeight;
  }

  // ---- 提交扫描 ----
  const btnSubmit = $("#btn-submit");
  btnSubmit.addEventListener("click", async () => {
    const targets = $("#targets").value.trim();
    if (!targets) {
      alert("请输入目标 IP");
      return;
    }
    const payload = {
      targets: targets,
      skip_tracer: $("#skip-tracer").checked,
      workers: parseInt($("#workers").value, 10) || 8,
      max_hops: parseInt($("#max-hops").value, 10) || 12,
    };
    btnSubmit.disabled = true;
    btnSubmit.textContent = "扫描中...";
    try {
      const resp = await fetch("/api/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      appendLog("[*] 任务已提交: " + data.id);
    } catch (err) {
      appendLog("[-] 提交失败: " + err.message);
    } finally {
      btnSubmit.disabled = false;
      btnSubmit.textContent = "开始扫描";
    }
  });

  // ---- 结果渲染 ----
  async function refreshResults() {
    try {
      const resp = await fetch("/api/jobs");
      const jobs = await resp.json();
      const tbody = $("#results tbody");
      tbody.innerHTML = "";
      jobs.forEach((job) => {
        (job.Results || []).forEach((r) => {
          const tr = document.createElement("tr");
          tr.innerHTML =
            "<td>" + esc(r.ip) + "</td>" +
            "<td>" + esc(r.detected_asn || "-") + "</td>" +
            "<td>" + esc(r.detected_isp || "-") + "</td>" +
            "<td>" + esc(r.detected_line || "-") + "</td>" +
            "<td>" + esc(r.country || "-") + "</td>" +
            "<td>" + esc(r.city || "-") + "</td>";
          tbody.appendChild(tr);
        });
      });

      // 历史任务表
      const tt = $("#tasks tbody");
      tt.innerHTML = "";
      jobs.slice().reverse().forEach((job) => {
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td>" + esc(job.ID) + "</td>" +
          "<td>" + (job.Targets || []).length + "</td>" +
          "<td><span class='badge " + (job.Done ? "done" : "running") + "'>" +
            (job.Done ? "完成" : "运行中") + "</span></td>" +
          "<td>" + esc(new Date(job.Created).toLocaleString()) + "</td>" +
          "<td>" + (job.Results || []).length + "</td>";
        tt.appendChild(tr);
      });
    } catch (e) {
      /* 忽略瞬时错误 */
    }
  }
  setInterval(refreshResults, 2000);
  refreshResults();

  // ---- 路由详情 ----
  const btnHops = $("#btn-hops");
  btnHops.addEventListener("click", async () => {
    const target = $("#hop-target").value.trim();
    if (!target) {
      alert("请输入目标 IP");
      return;
    }
    const status = $("#hop-status");
    status.textContent = "正在追踪 " + target + " ...";
    const tbody = $("#hops tbody");
    tbody.innerHTML = "";
    try {
      const resp = await fetch("/api/hops?target=" + encodeURIComponent(target));
      if (!resp.ok) {
        const err = await resp.text();
        status.textContent = "追踪失败: " + err;
        return;
      }
      const hops = await resp.json();
      hops.forEach((h) => {
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td>" + h.ttl + "</td>" +
          "<td>" + esc(h.ip || "*") + "</td>" +
          "<td>" + esc(h.latency || "-") + "</td>" +
          "<td>" + esc(h.asn || "-") + "</td>" +
          "<td>" + esc(h.org || "-") + "</td>" +
          "<td>" + esc(h.line || "-") + "</td>";
        tbody.appendChild(tr);
      });
      status.textContent = "共 " + hops.length + " 跳";
    } catch (err) {
      status.textContent = "追踪失败: " + err.message;
    }
  });

  function esc(s) {
    const div = document.createElement("div");
    div.textContent = s == null ? "" : String(s);
    return div.innerHTML;
  }
})();
