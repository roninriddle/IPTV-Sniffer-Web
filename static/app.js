const $ = (id) => document.getElementById(id);

const state = {
  logsOpen: false,
  latestLogId: 0,
  poller: null,
  logPoller: null,
  streams: [],
  probingKeys: new Set(),
};

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: {"Content-Type": "application/json"},
    ...options,
  });
  const payload = await response.json();
  if (!response.ok || payload.success === false) {
    throw new Error(payload.error || "请求失败");
  }
  return payload.data;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>\"]/g, (ch) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[ch]));
}

function formatTime(seconds) {
  const total = Math.max(0, Number(seconds || 0));
  const mins = Math.floor(total / 60);
  const secs = total % 60;
  return mins > 0 ? `${mins}分${secs}秒` : `${secs}秒`;
}

function formSettings() {
  return {
    interface: $("interface").value,
    http_host: $("httpHost").value.trim(),
    http_port: Number($("httpPort").value || 5140),
    path_mode: $("pathMode").value,
    duration: Number($("duration").value || 0),
    auto_probe: $("autoProbe").checked,
    auto_epg: $("autoEpg").checked,
    epg_url: $("epgUrl").value.trim(),
  };
}

function formScheduleSettings() {
  return {
    ...formSettings(),
    schedule_enabled: $("scheduleEnabled").checked,
    schedule_unit: $("scheduleUnit").value,
    schedule_every: Number($("scheduleEvery").value || 1),
    schedule_hour: Number($("scheduleHour").value || 0),
    schedule_minute: Number($("scheduleMinute").value || 0),
  };
}

function setRuntimeBadge(health) {
  const badge = $("runtimeBadge");
  const captureOk = Boolean(health.runtime?.ok);
  const probeOk = Boolean(health.probe_runtime?.ok);
  if (captureOk && probeOk) {
    badge.className = "chip ok";
    badge.textContent = "抓包与 4K 检测环境正常";
  } else if (captureOk && !probeOk) {
    badge.className = "chip warning";
    badge.textContent = "抓包可用，ffprobe 检测异常";
  } else {
    badge.className = "chip danger";
    badge.textContent = "抓包权限或依赖异常";
  }
}

async function loadHealth() {
  try {
    const response = await fetch("/api/health");
    const payload = await response.json();
    setRuntimeBadge(payload.data || {});
  } catch (_) {
    const badge = $("runtimeBadge");
    badge.className = "chip danger";
    badge.textContent = "健康检查失败";
  }
}

function maskToken(value) {
  const token = String(value || "");
  if (!token) return "-";
  if (token.length <= 12) return `${token.slice(0, 4)}...`;
  return `${token.slice(0, 6)}...${token.slice(-6)}`;
}

function renderMetrics(metrics, tokenData) {
  $("discoveredChannels").textContent = metrics.discovered_channels ?? 0;
  $("fccRecords").textContent = metrics.fcc_records ?? 0;
  $("stbTokens").textContent = metrics.stb_tokens ?? 0;
  const latest = tokenData?.latest;
  if (latest) {
    const endpoint = latest.dip && latest.dport ? `${latest.dip}:${latest.dport}` : "-";
    $("snifferInsight").innerHTML = `channelAcquire：<span class="mono">${escapeHtml(endpoint)}</span>，UserToken：<span class="mono">${escapeHtml(maskToken(latest.token))}</span>；FCC 记录：${escapeHtml(metrics.fcc_records ?? 0)} 条。`;
  } else if ((metrics.fcc_records ?? 0) > 0) {
    $("snifferInsight").textContent = `已发现 FCC 记录 ${metrics.fcc_records} 条，尚未捕获 channelAcquire UserToken。`;
  } else {
    $("snifferInsight").textContent = "尚未发现 FCC 或 channelAcquire 令牌。";
  }
}

function renderEpgStatus(epg) {
  const badge = $("epgBadge");
  if (epg.refreshing) {
    badge.className = "chip warning";
    badge.textContent = "EPG 刷新中";
  } else if (epg.last_error) {
    badge.className = "chip danger";
    badge.textContent = "EPG 异常";
  } else if ((epg.channels ?? 0) > 0) {
    badge.className = "chip ok";
    badge.textContent = `EPG ${epg.channels} 个频道`;
  } else {
    badge.className = "chip neutral";
    badge.textContent = "EPG 未加载";
  }
}

async function loadInterfaces() {
  const data = await requestJson("/api/interfaces");
  const select = $("interface");
  const current = select.value;
  select.innerHTML = "";
  for (const name of data.interfaces || []) {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name === "any" ? "any（所有接口，测试用）" : name;
    select.appendChild(option);
  }
  if ([...select.options].some((option) => option.value === current)) {
    select.value = current;
  }
}

async function loadSettings() {
  const data = await requestJson("/api/settings");
  $("interface").value = data.interface || $("interface").value;
  $("httpHost").value = data.http_host || "";
  $("httpPort").value = data.http_port ?? 5140;
  $("pathMode").value = data.path_mode || "rtp";
  $("duration").value = data.duration ?? 30;
  $("autoProbe").checked = data.auto_probe !== false;
  $("autoEpg").checked = data.auto_epg !== false;
  $("epgUrl").value = data.epg_url || "";
  $("scheduleEnabled").checked = Boolean(data.schedule_enabled);
  $("scheduleUnit").value = data.schedule_unit || "days";
  $("scheduleEvery").value = data.schedule_every ?? 1;
  $("scheduleHour").value = data.schedule_hour ?? 3;
  $("scheduleMinute").value = data.schedule_minute ?? 0;
  updateScheduleUnitState();
}

function updateScheduleUnitState() {
  const unit = $("scheduleUnit").value;
  const every = Math.max(1, Number($("scheduleEvery").value || 1));
  if (unit === "hours") {
    $("scheduleEvery").max = 168;
    $("scheduleEveryHint").textContent = `每 ${every} 小时`;
    $("scheduleHour").disabled = true;
    $("scheduleMinute").disabled = true;
  } else {
    $("scheduleEvery").max = 30;
    $("scheduleEveryHint").textContent = `每 ${every} 天`;
    $("scheduleHour").disabled = false;
    $("scheduleMinute").disabled = false;
  }
}

function renderSchedule(schedule) {
  const badge = $("scheduleBadge");
  if (schedule.enabled) {
    badge.className = schedule.last_error ? "chip warning" : "chip ok";
    badge.textContent = schedule.last_error ? "已启用，有错误" : "已启用";
  } else {
    badge.className = "chip neutral";
    badge.textContent = "未启用";
  }
  const mode = schedule.unit === "hours"
    ? `每 ${escapeHtml(schedule.every || 1)} 小时`
    : `每 ${escapeHtml(schedule.every || 1)} 天 ${String(schedule.hour ?? 0).padStart(2, "0")}:${String(schedule.minute ?? 0).padStart(2, "0")}`;
  const lines = [
    `<strong>${escapeHtml(schedule.last_message || (schedule.enabled ? "定时任务已启用" : "定时任务未启用"))}</strong>`,
    `模式：<span class="mono">${mode}</span>`,
    `下次执行：<span class="mono">${escapeHtml(schedule.next_run_text || "-")}</span>`,
    `上次执行：<span class="mono">${escapeHtml(schedule.last_run_text || "-")}</span>`,
  ];
  if (schedule.last_error) lines.push(`错误：${escapeHtml(schedule.last_error)}`);
  $("schedulePanel").innerHTML = lines.map((line) => `<div>${line}</div>`).join("");
}

function renderStatus(status) {
  const chip = $("statusChip");
  const labelMap = {
    idle: ["等待开始", "neutral"],
    running: ["抓包中", "ok"],
    stopped: ["已停止", "warning"],
    error: ["异常", "danger"],
  };
  const [label, cls] = labelMap[status.state] || [status.state || "未知", "neutral"];
  chip.className = `chip ${cls}`;
  chip.textContent = label;
  const lines = [
    `<strong>${escapeHtml(status.message || "")}</strong>`,
    `接口：<span class="mono">${escapeHtml(status.interface || "-")}</span>`,
    `rtp2httpd 前缀：<span class="mono">${status.http_host ? `http://${escapeHtml(status.http_host)}:${escapeHtml(status.http_port)}/${escapeHtml(status.path_mode)}/` : "-"}</span>`,
    `运行时间：${formatTime(status.elapsed)}`,
  ];
  if (status.remaining !== null && status.remaining !== undefined) lines.push(`剩余时间：${formatTime(status.remaining)}`);
  if (status.stop_reason) lines.push(`停止原因：${escapeHtml(status.stop_reason)}`);
  if (status.last_error) lines.push(`错误：${escapeHtml(status.last_error)}`);
  $("statusPanel").innerHTML = lines.map((line) => `<div>${line}</div>`).join("");
  $("streamsFound").textContent = status.streams_found ?? 0;
  $("eligibleStreams").textContent = status.eligible_streams ?? 0;
  $("packetCount").textContent = status.total_packets ?? 0;
  $("elapsed").textContent = status.elapsed ?? 0;
  $("startBtn").disabled = status.state === "running";
  $("stopBtn").disabled = status.state !== "running";
  $("resetBtn").disabled = status.state === "running";
}

function rowProbePayload(row) {
  return {
    probe_status: row.dataset.probeStatus || "not_probed",
    probe_message: row.dataset.probeMessage || "未检测",
    codec_name: row.dataset.codecName || "",
    width: row.dataset.width ? Number(row.dataset.width) : null,
    height: row.dataset.height ? Number(row.dataset.height) : null,
    frame_rate: row.dataset.frameRate || "",
    resolution_label: row.dataset.resolutionLabel || "未识别",
    quality_group: row.dataset.qualityGroup || "未识别",
    probed_at: row.dataset.probedAt ? Number(row.dataset.probedAt) : null,
    fcc_ip: row.dataset.fccIp || "",
    fcc_port: row.dataset.fccPort ? Number(row.dataset.fccPort) : null,
    tvg_id: row.dataset.tvgId || "",
    tvg_name: row.dataset.tvgName || "",
    tvg_logo: row.dataset.tvgLogo || "",
    epg_source: row.dataset.epgSource || "",
    auto_name: row.dataset.autoName || "",
    auto_name_source: row.dataset.autoNameSource || "",
    epg_matched_at: row.dataset.epgMatchedAt ? Number(row.dataset.epgMatchedAt) : null,
  };
}

function streamRowsFromDom() {
  return [...document.querySelectorAll("#streamsTableBody tr[data-key]")].map((row) => ({
    key: row.dataset.key,
    host: row.dataset.host,
    port: Number(row.dataset.port),
    packets: Number(row.dataset.packets || 0),
    name: row.querySelector(".channel-name")?.value.trim() || "",
    category: row.querySelector(".channel-category")?.value || "其它频道",
    ...rowProbePayload(row),
  }));
}

function preserveRowEdits(streams) {
  const currentEdits = new Map(streamRowsFromDom().map((row) => [row.key, row]));
  return (streams || []).map((stream) => {
    const draft = currentEdits.get(stream.key);
    if (!draft) return stream;
    return {
      ...stream,
      name: draft.name || stream.name || "",
      category: draft.category || stream.category || "其它频道",
      probe_status: stream.probe_status || draft.probe_status,
      probe_message: stream.probe_message || draft.probe_message,
      codec_name: stream.codec_name || draft.codec_name,
      width: stream.width ?? draft.width,
      height: stream.height ?? draft.height,
      frame_rate: stream.frame_rate || draft.frame_rate,
      resolution_label: stream.resolution_label || draft.resolution_label,
      quality_group: stream.quality_group || draft.quality_group,
      probed_at: stream.probed_at ?? draft.probed_at,
      fcc_ip: stream.fcc_ip || draft.fcc_ip,
      fcc_port: stream.fcc_port ?? draft.fcc_port,
      tvg_id: stream.tvg_id || draft.tvg_id,
      tvg_name: stream.tvg_name || draft.tvg_name,
      tvg_logo: stream.tvg_logo || draft.tvg_logo,
      epg_source: stream.epg_source || draft.epg_source,
      auto_name: stream.auto_name || draft.auto_name,
      auto_name_source: stream.auto_name_source || draft.auto_name_source,
      epg_matched_at: stream.epg_matched_at ?? draft.epg_matched_at,
    };
  });
}

function probeBadge(stream) {
  const status = stream.probe_status || "not_probed";
  if (status === "ok") {
    return stream.quality_group === "4K高清" ? '<span class="badge ultra">4K高清</span>' : '<span class="badge info">普通频道</span>';
  }
  if (status === "partial") return '<span class="badge wait">信息不完整</span>';
  if (status === "failed") return '<span class="badge danger">检测失败</span>';
  return '<span class="badge neutral">未检测</span>';
}

function streamInfoHtml(stream) {
  const codec = stream.codec_name ? escapeHtml(stream.codec_name) : "-";
  const resolution = stream.width && stream.height ? `${escapeHtml(stream.width)}×${escapeHtml(stream.height)}` : escapeHtml(stream.resolution_label || "未识别");
  const fps = stream.frame_rate ? escapeHtml(stream.frame_rate) : "-";
  const fcc = stream.fcc_ip && stream.fcc_port ? `<span>FCC：${escapeHtml(stream.fcc_ip)}:${escapeHtml(stream.fcc_port)}</span>` : "";
  const autoName = stream.auto_name ? `<span>自动名：${escapeHtml(stream.auto_name)}</span>` : "";
  const epgName = stream.tvg_name || stream.tvg_id ? `<span>EPG：${escapeHtml(stream.tvg_name || "-")} / ${escapeHtml(stream.tvg_id || "-")}</span>` : "";
  const message = stream.probe_message ? `<div class="probe-note">${escapeHtml(stream.probe_message)}</div>` : "";
  return `<div class="probe-meta">${probeBadge(stream)}${autoName}${epgName}<span>编码：${codec}</span><span>分辨率：${resolution}</span><span>帧率：${fps}</span>${fcc}${message}</div>`;
}

function previewHtml(stream) {
  if (!stream.preview_url) return '<span class="muted">未设置 rtp2httpd 地址</span>';
  const title = stream.name || stream.key;
  return `<div class="preview-cell">
    <button class="secondary preview-play-btn"
      data-stream-url="${escapeHtml(stream.preview_url)}"
      data-snapshot-url="${escapeHtml(stream.snapshot_url || "")}"
      data-player-url="${escapeHtml(stream.player_url || "")}"
      data-title="${escapeHtml(title)}">播放预览</button>
    <a class="preview-link" href="${escapeHtml(stream.preview_url)}" target="_blank" rel="noreferrer">${escapeHtml(stream.preview_url)}</a>
  </div>`;
}

function snapshotHtml(stream) {
  if (!stream.eligible || !stream.snapshot_url) return '<span class="muted">-</span>';
  const title = stream.name || stream.key;
  return `<button class="snapshot-thumb-btn"
      data-snapshot-url="${escapeHtml(stream.snapshot_url)}"
      data-title="${escapeHtml(title)}">
    <img class="snapshot-thumb" src="${escapeHtml(stream.snapshot_url)}" alt="${escapeHtml(title)} 截图" loading="lazy">
  </button>`;
}

function renderStreams(streams) {
  const currentChecks = new Map([...document.querySelectorAll("#streamsTableBody tr[data-key]")].map((row) => [row.dataset.key, Boolean(row.querySelector(".stream-check")?.checked)]));
  state.streams = preserveRowEdits(streams);
  const body = $("streamsTableBody");
  if (!state.streams.length) {
    body.innerHTML = '<tr><td colspan="10" class="empty">暂无候选流</td></tr>';
    return;
  }
  body.innerHTML = state.streams.map((stream) => {
    const candidateBadge = stream.eligible ? '<span class="badge ok">有效候选</span>' : '<span class="badge wait">包数偏少</span>';
    const checked = currentChecks.get(stream.key) ? "checked" : "";
    const probing = state.probingKeys.has(stream.key);
    return `<tr data-key="${escapeHtml(stream.key)}"
        data-host="${escapeHtml(stream.host)}"
        data-port="${escapeHtml(stream.port)}"
        data-packets="${escapeHtml(stream.packets)}"
        data-probe-status="${escapeHtml(stream.probe_status || "not_probed")}"
        data-probe-message="${escapeHtml(stream.probe_message || "未检测")}"
        data-codec-name="${escapeHtml(stream.codec_name || "")}"
        data-width="${escapeHtml(stream.width ?? "")}"
        data-height="${escapeHtml(stream.height ?? "")}"
        data-frame-rate="${escapeHtml(stream.frame_rate || "")}"
        data-resolution-label="${escapeHtml(stream.resolution_label || "未识别")}"
        data-quality-group="${escapeHtml(stream.quality_group || "未识别")}"
        data-probed-at="${escapeHtml(stream.probed_at ?? "")}"
        data-fcc-ip="${escapeHtml(stream.fcc_ip || "")}"
        data-fcc-port="${escapeHtml(stream.fcc_port ?? "")}"
        data-tvg-id="${escapeHtml(stream.tvg_id || "")}"
        data-tvg-name="${escapeHtml(stream.tvg_name || "")}"
        data-tvg-logo="${escapeHtml(stream.tvg_logo || "")}"
        data-epg-source="${escapeHtml(stream.epg_source || "")}"
        data-auto-name="${escapeHtml(stream.auto_name || "")}"
        data-auto-name-source="${escapeHtml(stream.auto_name_source || "")}"
        data-epg-matched-at="${escapeHtml(stream.epg_matched_at ?? "")}">
      <td><input type="checkbox" class="stream-check" ${checked}></td>
      <td><code>${escapeHtml(stream.key)}</code></td>
      <td>${escapeHtml(stream.packets)}</td>
      <td>${candidateBadge}</td>
      <td>${snapshotHtml(stream)}</td>
      <td><input class="channel-name" type="text" value="${escapeHtml(stream.name || "")}" placeholder="${stream.auto_name ? "自动识别，可修正" : "人工补全频道名"}"></td>
      <td>
        <select class="channel-category">
          <option value="央视频道" ${stream.category === "央视频道" ? "selected" : ""}>央视频道</option>
          <option value="卫视频道" ${stream.category === "卫视频道" ? "selected" : ""}>卫视频道</option>
          <option value="其它频道" ${!stream.category || stream.category === "其它频道" ? "selected" : ""}>其它频道</option>
        </select>
      </td>
      <td>${streamInfoHtml(stream)}</td>
      <td><button class="secondary probe-one-btn" data-key="${escapeHtml(stream.key)}" ${probing ? "disabled" : ""}>${probing ? "检测中" : "检测流信息"}</button></td>
      <td>${previewHtml(stream)}</td>
    </tr>`;
  }).join("");
}

function stopPreview() {
  $("previewFrame").removeAttribute("src");
  $("previewSnapshot").removeAttribute("src");
}

function openPreview(streamUrl, playerUrl, title, snapshotUrl) {
  $("previewTitle").textContent = title || "频道预览";
  $("previewStatus").textContent = "优先使用 rtp2httpd 内置播放器；若该页面未配置频道列表，请使用直连流或截图确认。";
  $("previewExternalLink").href = streamUrl;
  $("previewExternalLink").textContent = streamUrl;
  $("previewDirectLink").href = streamUrl;
  $("previewPlayerLink").href = playerUrl || "#";
  $("previewSnapshot").src = snapshotUrl || "";
  $("previewSnapshot").hidden = !snapshotUrl;
  $("previewFrame").src = playerUrl || streamUrl;
  $("previewModal").hidden = false;
}

function closePreview() {
  stopPreview();
  $("previewModal").hidden = true;
}

function openSnapshot(url, title) {
  $("snapshotLarge").src = url;
  $("snapshotLarge").alt = `${title || "频道"} 截图`;
  $("snapshotModal").hidden = false;
}

function closeSnapshot() {
  $("snapshotModal").hidden = true;
  $("snapshotLarge").removeAttribute("src");
}

async function refreshStatusAndStreams() {
  const [status, streams, metrics, tokenData, schedule, epg] = await Promise.all([
    requestJson("/api/status"),
    requestJson("/api/streams"),
    requestJson("/api/metrics"),
    requestJson("/api/stb-token"),
    requestJson("/api/schedule"),
    requestJson("/api/epg/status"),
  ]);
  renderStatus(status);
  renderMetrics(metrics, tokenData);
  renderSchedule(schedule);
  renderEpgStatus(epg);
  renderStreams(streams.streams || []);
}

function startPolling() {
  if (state.poller) clearInterval(state.poller);
  state.poller = setInterval(async () => {
    try {
      await refreshStatusAndStreams();
    } catch (_) {}
  }, 1000);
}

async function appendLogs() {
  const data = await requestJson(`/api/logs?after_id=${state.latestLogId}&limit=300`);
  const output = $("logsOutput");
  for (const entry of data.entries || []) {
    output.textContent += `[${entry.time}] [${entry.level}] ${entry.message}\n`;
    state.latestLogId = Math.max(state.latestLogId, entry.id);
  }
  if ((data.entries || []).length) output.scrollTop = output.scrollHeight;
}

function openLogs() {
  state.logsOpen = true;
  document.body.classList.add("logs-open");
  localStorage.setItem("logsOpen", "1");
  $("logsDrawer").classList.add("open");
  $("logsDrawer").setAttribute("aria-hidden", "false");
  appendLogs().catch(() => {});
  if (state.logPoller) clearInterval(state.logPoller);
  state.logPoller = setInterval(() => appendLogs().catch(() => {}), 1000);
}

function closeLogs() {
  state.logsOpen = false;
  document.body.classList.remove("logs-open");
  localStorage.setItem("logsOpen", "0");
  $("logsDrawer").classList.remove("open");
  $("logsDrawer").setAttribute("aria-hidden", "true");
  if (state.logPoller) clearInterval(state.logPoller);
}

function showExportDownloads(files) {
  const map = {
    direct_m3u: $("downloadDirectM3u"),
    source_m3u: $("downloadSourceM3u"),
    json: $("downloadJson"),
    txt: $("downloadTxt"),
    csv: $("downloadCsv"),
  };
  for (const [key, link] of Object.entries(map)) {
    if (files?.[key]) {
      link.href = `/api/download/${files[key]}`;
      link.classList.remove("disabled");
    }
  }
}

function selectedRowsOrAll() {
  const rows = streamRowsFromDom();
  const selectedKeys = new Set([...document.querySelectorAll("#streamsTableBody tr[data-key]")]
    .filter((row) => row.querySelector(".stream-check")?.checked)
    .map((row) => row.dataset.key));
  return selectedKeys.size ? rows.filter((row) => selectedKeys.has(row.key)) : rows;
}

async function probeOneByRow(row) {
  const rows = streamRowsFromDom();
  const payload = rows.find((item) => item.key === row.dataset.key);
  if (!payload) return;
  state.probingKeys.add(payload.key);
  renderStreams(state.streams);
  try {
    await requestJson("/api/probe", {
      method: "POST",
      body: JSON.stringify({...payload, path_mode: $("pathMode").value}),
    });
    await refreshStatusAndStreams();
  } catch (err) {
    alert(err.message);
  } finally {
    state.probingKeys.delete(payload.key);
    renderStreams(state.streams);
  }
}

async function probeBatch() {
  const rows = selectedRowsOrAll();
  if (!rows.length) {
    alert("暂无可检测的候选流");
    return;
  }
  rows.forEach((row) => state.probingKeys.add(row.key));
  renderStreams(state.streams);
  try {
    const data = await requestJson("/api/probe/batch", {
      method: "POST",
      body: JSON.stringify({channels: rows, path_mode: $("pathMode").value}),
    });
    await refreshStatusAndStreams();
    const ok = (data.results || []).filter((item) => item.probe_status === "ok").length;
    alert(`检测完成：共 ${data.count} 条，成功识别 ${ok} 条。`);
  } catch (err) {
    alert(err.message);
  } finally {
    rows.forEach((row) => state.probingKeys.delete(row.key));
    renderStreams(state.streams);
  }
}

async function bootstrap() {
  await loadHealth();
  await loadInterfaces();
  await loadSettings();
  await refreshStatusAndStreams();
  await appendLogs();
  if (localStorage.getItem("logsOpen") === "1") openLogs();
  startPolling();
}

$("refreshInterfacesBtn").addEventListener("click", () => loadInterfaces().catch((err) => alert(err.message)));
$("saveSettingsBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/settings", {method: "POST", body: JSON.stringify(formSettings())});
    await refreshStatusAndStreams();
    alert("默认设置已保存");
  } catch (err) { alert(err.message); }
});
$("refreshEpgBtn").addEventListener("click", async () => {
  try {
    const epg = await requestJson("/api/epg/refresh", {method: "POST", body: JSON.stringify(formSettings())});
    renderEpgStatus(epg);
    alert("EPG 刷新已启动");
  } catch (err) { alert(err.message); }
});
$("scheduleUnit").addEventListener("change", updateScheduleUnitState);
$("scheduleEvery").addEventListener("input", updateScheduleUnitState);
$("saveScheduleBtn").addEventListener("click", async () => {
  try {
    const data = await requestJson("/api/schedule", {method: "POST", body: JSON.stringify(formScheduleSettings())});
    renderSchedule(data);
    alert(data.enabled ? "定时任务已保存并启用" : "定时任务已保存为停用状态");
  } catch (err) { alert(err.message); }
});
$("disableScheduleBtn").addEventListener("click", async () => {
  try {
    $("scheduleEnabled").checked = false;
    const data = await requestJson("/api/schedule", {method: "POST", body: JSON.stringify(formScheduleSettings())});
    renderSchedule(data);
  } catch (err) { alert(err.message); }
});
$("startBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/capture/start", {method: "POST", body: JSON.stringify(formSettings())});
    await refreshStatusAndStreams();
  } catch (err) { alert(err.message); }
});
$("stopBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/capture/stop", {method: "POST", body: "{}"});
    await refreshStatusAndStreams();
  } catch (err) { alert(err.message); }
});
$("resetBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/capture/reset", {method: "POST", body: "{}"});
    await refreshStatusAndStreams();
  } catch (err) { alert(err.message); }
});
$("saveChannelsBtn").addEventListener("click", async () => {
  try {
    const data = await requestJson("/api/channels/save", {method: "POST", body: JSON.stringify({channels: streamRowsFromDom()})});
    alert(`频道草稿已保存：${data.saved} 条更新，${data.deleted} 条删除`);
  } catch (err) { alert(err.message); }
});
$("autoClassifyBtn").addEventListener("click", async () => {
  for (const row of document.querySelectorAll("#streamsTableBody tr[data-key]")) {
    const name = row.querySelector(".channel-name")?.value.trim() || "";
    const category = row.querySelector(".channel-category");
    if (!category) continue;
    if (/CCTV/i.test(name) || name.includes("央视") || name.includes("中央")) category.value = "央视频道";
    else if (name.includes("卫视")) category.value = "卫视频道";
    else category.value = "其它频道";
  }
  try {
    await requestJson("/api/channels/save", {method: "POST", body: JSON.stringify({channels: streamRowsFromDom()})});
  } catch (err) { alert(err.message); }
});
$("selectAllStreams").addEventListener("change", (event) => {
  document.querySelectorAll(".stream-check").forEach((checkbox) => { checkbox.checked = event.target.checked; });
});
$("applyBatchCategoryBtn").addEventListener("click", () => {
  const category = $("batchCategory").value;
  document.querySelectorAll("#streamsTableBody tr[data-key]").forEach((row) => {
    if (row.querySelector(".stream-check")?.checked) {
      row.querySelector(".channel-category").value = category;
    }
  });
});
$("probeSelectedBtn").addEventListener("click", probeBatch);
$("streamsTableBody").addEventListener("click", (event) => {
  const probeButton = event.target.closest(".probe-one-btn");
  if (probeButton) {
    const row = probeButton.closest("tr[data-key]");
    if (row) probeOneByRow(row);
    return;
  }
  const previewButton = event.target.closest(".preview-play-btn");
  if (previewButton) {
    openPreview(
      previewButton.dataset.streamUrl,
      previewButton.dataset.playerUrl,
      previewButton.dataset.title,
      previewButton.dataset.snapshotUrl,
    );
    return;
  }
  const snapshotButton = event.target.closest(".snapshot-thumb-btn");
  if (snapshotButton) {
    openSnapshot(snapshotButton.dataset.snapshotUrl, snapshotButton.dataset.title);
  }
});
$("exportBtn").addEventListener("click", async () => {
  try {
    const data = await requestJson("/api/export", {method: "POST", body: JSON.stringify({channels: streamRowsFromDom()})});
    showExportDownloads(data.files);
    $("exportResult").className = "result-box";
    $("exportResult").textContent = `导出完成：共 ${data.count} 个原始频道；已生成直连 M3U、rtp2httpd 源地址 M3U、JSON、TXT、CSV；4K高清分组 ${data.quality_group_counts?.["4K高清"] ?? 0} 条，普通频道分组 ${data.quality_group_counts?.["普通频道"] ?? 0} 条，未识别清晰度 ${data.unclassified_resolution_count ?? 0} 条。`;
  } catch (err) { alert(err.message); }
});
$("logsBtn").addEventListener("click", openLogs);
$("closeLogsBtn").addEventListener("click", closeLogs);
$("closePreviewBtn").addEventListener("click", closePreview);
$("previewModal").addEventListener("click", (event) => {
  if (event.target.id === "previewModal") closePreview();
});
$("closeSnapshotBtn").addEventListener("click", closeSnapshot);
$("snapshotModal").addEventListener("click", (event) => {
  if (event.target.id === "snapshotModal") closeSnapshot();
});
$("clearLogMemoryBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/logs/clear-memory", {method: "POST", body: "{}"});
    $("logsOutput").textContent = "";
    state.latestLogId = 0;
    await appendLogs();
  } catch (err) { alert(err.message); }
});

bootstrap().catch((err) => alert(err.message));
