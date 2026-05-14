const $ = (id) => document.getElementById(id);

const _IGNORED_KEYS_STORAGE = "iptv_ignored_keys";
function _loadIgnoredKeys() {
  try { return new Set(JSON.parse(localStorage.getItem(_IGNORED_KEYS_STORAGE) || "[]")); } catch { return new Set(); }
}
function _saveIgnoredKeys(set) {
  try { localStorage.setItem(_IGNORED_KEYS_STORAGE, JSON.stringify([...set])); } catch {}
}

const state = {
  logsOpen: false,
  latestLogId: 0,
  poller: null,
  logPoller: null,
  streams: [],
  epgSources: [],
  logoSources: [],
  ignoredKeys: _loadIgnoredKeys(),
  logoAuto: true,
  epgAuto: true,
  detectedEpgUrl: "",
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
  const epgUrl = state.epgAuto
    ? (state.detectedEpgUrl || $("epgUrl").value.trim() || state.epgSources[0]?.url || "")
    : $("epgUrl").value.trim();
  const logoUrl = state.logoAuto
    ? (state.logoSources[0]?.url || "")
    : $("logoUrl").value.trim();
  return {
    interface: $("interface").value,
    http_host: $("httpHost").value.trim(),
    http_port: Number($("httpPort").value || 5140),
    path_mode: $("pathMode").value,
    duration: Number($("duration").value || 0),
    auto_probe: $("autoProbe").checked,
    auto_epg: $("autoEpg").checked,
    epg_url: epgUrl,
    logo_url: logoUrl,
  };
}

function formScheduleSettings() {
  return {
    ...formSettings(),
    schedule_m3u_url: $("scheduleM3uUrl").value.trim(),
    schedule_output_name: $("scheduleOutputName").value.trim() || "scheduled-epg.m3u",
    schedule_enabled: $("scheduleEnabled").checked,
    schedule_unit: $("scheduleUnit").value,
    schedule_every: Number($("scheduleEvery").value || 1),
    schedule_hour: Number($("scheduleHour").value || 0),
    schedule_minute: Number($("scheduleMinute").value || 0),
  };
}

function showHome() {
  $("homePage").hidden = false;
  $("workbenchPage").hidden = true;
  document.querySelectorAll("[data-page='home']").forEach((item) => item.classList.add("active"));
  document.querySelectorAll("[data-tab]").forEach((item) => item.classList.remove("active"));
}

function showTab(tabName) {
  $("homePage").hidden = true;
  $("workbenchPage").hidden = false;
  $("snifferTab").hidden = tabName !== "sniffer";
  $("scheduleTab").hidden = tabName !== "schedule";
  document.querySelectorAll("[data-page='home']").forEach((item) => item.classList.remove("active"));
  document.querySelectorAll("[data-tab]").forEach((item) => {
    item.classList.toggle("active", item.dataset.tab === tabName);
  });
}

function setRuntimeBadge(health) {
  const badge = $("runtimeBadge");
  const captureOk = Boolean(health.runtime?.ok);
  const probeOk = Boolean(health.probe_runtime?.ok);
  if (captureOk && probeOk) {
    badge.className = "chip ok";
    badge.textContent = "抓包与 4K 自动识别环境正常";
  } else if (captureOk && !probeOk) {
    badge.className = "chip warning";
    badge.textContent = "抓包可用，ffprobe 异常";
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
  if (metrics.output_files?.["scheduled-epg.m3u"]) {
    $("downloadScheduledM3u").href = "/api/download/scheduled-epg.m3u";
    $("downloadScheduledM3u").classList.remove("disabled");
  }
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
  } else if ((epg.channels ?? 0) > 0) {
    badge.className = epg.last_error ? "chip warning" : "chip ok";
    badge.textContent = `EPG ${epg.channels} 个频道 / 台标 ${epg.logos ?? 0}`;
    badge.title = epg.last_error || "";
  } else if (epg.last_error) {
    badge.className = "chip danger";
    badge.textContent = "EPG 加载失败";
    badge.title = epg.last_error;
  } else {
    badge.className = "chip neutral";
    badge.textContent = "EPG 未加载";
    badge.title = "";
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

function populatePreset(select, sources) {
  const current = select.value;
  select.innerHTML = "";
  for (const source of sources || []) {
    const option = document.createElement("option");
    option.value = source.url;
    option.textContent = source.name;
    select.appendChild(option);
  }
  const custom = document.createElement("option");
  custom.value = "";
  custom.textContent = "自定义";
  select.appendChild(custom);
  select.value = [...select.options].some((option) => option.value === current) ? current : (select.options[0]?.value || "");
}

function syncPresetFromUrl(select, url) {
  const value = String(url || "").trim();
  select.value = [...select.options].some((option) => option.value === value) ? value : "";
}

function setEpgMode(auto, detectNow = auto) {
  state.epgAuto = auto;
  $("epgAutoBtn").classList.toggle("active", auto);
  $("epgManualBtn").classList.toggle("active", !auto);
  $("epgManualRow").hidden = auto;
  if (detectNow) triggerEpgDetect();
}

async function triggerEpgDetect() {
  const statusEl = $("epgDetectStatus");
  if (statusEl) { statusEl.textContent = "检测中…"; statusEl.hidden = false; }
  try {
    await requestJson("/api/epg/detect-best", {method: "POST", body: "{}"});
    const poll = async () => {
      const d = await requestJson("/api/epg/detect-best");
      if (!state.epgAuto) return;
      if (d.status === "detecting") { setTimeout(poll, 1500); return; }
      if (d.best_url) {
        state.detectedEpgUrl = d.best_url;
        if (statusEl) { statusEl.textContent = `已选：${d.best_name}（${d.best_channels} 频道）`; }
      } else {
        if (statusEl) { statusEl.textContent = "检测失败，将使用默认源"; }
      }
    };
    poll();
  } catch (_) {
    if (statusEl) { statusEl.textContent = ""; statusEl.hidden = true; }
  }
}

function setLogoMode(auto) {
  state.logoAuto = auto;
  $("logoAutoBtn").classList.toggle("active", auto);
  $("logoManualBtn").classList.toggle("active", !auto);
  $("logoManualRow").hidden = auto;
}

let _sourcesModalType = "epg";

function openSourcesModal(type) {
  _sourcesModalType = type;
  $("sourcesModalTitle").textContent = type === "epg" ? "管理 EPG 来源" : "管理台标来源";
  $("sourcesAddName").value = "";
  $("sourcesAddUrl").value = "";
  renderSourcesList();
  $("sourcesModal").hidden = false;
}

function closeSourcesModal() {
  $("sourcesModal").hidden = true;
}

async function renderSourcesList() {
  const type = _sourcesModalType;
  const sources = type === "epg" ? state.epgSources : state.logoSources;
  const list = $("sourcesList");
  if (!sources.length) {
    list.innerHTML = `<div class="sources-empty">暂无来源</div>`;
    return;
  }
  list.innerHTML = sources.map((s) => `
    <div class="source-row" data-id="${escapeHtml(s.id)}" data-builtin="${s.builtin ? "1" : "0"}">
      <span class="source-name">${escapeHtml(s.name)}</span>
      <span class="source-url muted small">${escapeHtml(s.url)}</span>
      ${s.builtin ? `<span class="chip neutral" style="font-size:11px">内置</span>` : `<button class="secondary xs-btn source-del-btn" type="button" data-id="${escapeHtml(s.id)}">删除</button>`}
    </div>
  `).join("");
}

async function addCustomSource() {
  const name = $("sourcesAddName").value.trim();
  const url = $("sourcesAddUrl").value.trim();
  if (!name || !url) { alert("名称和地址不能为空"); return; }
  try {
    await requestJson("/api/sources/custom", {
      method: "POST",
      body: JSON.stringify({type: _sourcesModalType, name, url}),
    });
    $("sourcesAddName").value = "";
    $("sourcesAddUrl").value = "";
    await loadEpgSources();
    renderSourcesList();
  } catch (err) { alert(err.message); }
}

async function deleteCustomSource(id) {
  try {
    await requestJson(`/api/sources/custom/${_sourcesModalType}/${id}`, {method: "DELETE"});
    await loadEpgSources();
    renderSourcesList();
  } catch (err) { alert(err.message); }
}

async function loadEpgSources() {
  const data = await requestJson("/api/epg/sources");
  state.epgSources = data.epg_sources || [];
  state.logoSources = data.logo_sources || [];
  populatePreset($("epgPreset"), state.epgSources);
  populatePreset($("logoPreset"), state.logoSources);
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
  $("logoUrl").value = data.logo_url || "";
  syncPresetFromUrl($("epgPreset"), $("epgUrl").value);
  syncPresetFromUrl($("logoPreset"), $("logoUrl").value);
  const knownEpgUrls = new Set(state.epgSources.map((s) => s.url));
  const savedEpgUrl = data.epg_url || "";
  setEpgMode(!savedEpgUrl || knownEpgUrls.has(savedEpgUrl), false);
  const knownLogoUrls = new Set(state.logoSources.map((s) => s.url));
  const savedLogoUrl = data.logo_url || "";
  setLogoMode(!savedLogoUrl || knownLogoUrls.has(savedLogoUrl));
  $("scheduleM3uUrl").value = data.schedule_m3u_url || "";
  $("scheduleOutputName").value = data.schedule_output_name || "scheduled-epg.m3u";
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
  if (schedule.running) {
    badge.className = "chip warning";
    badge.textContent = "更新中";
  } else if (schedule.enabled) {
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
    `M3U：<span class="mono">${escapeHtml(schedule.m3u_url || "-")}</span>`,
    `下次执行：<span class="mono">${escapeHtml(schedule.next_run_text || "-")}</span>`,
    `上次执行：<span class="mono">${escapeHtml(schedule.last_run_text || "-")}</span>`,
  ];
  if (schedule.last_result) {
    lines.push(`上次结果：${escapeHtml(schedule.last_result.count ?? 0)} 个频道，匹配 ${escapeHtml(schedule.last_result.matched ?? 0)} 个，输出 <span class="mono">${escapeHtml(schedule.last_result.file || "-")}</span>`);
    if (schedule.last_result.file) {
      $("downloadScheduledM3u").href = `/api/download/${schedule.last_result.file}`;
      $("downloadScheduledM3u").classList.remove("disabled");
    }
  }
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
    probe_message: row.dataset.probeMessage || "未识别",
    codec_name: row.dataset.codecName || "",
    width: row.dataset.width ? Number(row.dataset.width) : null,
    height: row.dataset.height ? Number(row.dataset.height) : null,
    frame_rate: row.dataset.frameRate || "",
    resolution_label: row.dataset.resolutionLabel || "未识别",
    quality_group: row.dataset.qualityGroup || "未识别",
    detected_name: row.dataset.detectedName || "",
    detected_name_source: row.dataset.detectedNameSource || "",
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
  return (streams || []).filter((s) => !state.ignoredKeys.has(s.key)).map((stream) => {
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
      detected_name: stream.detected_name || draft.detected_name,
      detected_name_source: stream.detected_name_source || draft.detected_name_source,
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
    if (stream.quality_group === "4K高清") return '<span class="badge ultra">4K高清</span>';
    if (stream.quality_group === "高清频道") return '<span class="badge hd">高清频道</span>';
    return '<span class="badge info">普通频道</span>';
  }
  if (status === "partial") return '<span class="badge wait">信息不完整</span>';
  if (status === "failed") return '<span class="badge danger">识别失败</span>';
  return '<span class="badge neutral">等待自动识别</span>';
}

function streamInfoHtml(stream) {
  const codec = stream.codec_name ? escapeHtml(stream.codec_name) : "-";
  const resolution = stream.width && stream.height ? `${escapeHtml(stream.width)}×${escapeHtml(stream.height)}` : escapeHtml(stream.resolution_label || "未识别");
  const fps = stream.frame_rate ? escapeHtml(stream.frame_rate) : "-";
  const fcc = stream.fcc_ip && stream.fcc_port ? `<span>FCC：${escapeHtml(stream.fcc_ip)}:${escapeHtml(stream.fcc_port)}</span>` : "";
  const autoName = stream.auto_name ? `<span>自动名：${escapeHtml(stream.auto_name)}</span>` : "";
  const detectedName = stream.detected_name && stream.detected_name !== stream.auto_name ? `<span>流内名称：${escapeHtml(stream.detected_name)}</span>` : "";
  const epgName = stream.tvg_name || stream.tvg_id ? `<span>EPG：${escapeHtml(stream.tvg_name || "-")} / ${escapeHtml(stream.tvg_id || "-")}</span>` : "";
  const message = stream.probe_message ? `<div class="probe-note">${escapeHtml(stream.probe_message)}</div>` : "";
  return `<div class="probe-meta">${probeBadge(stream)}${autoName}${detectedName}${epgName}<span>编码：${codec}</span><span>分辨率：${resolution}</span><span>帧率：${fps}</span>${fcc}${message}</div>`;
}

function previewHtml(stream) {
  if (!stream.preview_url) return '<span class="muted">-</span>';
  return `<a class="preview-link" href="${escapeHtml(stream.preview_url)}" target="_blank" rel="noreferrer">${escapeHtml(stream.preview_url)}</a>`;
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

function tableHasEditingFocus() {
  const active = document.activeElement;
  const body = $("streamsTableBody");
  return Boolean(
    active
    && body?.contains(active)
    && ["INPUT", "SELECT", "TEXTAREA"].includes(active.tagName)
  );
}

function renderStreams(streams) {
  const currentChecks = new Map([...document.querySelectorAll("#streamsTableBody tr[data-key]")].map((row) => [row.dataset.key, Boolean(row.querySelector(".stream-check")?.checked)]));
  let filtered = (streams || []).filter((s) => !state.ignoredKeys.has(s.key));
  if ($("filterBestPerIp").checked) {
    const bestPerIp = new Map();
    for (const s of filtered) {
      const prev = bestPerIp.get(s.host);
      if (!prev || (s.packets || 0) > (prev.packets || 0)) bestPerIp.set(s.host, s);
    }
    filtered = [...bestPerIp.values()];
  }
  const sorted = filtered.sort((a, b) => (b.first_seen || 0) - (a.first_seen || 0));
  state.streams = preserveRowEdits(sorted);
  const body = $("streamsTableBody");
  if (!state.streams.length) {
    body.innerHTML = '<tr><td colspan="9" class="empty">暂无候选流</td></tr>';
    return;
  }
  body.innerHTML = state.streams.map((stream) => {
    const candidateBadge = stream.eligible ? '<span class="badge ok">有效候选</span>' : '<span class="badge wait">包数偏少</span>';
    const checked = currentChecks.get(stream.key) ? "checked" : "";
    return `<tr data-key="${escapeHtml(stream.key)}"
        data-host="${escapeHtml(stream.host)}"
        data-port="${escapeHtml(stream.port)}"
        data-packets="${escapeHtml(stream.packets)}"
        data-probe-status="${escapeHtml(stream.probe_status || "not_probed")}"
        data-probe-message="${escapeHtml(stream.probe_message || "未识别")}"
        data-codec-name="${escapeHtml(stream.codec_name || "")}"
        data-width="${escapeHtml(stream.width ?? "")}"
        data-height="${escapeHtml(stream.height ?? "")}"
        data-frame-rate="${escapeHtml(stream.frame_rate || "")}"
        data-resolution-label="${escapeHtml(stream.resolution_label || "未识别")}"
        data-quality-group="${escapeHtml(stream.quality_group || "未识别")}"
        data-detected-name="${escapeHtml(stream.detected_name || "")}"
        data-detected-name-source="${escapeHtml(stream.detected_name_source || "")}"
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
      <td><input class="channel-name" type="text" value="${escapeHtml(stream.name || "")}" placeholder="${stream.auto_name || stream.tvg_name ? "自动识别，可修正" : "人工补全频道名"}"></td>
      <td><input class="channel-category" type="text" list="categoryDatalist" value="${escapeHtml(stream.category || "其它频道")}"></td>
      <td>${streamInfoHtml(stream)}</td>
      <td>${previewHtml(stream)}</td>
    </tr>`;
  }).join("");
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
  if (tableHasEditingFocus()) {
    state.streams = preserveRowEdits(streams.streams || []);
  } else {
    renderStreams(streams.streams || []);
  }
}

function startPolling(fast = false) {
  if (state.poller) clearInterval(state.poller);
  const ms = fast ? 1000 : 2000;
  state.poller = setInterval(async () => {
    try {
      await refreshStatusAndStreams();
    } catch (_) {}
  }, ms);
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

async function checkVersion() {
  try {
    const data = await requestJson("/api/version");
    const badge = $("updateBadge");
    if (data.update_available && data.latest_version) {
      badge.textContent = `有新版本 v${data.latest_version}`;
      badge.href = data.release_url || "#";
      badge.hidden = false;
    } else {
      badge.hidden = true;
    }
  } catch (_) {}
}

async function bootstrap() {
  await Promise.all([loadHealth(), loadInterfaces(), loadEpgSources()]);
  await loadSettings();
  await Promise.all([refreshStatusAndStreams(), appendLogs(), checkVersion()]);
  if (localStorage.getItem("logsOpen") === "1") openLogs();
  const initialState = (await requestJson("/api/status").catch(() => ({}))).state;
  startPolling(initialState === "running");
}

document.querySelectorAll("[data-page='home']").forEach((item) => item.addEventListener("click", showHome));
document.querySelectorAll("[data-tab]").forEach((item) => item.addEventListener("click", () => showTab(item.dataset.tab)));
$("epgPreset").addEventListener("change", () => {
  if ($("epgPreset").value) $("epgUrl").value = $("epgPreset").value;
});
$("logoPreset").addEventListener("change", () => {
  if ($("logoPreset").value) $("logoUrl").value = $("logoPreset").value;
});
$("epgUrl").addEventListener("input", () => syncPresetFromUrl($("epgPreset"), $("epgUrl").value));
$("logoUrl").addEventListener("input", () => syncPresetFromUrl($("logoPreset"), $("logoUrl").value));
$("filterBestPerIp").addEventListener("change", () => renderStreams(state.streams));
$("epgAutoBtn").addEventListener("click", () => setEpgMode(true));
$("epgManualBtn").addEventListener("click", () => setEpgMode(false));
$("logoAutoBtn").addEventListener("click", () => setLogoMode(true));
$("logoManualBtn").addEventListener("click", () => setLogoMode(false));
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
$("runScheduleNowBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/schedule", {method: "POST", body: JSON.stringify(formScheduleSettings())});
    const data = await requestJson("/api/schedule/run-now", {method: "POST", body: "{}"});
    renderSchedule(data);
  } catch (err) { alert(err.message); }
});
$("startBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/capture/start", {method: "POST", body: JSON.stringify(formSettings())});
    await refreshStatusAndStreams();
    startPolling(true);
  } catch (err) { alert(err.message); }
});
$("stopBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/capture/stop", {method: "POST", body: "{}"});
    await refreshStatusAndStreams();
    startPolling(false);
  } catch (err) { alert(err.message); }
});
$("resetBtn").addEventListener("click", async () => {
  try {
    state.ignoredKeys.clear();
    _saveIgnoredKeys(state.ignoredKeys);
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
    await refreshStatusAndStreams();
  } catch (err) { alert(err.message); }
});
$("deleteCheckedBtn").addEventListener("click", async () => {
  const checkedRows = [...document.querySelectorAll("#streamsTableBody tr[data-key]")]
    .filter((row) => row.querySelector(".stream-check")?.checked);
  if (!checkedRows.length) return;
  checkedRows.forEach((row) => state.ignoredKeys.add(row.dataset.key));
  _saveIgnoredKeys(state.ignoredKeys);
  state.streams = state.streams.filter((s) => !state.ignoredKeys.has(s.key));
  renderStreams(state.streams);
  try {
    await requestJson("/api/channels/save", {
      method: "POST",
      body: JSON.stringify({
        channels: checkedRows.map((row) => ({
          key: row.dataset.key,
          host: row.dataset.host,
          port: Number(row.dataset.port),
          name: "",
        })),
      }),
    });
  } catch (_) {}
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
$("streamsTableBody").addEventListener("click", (event) => {
  const snapshotButton = event.target.closest(".snapshot-thumb-btn");
  if (snapshotButton) openSnapshot(snapshotButton.dataset.snapshotUrl, snapshotButton.dataset.title);
});
$("streamsTableBody").addEventListener("focusout", () => {
  setTimeout(() => {
    if (!tableHasEditingFocus()) renderStreams(state.streams);
  }, 80);
});
$("exportBtn").addEventListener("click", async () => {
  try {
    const body = {...formSettings(), channels: streamRowsFromDom()};
    const data = await requestJson("/api/export", {method: "POST", body: JSON.stringify(body)});
    showExportDownloads(data.files);
    $("exportResult").className = "result-box";
    $("exportResult").textContent = `导出完成：共 ${data.count} 个原始频道；4K高清 ${data.quality_group_counts?.["4K高清"] ?? 0} 条，高清频道 ${data.quality_group_counts?.["高清频道"] ?? 0} 条，普通频道 ${data.quality_group_counts?.["普通频道"] ?? 0} 条，未识别清晰度 ${data.unclassified_resolution_count ?? 0} 条。`;
  } catch (err) { alert(err.message); }
});
$("logsBtn").addEventListener("click", openLogs);
$("closeLogsBtn").addEventListener("click", closeLogs);
$("manageEpgSourcesBtn").addEventListener("click", () => openSourcesModal("epg"));
$("manageLogoSourcesBtn").addEventListener("click", () => openSourcesModal("logo"));
$("closeSourcesBtn").addEventListener("click", closeSourcesModal);
$("sourcesModal").addEventListener("click", (event) => {
  if (event.target.id === "sourcesModal") closeSourcesModal();
});
$("sourcesAddBtn").addEventListener("click", addCustomSource);
$("sourcesList").addEventListener("click", (event) => {
  const btn = event.target.closest(".source-del-btn");
  if (btn) deleteCustomSource(btn.dataset.id);
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
