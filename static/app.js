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
  channelList: [],
  epgSources: [],
  logoSources: [],
  allEpgSources: [],
  allLogoSources: [],
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
    auto_epg: $("autoEpg").checked,
    epg_url: state.epgAuto
      ? (state.detectedEpgUrl || $("epgUrl").value.trim() || state.epgSources[0]?.url || "")
      : $("epgUrl").value.trim(),
    logo_url: state.logoAuto ? (state.logoSources[0]?.url || "") : $("logoUrl").value.trim(),
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
  $("stbDiscoveryTab").hidden = tabName !== "stbDiscovery";
  $("channelListTab").hidden = tabName !== "channelList";
  if (tabName === "channelList") loadChannelList();
  if (tabName === "schedule") loadScheduleEpgSources();
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
  for (const id of ["interface", "stbDiscoveryIface"]) {
    const select = $(id);
    if (!select) continue;
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

function renderSourcesList() {
  const type = _sourcesModalType;
  const sources = type === "epg" ? state.allEpgSources : state.allLogoSources;
  const list = $("sourcesList");
  if (!sources.length) {
    list.innerHTML = `<div class="sources-empty">暂无来源</div>`;
    return;
  }
  list.innerHTML = sources.map((s) => {
    const nameHtml = `<span class="source-name${s.deleted ? " muted" : ""}">${escapeHtml(s.name)}</span>`;
    const urlHtml = `<span class="source-url muted small">${escapeHtml(s.url)}</span>`;
    let action;
    if (s.builtin) {
      action = s.deleted
        ? `<button class="secondary xs-btn source-restore-btn" type="button" data-id="${escapeHtml(s.id)}">恢复</button>`
        : `<button class="secondary xs-btn source-del-btn" type="button" data-id="${escapeHtml(s.id)}" data-builtin="1">删除</button>`;
    } else {
      action = `<button class="secondary xs-btn source-del-btn" type="button" data-id="${escapeHtml(s.id)}" data-builtin="0">删除</button>`;
    }
    return `<div class="source-row${s.deleted ? " source-row--deleted" : ""}" data-id="${escapeHtml(s.id)}">${nameHtml}${urlHtml}${action}</div>`;
  }).join("");
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

async function deleteBuiltin(id) {
  try {
    await requestJson(`/api/sources/builtin/${_sourcesModalType}/${id}`, {method: "DELETE"});
    await loadEpgSources();
    renderSourcesList();
  } catch (err) { alert(err.message); }
}

async function restoreBuiltin(id) {
  try {
    await requestJson(`/api/sources/builtin/${_sourcesModalType}/${id}/restore`, {method: "POST", body: "{}"});
    await loadEpgSources();
    renderSourcesList();
  } catch (err) { alert(err.message); }
}

async function loadEpgSources() {
  const data = await requestJson("/api/epg/sources");
  state.epgSources = data.epg_sources || [];
  state.logoSources = data.logo_sources || [];
  state.allEpgSources = data.all_epg_sources || [];
  state.allLogoSources = data.all_logo_sources || [];
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
    `<strong>${escapeHtml(schedule.last_message || (schedule.enabled ? "定时刷新已启用" : "定时刷新未启用"))}</strong>`,
    `模式：<span class="mono">${mode}</span>`,
    `下次执行：<span class="mono">${escapeHtml(schedule.next_run_text || "-")}</span>`,
    `上次执行：<span class="mono">${escapeHtml(schedule.last_run_text || "-")}</span>`,
  ];
  if (schedule.last_result) {
    const r = schedule.last_result;
    lines.push(`上次结果：刷新 ${escapeHtml(r.count ?? 0)} 个来源，合计 ${escapeHtml(r.total_channels ?? 0)} 个频道`);
    if (r.errors?.length) lines.push(`失败 ${r.errors.length} 个来源`);
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
  return `<div class="probe-meta probe-meta--clickable" data-probe-key="${escapeHtml(stream.key)}" title="点击查看完整流信息">${probeBadge(stream)}${autoName}${detectedName}${epgName}<span>编码：${codec}</span><span>分辨率：${resolution}</span><span>帧率：${fps}</span>${fcc}${message}</div>`;
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
      <td><input class="channel-name" type="text" value="${escapeHtml(stream.name || stream.auto_name || "")}" placeholder="${stream.auto_name || stream.tvg_name ? "自动识别，可修正" : "人工补全频道名"}"></td>
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

function buildProbeDetailHtml(stream) {
  const parts = [];
  parts.push(`<div class="pd-section"><span class="pd-addr">${escapeHtml(stream.host)}:${escapeHtml(String(stream.port))}</span></div>`);
  const codec = stream.codec_name || "-";
  const res = stream.width && stream.height ? `${stream.width}×${stream.height}` : (stream.resolution_label || "未识别");
  const fps = stream.frame_rate || "-";
  let bitrate = "-";
  if (stream.format_bit_rate) bitrate = `${(stream.format_bit_rate / 1_000_000).toFixed(2)} Mbps`;
  const fieldOrderMap = {"progressive": "逐行", "tt": "隔行（上场优先）", "bb": "隔行（下场优先）", "tb": "隔行", "bt": "隔行"};
  const scanType = stream.field_order ? (fieldOrderMap[stream.field_order] || stream.field_order) : null;
  let profileStr = null;
  if (stream.video_profile) {
    let lvl = "";
    if (stream.video_level) {
      const isHevc = (stream.codec_name || "").toLowerCase() === "hevc";
      lvl = " " + (isHevc ? (stream.video_level / 30).toFixed(1) : `${Math.floor(stream.video_level / 10)}.${stream.video_level % 10}`);
    }
    profileStr = `${stream.video_profile}${lvl}`;
  }
  const pixStr = stream.pix_fmt ? (stream.pix_fmt.includes("10") ? "10bit（可能 HDR）" : "8bit") : null;
  const codecRows = [
    `<span class="pd-k">判定</span><span>${probeBadge(stream)}</span>`,
    `<span class="pd-k">编码</span><span>${escapeHtml(codec)}</span>`,
    profileStr ? `<span class="pd-k">规格</span><span>${escapeHtml(profileStr)}</span>` : "",
    `<span class="pd-k">分辨率</span><span>${escapeHtml(res)}</span>`,
    scanType ? `<span class="pd-k">扫描方式</span><span>${escapeHtml(scanType)}</span>` : "",
    `<span class="pd-k">帧率</span><span>${escapeHtml(fps)}</span>`,
    pixStr ? `<span class="pd-k">色深</span><span>${escapeHtml(pixStr)}</span>` : "",
    `<span class="pd-k">码率</span><span>${escapeHtml(bitrate)}</span>`,
  ].filter(Boolean).join("");
  parts.push(`<div class="pd-section"><div class="pd-title">清晰度 / 编码</div><div class="pd-grid">${codecRows}</div></div>`);
  if (stream.audio_streams?.length) {
    const rows = stream.audio_streams.map((a, i) => {
      const kbps = a.bit_rate ? `${Math.round(a.bit_rate / 1000)} kbps` : null;
      const info = [a.codec_name, a.sample_rate ? `${a.sample_rate} Hz` : null, a.channel_layout || (a.channels ? `${a.channels}ch` : null), kbps].filter(Boolean).join(" · ");
      return `<span class="pd-k">音频流 ${i + 1}</span><span>${escapeHtml(info || "-")}</span>`;
    }).join("");
    parts.push(`<div class="pd-section"><div class="pd-title">音频流</div><div class="pd-grid">${rows}</div></div>`);
  }
  const svcName = stream.detected_name || stream.auto_name;
  if (svcName || stream.service_provider || stream.nb_programs || stream.nb_streams) {
    const rows = [
      svcName ? `<span class="pd-k">频道名</span><span>${escapeHtml(svcName)}</span>` : "",
      stream.service_provider ? `<span class="pd-k">运营商</span><span>${escapeHtml(stream.service_provider)}</span>` : "",
      stream.nb_programs ? `<span class="pd-k">节目数</span><span>${stream.nb_programs}</span>` : "",
      stream.nb_streams ? `<span class="pd-k">流数量</span><span>${stream.nb_streams}</span>` : "",
    ].filter(Boolean).join("");
    parts.push(`<div class="pd-section"><div class="pd-title">节目信息</div><div class="pd-grid">${rows}</div></div>`);
  }
  if (stream.tvg_id || stream.tvg_name || stream.tvg_logo || stream.epg_source) {
    const rows = [
      stream.tvg_id ? `<span class="pd-k">tvg-id</span><span>${escapeHtml(stream.tvg_id)}</span>` : "",
      stream.tvg_name ? `<span class="pd-k">tvg-name</span><span>${escapeHtml(stream.tvg_name)}</span>` : "",
      stream.tvg_logo ? `<span class="pd-k">台标</span><span style="overflow-wrap:anywhere">${escapeHtml(stream.tvg_logo)}</span>` : "",
      stream.epg_source ? `<span class="pd-k">EPG来源</span><span style="overflow-wrap:anywhere">${escapeHtml(stream.epg_source)}</span>` : "",
    ].filter(Boolean).join("");
    parts.push(`<div class="pd-section"><div class="pd-title">EPG / 台标</div><div class="pd-grid">${rows}</div></div>`);
  }
  if (stream.fcc_ip && stream.fcc_port) {
    parts.push(`<div class="pd-section"><div class="pd-title">FCC</div><div class="pd-grid">
      <span class="pd-k">FCC服务器</span><span>${escapeHtml(stream.fcc_ip)}:${escapeHtml(String(stream.fcc_port))}</span>
    </div></div>`);
  }
  const probedAt = stream.probed_at ? new Date(stream.probed_at * 1000).toLocaleString("zh-CN") : "-";
  parts.push(`<div class="pd-section"><div class="pd-title">识别状态</div><div class="pd-grid">
    <span class="pd-k">状态</span><span>${escapeHtml(stream.probe_message || "未识别")}</span>
    <span class="pd-k">识别时间</span><span>${escapeHtml(probedAt)}</span>
  </div></div>`);
  return parts.join("");
}

function openProbeDetail(key) {
  const stream = state.streams.find((s) => s.key === key);
  if (!stream) return;
  $("probeDetailTitle").textContent = stream.name || stream.key;
  $("probeDetailBody").innerHTML = buildProbeDetailHtml(stream);
  $("probeDetailModal").hidden = false;
}

function closeProbeDetail() {
  $("probeDetailModal").hidden = true;
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

function showClExportDownloads(files) {
  const map = {
    direct_m3u: $("clDownloadDirectM3u"),
    source_m3u: $("clDownloadSourceM3u"),
    json: $("clDownloadJson"),
    txt: $("clDownloadTxt"),
    csv: $("clDownloadCsv"),
  };
  for (const [key, link] of Object.entries(map)) {
    if (files?.[key]) {
      link.href = `/api/download/${files[key]}`;
      link.classList.remove("disabled");
    }
  }
}

async function loadChannelList() {
  try {
    const data = await requestJson("/api/channels");
    state.channelList = data.channels || [];
    renderChannelList(state.channelList);
  } catch (err) { console.warn("loadChannelList:", err.message); }
}

function renderChannelList(channels) {
  $("clChannelCount").textContent = `${channels.length} 个`;
  const tbody = $("clChannelTableBody");
  if (!channels.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">频道列表为空，请先导入运营商频道或嗅探结果。</td></tr>';
    return;
  }
  tbody.innerHTML = channels.map((ch) => {
    const addr = ch.key || `${ch.host || ""}:${ch.port ?? ""}`;
    const quality = (ch.quality_group && ch.quality_group !== "未识别")
      ? ch.quality_group
      : ((ch.resolution_label && ch.resolution_label !== "未识别") ? ch.resolution_label : "-");
    const epg = ch.tvg_id || "-";
    return `
    <tr data-key="${escapeHtml(ch.key || "")}">
      <td><input type="checkbox" class="cl-check"></td>
      <td>${escapeHtml(ch.name || "")}</td>
      <td class="mono small">${escapeHtml(addr)}</td>
      <td>${escapeHtml(ch.category || "")}</td>
      <td>${escapeHtml(quality)}</td>
      <td class="mono small">${escapeHtml(epg)}</td>
    </tr>`;
  }).join("");
}

async function loadScheduleEpgSources() {
  try {
    await loadEpgSources();
    const epgStatus = await requestJson("/api/epg/status");
    const sourceStats = epgStatus.source_stats || {};
    renderScheduleEpgSources(state.epgSources, sourceStats);
  } catch (err) { console.warn("loadScheduleEpgSources:", err.message); }
}

function renderScheduleEpgSources(sources, stats) {
  const list = $("scheduleEpgSourceList");
  if (!sources.length) {
    list.innerHTML = '<div class="muted" style="padding:8px 0">暂无配置的 EPG 来源。在嗅探整理页面可添加来源。</div>';
    return;
  }
  list.innerHTML = sources.map((src) => {
    const s = stats[src.url] || {};
    const lastRefresh = s.last_refresh ? new Date(s.last_refresh * 1000).toLocaleString("zh-CN") : "从未刷新";
    const channelCount = s.channels != null ? `　${s.channels} 个频道` : "";
    return `<div class="epg-source-row">
      <span class="epg-source-name">${escapeHtml(src.name)}</span>
      <span class="muted small" style="overflow-wrap:anywhere">${escapeHtml(src.url)}</span>
      <span class="muted small">${escapeHtml(lastRefresh)}${escapeHtml(channelCount)}</span>
      <button class="secondary xs-btn epg-src-refresh-btn" data-epg-url="${escapeHtml(src.url)}" type="button">刷新</button>
    </div>`;
  }).join("");
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
$("importToChannelListBtn").addEventListener("click", async () => {
  try {
    const data = await requestJson("/api/channels/save", {method: "POST", body: JSON.stringify({channels: streamRowsFromDom()})});
    alert(`已导入 ${data.saved} 个频道到频道列表。`);
    showTab("channelList");
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
$("clExportBtn").addEventListener("click", async () => {
  try {
    const selectedKeys = new Set([...document.querySelectorAll("#clChannelTableBody tr[data-key]")]
      .filter((row) => row.querySelector(".cl-check")?.checked)
      .map((row) => row.dataset.key));
    const channels = selectedKeys.size > 0
      ? (state.channelList || []).filter((ch) => selectedKeys.has(ch.key))
      : (state.channelList || []);
    const body = {...formSettings(), channels};
    const data = await requestJson("/api/export", {method: "POST", body: JSON.stringify(body)});
    showClExportDownloads(data.files);
    $("clExportResult").className = "result-box";
    $("clExportResult").textContent = `导出完成：共 ${data.count} 个频道；4K高清 ${data.quality_group_counts?.["4K高清"] ?? 0} 条，高清频道 ${data.quality_group_counts?.["高清频道"] ?? 0} 条，普通频道 ${data.quality_group_counts?.["普通频道"] ?? 0} 条，未识别清晰度 ${data.unclassified_resolution_count ?? 0} 条。`;
  } catch (err) { alert(err.message); }
});
$("clSelectAll").addEventListener("change", function() {
  document.querySelectorAll("#clChannelTableBody .cl-check").forEach((cb) => { cb.checked = this.checked; });
});
$("clSelectAllBtn").addEventListener("click", () => {
  document.querySelectorAll("#clChannelTableBody .cl-check").forEach((cb) => { cb.checked = true; });
  $("clSelectAll").checked = true;
});
$("clClearSelBtn").addEventListener("click", () => {
  document.querySelectorAll("#clChannelTableBody .cl-check").forEach((cb) => { cb.checked = false; });
  $("clSelectAll").checked = false;
});
$("clDeleteSelectedBtn").addEventListener("click", async () => {
  const selectedKeys = [...document.querySelectorAll("#clChannelTableBody tr[data-key]")]
    .filter((row) => row.querySelector(".cl-check")?.checked)
    .map((row) => row.dataset.key);
  if (!selectedKeys.length) { alert("请先勾选要删除的频道"); return; }
  if (!confirm(`确定删除选中的 ${selectedKeys.length} 个频道？`)) return;
  try {
    await requestJson("/api/channels/delete", {method: "POST", body: JSON.stringify({keys: selectedKeys})});
    await loadChannelList();
  } catch (err) { alert(err.message); }
});
$("clRefreshBtn").addEventListener("click", () => loadChannelList());
$("refreshAllEpgBtn").addEventListener("click", async () => {
  const btn = $("refreshAllEpgBtn");
  btn.disabled = true; btn.textContent = "刷新中…";
  try {
    const result = await requestJson("/api/epg/refresh-all", {method: "POST", body: "{}"});
    await loadScheduleEpgSources();
    alert(`已刷新 ${result.count} 个来源，合计 ${result.total_channels} 个频道。`);
  } catch (err) { alert(err.message); }
  finally { btn.disabled = false; btn.textContent = "立即刷新全部"; }
});
$("scheduleEpgSourceList").addEventListener("click", async (event) => {
  const btn = event.target.closest(".epg-src-refresh-btn");
  if (!btn) return;
  const url = btn.dataset.epgUrl;
  btn.disabled = true; btn.textContent = "刷新中…";
  try {
    await requestJson("/api/epg/refresh", {method: "POST", body: JSON.stringify({epg_url: url})});
    await loadScheduleEpgSources();
  } catch (err) { alert(err.message); }
  finally { btn.disabled = false; btn.textContent = "刷新"; }
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
  const delBtn = event.target.closest(".source-del-btn");
  if (delBtn) {
    if (delBtn.dataset.builtin === "1") deleteBuiltin(delBtn.dataset.id);
    else deleteCustomSource(delBtn.dataset.id);
    return;
  }
  const restoreBtn = event.target.closest(".source-restore-btn");
  if (restoreBtn) restoreBuiltin(restoreBtn.dataset.id);
});
$("closeSnapshotBtn").addEventListener("click", closeSnapshot);
$("snapshotModal").addEventListener("click", (event) => {
  if (event.target.id === "snapshotModal") closeSnapshot();
});
$("closeProbeDetailBtn").addEventListener("click", closeProbeDetail);
$("probeDetailModal").addEventListener("click", (event) => {
  if (event.target.id === "probeDetailModal") closeProbeDetail();
});
$("streamsTableBody").addEventListener("click", (event) => {
  const meta = event.target.closest(".probe-meta--clickable");
  if (meta?.dataset.probeKey) openProbeDetail(meta.dataset.probeKey);
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

// ===== STB Discovery Tab =====

let stbDiscoveryPollTimer = null;

const STB_STATUS_LABELS = {
  idle: "就绪",
  capturing: "捕获中…",
  analyzing: "分析中…",
  done: "完成",
  error: "出错",
};
const STB_STATUS_CHIP = {
  idle: "neutral",
  capturing: "ok",
  analyzing: "warning",
  done: "ok",
  error: "error",
};

function renderStbDiscoveryStatus(state) {
  const status = state.status || "idle";
  const badge = $("stbDiscoveryBadge");
  badge.textContent = STB_STATUS_LABELS[status] || status;
  badge.className = `chip ${STB_STATUS_CHIP[status] || "neutral"}`;

  const box = $("stbDiscoveryStatus");
  const isCapturing = status === "capturing";
  const isAnalyzing = status === "analyzing";
  const isDone = status === "done";
  const isError = status === "error";

  $("stbDiscoveryStartBtn").disabled = isCapturing || isAnalyzing;
  $("stbDiscoveryStopBtn").disabled = !isCapturing;
  $("stbDiscoveryResetBtn").disabled = isCapturing || isAnalyzing;

  if (isCapturing) {
    const elapsed = state.started_at ? Math.round(Date.now() / 1000 - state.started_at) : 0;
    box.textContent = `正在捕获 ${escapeHtml(state.stb_ip || "")} 的流量（${elapsed} 秒）…请立即重启机顶盒。`;
    box.className = "result-box ok";
  } else if (isAnalyzing) {
    box.textContent = "正在分析 pcap 数据，提取频道信息…";
    box.className = "result-box warning";
  } else if (isDone) {
    const n = state.channel_count || 0;
    box.textContent = n > 0 ? `捕获完成，共发现 ${n} 个频道。` : "捕获完成，未发现频道。请确认机顶盒已完成开机流程。";
    box.className = n > 0 ? "result-box ok" : "result-box warning";
    renderStbDiscoveryChannels(state.channels || []);
  } else if (isError) {
    box.textContent = `捕获出错：${escapeHtml(state.error || "未知错误")}`;
    box.className = "result-box error";
  } else {
    box.textContent = "等待开始…";
    box.className = "result-box muted";
  }
}

function renderStbDiscoveryChannels(channels) {
  const section = $("stbDiscoveryResultSection");
  const tbody = $("stbDiscoveryTableBody");
  const badge = $("stbDiscoveryCountBadge");
  if (!channels.length) {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  badge.textContent = `${channels.length} 个`;
  tbody.innerHTML = channels.map((ch) => `
    <tr>
      <td>${escapeHtml(String(ch.num || ""))}</td>
      <td>${escapeHtml(ch.name || "")}</td>
      <td class="mono">${escapeHtml(ch.ip || "")}:${escapeHtml(String(ch.port || ""))}</td>
      <td>${ch.is_hd ? "✓" : ""}</td>
      <td>${ch.time_shift ? "✓" : ""}</td>
    </tr>`).join("");
}

function startStbDiscoveryPoll() {
  stopStbDiscoveryPoll();
  stbDiscoveryPollTimer = setInterval(async () => {
    try {
      const data = await requestJson("/api/stb_discovery/status");
      renderStbDiscoveryStatus(data);
      if (data.status !== "capturing" && data.status !== "analyzing") {
        stopStbDiscoveryPoll();
      }
    } catch (_) {}
  }, 2000);
}

function stopStbDiscoveryPoll() {
  if (stbDiscoveryPollTimer) {
    clearInterval(stbDiscoveryPollTimer);
    stbDiscoveryPollTimer = null;
  }
}


$("stbDiscoveryStartBtn").addEventListener("click", async () => {
  const ip = ($("stbDiscoveryIp").value || "").trim();
  const iface = ($("stbDiscoveryIface").value || "").trim() || "any";
  if (!ip) { alert("请填写机顶盒 IP 地址"); return; }
  try {
    const data = await requestJson("/api/stb_discovery/start", {method: "POST", body: JSON.stringify({stb_ip: ip, interface: iface})});
    renderStbDiscoveryStatus(data);
    startStbDiscoveryPoll();
  } catch (err) { alert(err.message); }
});

$("stbDiscoveryStopBtn").addEventListener("click", async () => {
  try {
    const data = await requestJson("/api/stb_discovery/stop", {method: "POST", body: "{}"});
    renderStbDiscoveryStatus(data);
    if (data.status === "analyzing") startStbDiscoveryPoll();
    else stopStbDiscoveryPoll();
  } catch (err) { alert(err.message); }
});

$("stbDiscoveryResetBtn").addEventListener("click", async () => {
  try {
    stopStbDiscoveryPoll();
    const data = await requestJson("/api/stb_discovery/reset", {method: "POST", body: "{}"});
    renderStbDiscoveryStatus(data);
    $("stbDiscoveryResultSection").hidden = true;
  } catch (err) { alert(err.message); }
});

$("stbDiscoveryImportBtn").addEventListener("click", async () => {
  try {
    const data = await requestJson("/api/stb_discovery/import", {method: "POST", body: "{}"});
    alert(`已导入 ${data.imported} 个频道到频道列表。`);
    showTab("channelList");
  } catch (err) { alert(err.message); }
});
