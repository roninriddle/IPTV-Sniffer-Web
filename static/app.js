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
  channelListSection: "list",
  iptvAuthSection: "summary",
  ignoredKeys: _loadIgnoredKeys(),
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

function formatDateTime(ts) {
  const value = Number(ts || 0);
  if (!value) return "—";
  try { return new Date(value * 1000).toLocaleString("zh-CN", {hour12: false}); }
  catch { return "—"; }
}

function formSettings() {
  return {
    interface: $("interface").value,
    http_host: $("httpHost").value.trim(),
    http_port: Number($("httpPort").value || 5140),
    rtp2httpd_config_path: $("diagConfigPath")?.value.trim() || "",
    path_mode: $("pathMode").value,
    duration: Number($("duration").value || 0),
    auto_probe: $("autoProbe").checked,
    auto_epg: $("autoEpg").checked,
    catchup_days: Number($("catchupDays")?.value ?? 7),
    catchup_source_template: $("catchupSourceTemplate")?.value.trim() || "",
    fcc_type: $("fccType")?.value || "",
  };
}

function showHome() {
  $("homePage").hidden = false;
  $("workbenchPage").hidden = true;
  document.querySelectorAll("[data-page='home']").forEach((item) => item.classList.add("active"));
  document.querySelectorAll("[data-nav-tab]").forEach((item) => item.classList.remove("active"));
  hideChannelListSections();
  hideIptvAuthSections();
}

function showChannelListSection(sectionName = "list") {
  const allowed = new Set(["list", "export", "epg", "snapshots"]);
  const target = allowed.has(sectionName) ? sectionName : "list";
  state.channelListSection = target;
  document.querySelectorAll("[data-cl-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.clPanel !== target;
  });
  document.querySelectorAll("[data-cl-section]").forEach((button) => {
    button.classList.toggle("active", button.dataset.clSection === target);
  });
}

function hideChannelListSections() {
  document.querySelectorAll("[data-cl-panel]").forEach((panel) => { panel.hidden = true; });
  document.querySelectorAll("[data-cl-section]").forEach((button) => button.classList.remove("active"));
}

function showIptvAuthSection(sectionName = "summary") {
  const allowed = new Set(["summary", "advanced"]);
  const target = allowed.has(sectionName) ? sectionName : "summary";
  state.iptvAuthSection = target;
  document.querySelectorAll("[data-auth-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.authPanel !== target;
  });
  document.querySelectorAll("[data-auth-section]").forEach((button) => {
    button.classList.toggle("active", button.dataset.authSection === target);
  });
}

function hideIptvAuthSections() {
  document.querySelectorAll("[data-auth-panel]").forEach((panel) => { panel.hidden = true; });
  document.querySelectorAll("[data-auth-section]").forEach((button) => button.classList.remove("active"));
}

function showTab(tabName) {
  $("homePage").hidden = true;
  $("workbenchPage").hidden = false;
  $("snifferTab").hidden = tabName !== "sniffer";
  $("stbDiscoveryTab").hidden = tabName !== "stbDiscovery";
  $("iptvAuthTab").hidden = tabName !== "iptvAuth";
  $("channelListTab").hidden = tabName !== "channelList";
  $("diagnoseTab").hidden = tabName !== "diagnose";
  if (tabName === "channelList") {
    showChannelListSection(state.channelListSection || "list");
    loadChannelList();
    loadSnapshots();
    loadEpgSettings();
  } else {
    hideChannelListSections();
  }
  if (tabName === "stbDiscovery") loadSavedOperatorCount();
  if (tabName === "iptvAuth") {
    showIptvAuthSection(state.iptvAuthSection || "summary");
    initIptvAuthTab();
  } else {
    hideIptvAuthSections();
  }
  if (tabName === "diagnose") initDiagnoseTab();
  document.querySelectorAll("[data-page='home']").forEach((item) => item.classList.remove("active"));
  document.querySelectorAll("[data-nav-tab]").forEach((item) => {
    item.classList.toggle("active", item.dataset.navTab === tabName);
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
  for (const id of ["interface", "stbDiscoveryIface", "iptvAuthIface"]) {
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

async function loadEpgSettings() {
  try {
    const [data, epg] = await Promise.all([
      requestJson("/api/settings"),
      requestJson("/api/epg/status"),
    ]);
    const useEpg = data.use_epg !== false;
    const useLogo = data.use_logo !== false;
    $("useEpg").checked = useEpg;
    $("useLogo").checked = useLogo;
    $("epgSourceName").value = data.epg_name || "";
    $("epgSourceUrl").value = data.epg_url || "";
    $("logoSourceName").value = data.logo_name || "";
    $("logoSourceUrl").value = data.logo_url || "";
    $("epgSourceRow").hidden = !useEpg;
    $("logoSourceRow").hidden = !useLogo;
    renderEpgBadge(useEpg, epg);
  } catch (err) { console.warn("loadEpgSettings:", err.message); }
}

function renderEpgBadge(useEpg, epg) {
  const badge2 = $("epgBadge2");
  if (!badge2) return;
  if (!useEpg) { badge2.className = "chip neutral"; badge2.textContent = "未启用"; }
  else if (epg?.refreshing) { badge2.className = "chip warning"; badge2.textContent = "刷新中"; }
  else if ((epg?.channels ?? 0) > 0) { badge2.className = "chip ok"; badge2.textContent = `${epg.channels} 个频道`; }
  else { badge2.className = "chip neutral"; badge2.textContent = "未加载"; }
  const box = $("epgStatusBox");
  if (!box) return;
  if (!useEpg) { box.textContent = "EPG 与台标已禁用，导出文件中不含 tvg-id / logo。"; box.className = "result-box muted"; return; }
  if (epg?.refreshing) { box.textContent = "正在刷新 EPG…"; box.className = "result-box warning"; return; }
  if ((epg?.channels ?? 0) > 0) {
    box.textContent = `已缓存 ${epg.channels} 个频道节目单，台标 ${epg.logos ?? 0} 个。${epg.last_error ? " 警告：" + epg.last_error : ""}`;
    box.className = "result-box " + (epg.last_error ? "warning" : "ok");
  } else if (epg?.last_error) {
    box.textContent = `EPG 加载失败：${epg.last_error}`;
    box.className = "result-box error";
  } else {
    box.textContent = "EPG 尚未加载，点击「刷新」获取节目单。";
    box.className = "result-box muted";
  }
}

async function loadSettings() {
  const data = await requestJson("/api/settings");
  state.settings = data;
  $("interface").value = data.interface || $("interface").value;
  if ($("iptvAuthIface") && data.interface) $("iptvAuthIface").value = data.interface;
  $("httpHost").value = data.http_host || "";
  $("httpPort").value = data.http_port ?? 5140;
  if ($("diagConfigPath")) $("diagConfigPath").value = data.rtp2httpd_config_path || "";
  $("pathMode").value = data.path_mode || "rtp";
  $("duration").value = data.duration ?? 30;
  $("autoProbe").checked = data.auto_probe !== false;
  $("autoEpg").checked = data.auto_epg !== false;
  $("catchupDays").value = data.catchup_days ?? 7;
  $("catchupSourceTemplate").value = data.catchup_source_template || "";
  if ($("fccType") && data.fcc_type !== undefined) $("fccType").value = data.fcc_type || "";
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
      stream.tvg_logo ? `<span class="pd-k">台标</span><span class="wrap-anywhere">${escapeHtml(stream.tvg_logo)}</span>` : "",
      stream.epg_source ? `<span class="pd-k">EPG来源</span><span class="wrap-anywhere">${escapeHtml(stream.epg_source)}</span>` : "",
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
  const [status, streams, metrics, tokenData, epg] = await Promise.all([
    requestJson("/api/status"),
    requestJson("/api/streams"),
    requestJson("/api/metrics"),
    requestJson("/api/stb-token"),
    requestJson("/api/epg/status"),
  ]);
  renderStatus(status);
  renderMetrics(metrics, tokenData);
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

function setLogsDrawerOpen(isOpen) {
  const drawer = $("logsDrawer");
  drawer.classList.toggle("open", isOpen);
  drawer.setAttribute("aria-hidden", isOpen ? "false" : "true");
  if (isOpen) drawer.removeAttribute("inert");
  else drawer.setAttribute("inert", "");
  drawer.querySelectorAll("button,a,input,select,textarea,[tabindex]").forEach((el) => {
    if (isOpen) {
      if (Object.prototype.hasOwnProperty.call(el.dataset, "prevTabindex")) {
        const previous = el.dataset.prevTabindex;
        if (previous) el.setAttribute("tabindex", previous);
        else el.removeAttribute("tabindex");
        delete el.dataset.prevTabindex;
      }
    } else {
      if (!Object.prototype.hasOwnProperty.call(el.dataset, "prevTabindex")) {
        el.dataset.prevTabindex = el.getAttribute("tabindex") || "";
      }
      el.setAttribute("tabindex", "-1");
    }
  });
}

function openLogs() {
  state.logsOpen = true;
  document.body.classList.add("logs-open");
  localStorage.setItem("logsOpen", "1");
  setLogsDrawerOpen(true);
  appendLogs().catch(() => {});
  if (state.logPoller) clearInterval(state.logPoller);
  state.logPoller = setInterval(() => appendLogs().catch(() => {}), 1000);
}

function closeLogs() {
  state.logsOpen = false;
  document.body.classList.remove("logs-open");
  localStorage.setItem("logsOpen", "0");
  setLogsDrawerOpen(false);
  if (state.logPoller) clearInterval(state.logPoller);
}

async function doExportDownload(filename, btn, requireHost = false) {
  if (requireHost && !$("httpHost").value.trim()) {
    alert("请先填写 rtp2httpd 主机地址，否则导出文件中的 URL 为 rtp:// 格式，无法在播放器中直接使用。");
    return;
  }
  const origText = btn.textContent;
  btn.disabled = true;
  btn.textContent = "生成中…";
  try {
    const selectedKeys = new Set([...document.querySelectorAll("#clChannelTableBody tr[data-key]")]
      .filter((row) => row.querySelector(".cl-check")?.checked)
      .map((row) => row.dataset.key));
    const channels = selectedKeys.size > 0
      ? (state.channelList || []).filter((ch) => selectedKeys.has(ch.key))
      : (state.channelList || []);
    const data = await requestJson("/api/export", {method: "POST", body: JSON.stringify({...formSettings(), channels})});
    $("clExportResult").className = "result-box";
    $("clExportResult").textContent = `共 ${data.count} 条线路，分组后主源 ${data.best_count ?? data.count} 个；4K高清 ${data.quality_group_counts?.["4K高清"] ?? 0} 条，高清频道 ${data.quality_group_counts?.["高清频道"] ?? 0} 条，普通频道 ${data.quality_group_counts?.["普通频道"] ?? 0} 条。`;
    const a = document.createElement("a");
    a.href = `/api/download/${filename}`;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } catch (err) { alert(err.message); }
  finally { btn.disabled = false; btn.textContent = origText; }
}

async function loadChannelList() {
  try {
    const data = await requestJson("/api/channels");
    state.channelList = data.channels || [];
    filterAndRenderChannelList();
  } catch (err) { console.warn("loadChannelList:", err.message); }
}

function filterAndRenderChannelList() {
  if (_groupViewActive) { filterAndRenderGroupView(); return; }
  const name = ($("clFilterName").value || "").trim().toLowerCase();
  const category = $("clFilterCategory").value;
  const quality = $("clFilterQuality").value;
  let filtered = state.channelList || [];
  if (name) filtered = filtered.filter(ch => (ch.name || "").toLowerCase().includes(name));
  if (category) filtered = filtered.filter(ch => ch.category === category);
  if (quality) {
    filtered = filtered.filter(ch => {
      const q = (ch.quality_group && ch.quality_group !== "未识别")
        ? ch.quality_group
        : ((ch.resolution_label && ch.resolution_label !== "未识别") ? ch.resolution_label : "-");
      return q === quality;
    });
  }
  renderChannelList(filtered);
}

function renderChannelList(channels) {
  const total = (state.channelList || []).length;
  $("clChannelCount").textContent = channels.length === total
    ? `${channels.length} 个`
    : `${channels.length} / ${total} 个`;
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

async function loadSavedOperatorCount() {
  try {
    const data = await requestJson("/api/operator_channels");
    $("savedOperatorCount").textContent = `${data.count} 个`;
    $("reimportOperatorBtn").disabled = !data.count;
  } catch (_) {}
}

async function loadSnapshots() {
  try {
    const data = await requestJson("/api/channels/snapshots");
    renderSnapshots(data.snapshots || []);
  } catch (_) {}
}

function renderSnapshots(snapshots) {
  const list = $("snapshotList");
  if (!snapshots.length) {
    list.innerHTML = '<div class="sources-empty-inline">暂无快照。</div>';
    return;
  }
  list.innerHTML = snapshots.map((s) => `
    <div class="epg-source-row">
      <span class="epg-source-name">${escapeHtml(s.name)}</span>
      <span class="muted small">${escapeHtml(new Date(s.created_at * 1000).toLocaleString("zh-CN"))}　${s.count} 个频道</span>
      <span></span>
      <button class="secondary xs-btn snap-restore-btn" data-snap-id="${escapeHtml(s.id)}" type="button">恢复</button>
      <button class="danger xs-btn snap-del-btn" data-snap-id="${escapeHtml(s.id)}" type="button">删除</button>
    </div>`).join("");
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
  await Promise.all([loadHealth(), loadInterfaces()]);
  await loadSettings();
  await Promise.all([refreshStatusAndStreams(), appendLogs(), checkVersion()]);
  if (localStorage.getItem("logsOpen") === "1") openLogs();
  else setLogsDrawerOpen(false);
  const initialState = (await requestJson("/api/status").catch(() => ({}))).state;
  startPolling(initialState === "running");
  loadIptvAuthSummary().catch(() => {});
}

document.querySelectorAll("[data-page='home']").forEach((item) => item.addEventListener("click", showHome));
document.querySelectorAll("[data-nav-tab]").forEach((item) => item.addEventListener("click", () => showTab(item.dataset.navTab)));
document.querySelectorAll("[data-home-tab]").forEach((item) => item.addEventListener("click", () => showTab(item.dataset.homeTab)));
document.querySelectorAll("[data-cl-section]").forEach((item) => {
  item.addEventListener("click", () => showChannelListSection(item.dataset.clSection));
});
document.querySelectorAll("[data-auth-section]").forEach((item) => {
  item.addEventListener("click", () => showIptvAuthSection(item.dataset.authSection));
});
$("filterBestPerIp").addEventListener("change", () => renderStreams(state.streams));
$("useEpg").addEventListener("change", () => { $("epgSourceRow").hidden = !$("useEpg").checked; });
$("useLogo").addEventListener("change", () => { $("logoSourceRow").hidden = !$("useLogo").checked; });
$("refreshInterfacesBtn").addEventListener("click", () => loadInterfaces().catch((err) => alert(err.message)));
$("saveSettingsBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/settings", {method: "POST", body: JSON.stringify(formSettings())});
    await refreshStatusAndStreams();
    alert("默认设置已保存");
  } catch (err) { alert(err.message); }
});
$("saveEpgSettingsBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/settings", {method: "POST", body: JSON.stringify({
      use_epg: $("useEpg").checked,
      epg_name: $("epgSourceName").value.trim(),
      epg_url: $("epgSourceUrl").value.trim(),
      use_logo: $("useLogo").checked,
      logo_name: $("logoSourceName").value.trim(),
      logo_url: $("logoSourceUrl").value.trim(),
    })});
    alert("EPG 与台标设置已保存");
  } catch (err) { alert(err.message); }
});
$("refreshEpgBtn").addEventListener("click", async () => {
  const btn = $("refreshEpgBtn");
  btn.disabled = true;
  try {
    await requestJson("/api/settings", {method: "POST", body: JSON.stringify({
      use_epg: $("useEpg").checked,
      epg_name: $("epgSourceName").value.trim(),
      epg_url: $("epgSourceUrl").value.trim(),
      use_logo: $("useLogo").checked,
      logo_name: $("logoSourceName").value.trim(),
      logo_url: $("logoSourceUrl").value.trim(),
    })});
    const epg = await requestJson("/api/epg/refresh", {method: "POST", body: "{}"});
    renderEpgStatus(epg);
    renderEpgBadge($("useEpg").checked, epg);
    alert("EPG 刷新已启动");
  } catch (err) { alert(err.message); }
  finally { btn.disabled = false; }
});
$("refreshLogoBtn").addEventListener("click", async () => {
  const btn = $("refreshLogoBtn");
  btn.disabled = true;
  try {
    const logoUrl = $("logoSourceUrl").value.trim();
    if (!logoUrl) { alert("请先填写台标 M3U 地址"); return; }
    await requestJson("/api/settings", {method: "POST", body: JSON.stringify({
      use_logo: $("useLogo").checked,
      logo_name: $("logoSourceName").value.trim(),
      logo_url: logoUrl,
    })});
    await requestJson("/api/logo/refresh", {method: "POST", body: JSON.stringify({logo_url: logoUrl})});
    alert("台标刷新已启动");
  } catch (err) { alert(err.message); }
  finally { btn.disabled = false; }
});
$("rematchEpgBtn").addEventListener("click", async function () {
  const btn = this;
  btn.disabled = true;
  btn.textContent = "匹配中…";
  try {
    const d = await requestJson("/api/epg/rematch", { method: "POST" });
    alert(`节目单重新匹配完成：共 ${d.total} 个频道，更新 ${d.updated} 个。`);
    await loadChannelList();
  } catch (err) {
    alert("重新匹配失败：" + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "重新匹配节目单";
  }
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
    state.channelListSection = "list";
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
$("clDownloadBestM3u").addEventListener("click", function() { doExportDownload("channels-best.m3u", this, true); });
$("clDownloadFnosHlsM3u").addEventListener("click", async function () {
  const btn = this;
  btn.disabled = true;
  try {
    const resp = await fetch("/api/hls/m3u");
    if (!resp.ok) {
      const j = await resp.json().catch(() => ({}));
      throw new Error(j.error || `HTTP ${resp.status}`);
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "channels-fnos-hls.m3u";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (e) {
    alert("生成 HLS M3U 失败：" + e.message);
  } finally {
    btn.disabled = false;
  }
});
$("clDownloadAllM3u").addEventListener("click", function() { doExportDownload("channels-all.m3u", this, true); });
$("clDownloadRtpBestM3u").addEventListener("click", function() { doExportDownload("channels-rtp2httpd-best.m3u", this); });
$("clDownloadRtpAllM3u").addEventListener("click", function() { doExportDownload("channels-rtp2httpd-all.m3u", this); });
$("clDownloadJson").addEventListener("click", function() { doExportDownload("channels.json", this); });
$("clDownloadTxt").addEventListener("click", function() { doExportDownload("channels.txt", this); });
$("clDownloadCsv").addEventListener("click", function() { doExportDownload("channels.csv", this); });
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
$("clFilterName").addEventListener("input", filterAndRenderChannelList);
$("clFilterCategory").addEventListener("change", filterAndRenderChannelList);
$("clFilterQuality").addEventListener("change", filterAndRenderChannelList);
$("clProbeBtn").addEventListener("click", async function() {
  const selectedKeys = new Set([...document.querySelectorAll("#clChannelTableBody tr[data-key]")]
    .filter((row) => row.querySelector(".cl-check")?.checked)
    .map((row) => row.dataset.key));
  const toProbe = selectedKeys.size > 0
    ? (state.channelList || []).filter(ch => selectedKeys.has(ch.key))
    : (state.channelList || []);
  if (!toProbe.length) { alert("请先勾选要探测的频道。"); return; }
  if (!confirm(`将对 ${toProbe.length} 个频道运行 ffprobe 探测，每个约 10 秒，请耐心等待。继续？`)) return;
  this.disabled = true; this.textContent = `探测中… (0/${toProbe.length})`;
  const btn = this;
  const settings = formSettings();
  let done = 0;
  for (const ch of toProbe) {
    try {
      await requestJson("/api/probe/batch", {method: "POST", body: JSON.stringify({channels: [ch], path_mode: settings.path_mode})});
    } catch (_) {}
    done++;
    btn.textContent = `探测中… (${done}/${toProbe.length})`;
  }
  btn.disabled = false; btn.textContent = "探测选中频道分辨率";
  await loadChannelList();
  alert(`探测完成，已更新 ${done} 个频道。`);
});
$("reimportOperatorBtn").addEventListener("click", async () => {
  const btn = $("reimportOperatorBtn");
  btn.disabled = true; btn.textContent = "导入中…";
  try {
    const data = await requestJson("/api/operator_channels");
    if (!data.channels?.length) { alert("暂无已保存的运营商频道表，请先完成 STB 开机捕获。"); return; }
    const result = await requestJson("/api/operator_channels/import", {method: "POST", body: JSON.stringify({channels: data.channels})});
    const status = $("reimportOperatorStatus");
    status.hidden = false;
    status.className = "result-box";
    status.textContent = `重新导入完成：${result.imported} 个频道，频道列表更新 ${result.channels_saved} 条。`;
    state.channelListSection = "list";
    showTab("channelList");
  } catch (err) { alert(err.message); }
  finally { btn.disabled = false; btn.textContent = "重新导入到频道列表"; }
});
$("saveSnapshotBtn").addEventListener("click", async () => {
  const name = $("snapshotNameInput").value.trim();
  try {
    const meta = await requestJson("/api/channels/snapshot", {method: "POST", body: JSON.stringify({name})});
    $("snapshotNameInput").value = "";
    await loadSnapshots();
    alert(`快照「${meta.name}」已保存，共 ${meta.count} 个频道。`);
  } catch (err) { alert(err.message); }
});
$("snapshotList").addEventListener("click", async (event) => {
  const restoreBtn = event.target.closest(".snap-restore-btn");
  if (restoreBtn) {
    if (!confirm("确定从此快照恢复？将覆盖当前频道列表。")) return;
    try {
      const result = await requestJson(`/api/channels/snapshots/${restoreBtn.dataset.snapId}/restore`, {method: "POST", body: "{}"});
      await loadChannelList();
      alert(`已从快照「${result.name}」恢复 ${result.restored} 个频道。`);
    } catch (err) { alert(err.message); }
    return;
  }
  const delBtn = event.target.closest(".snap-del-btn");
  if (delBtn) {
    if (!confirm("确定删除此快照？")) return;
    try {
      await requestJson(`/api/channels/snapshots/${delBtn.dataset.snapId}`, {method: "DELETE"});
      await loadSnapshots();
    } catch (err) { alert(err.message); }
  }
});
$("logsBtn").addEventListener("click", openLogs);
$("closeLogsBtn").addEventListener("click", closeLogs);
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
    const liveCount = state.live_channel_count || 0;
    const liveParts = [];
    if (liveCount > 0) liveParts.push(`已发现 ${liveCount} 个频道`);
    if (state.live_has_auth) liveParts.push("已捕获认证信息");
    const liveHint = liveParts.length ? `，${liveParts.join("、")}` : "";
    box.textContent = `正在捕获 ${escapeHtml(state.stb_ip || "")} 的流量（${elapsed} 秒${liveHint}）…请立即重启机顶盒。`;
    box.className = "result-box ok";
  } else if (isAnalyzing) {
    box.textContent = "正在分析 pcap 数据，提取频道信息…";
    box.className = "result-box warning";
  } else if (isDone) {
    const n = state.channel_count || 0;
    box.textContent = n > 0 ? `捕获完成，共发现 ${n} 个频道。` : "捕获完成，未发现频道。请确认机顶盒已完成开机流程。";
    box.className = n > 0 ? "result-box ok" : "result-box warning";
    renderStbDiscoveryChannels(state.channels || []);
    loadIptvAuthSummary().catch(() => {});
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
    loadIptvAuthSummary().catch(() => {});
  } catch (err) { alert(err.message); }
});

$("stbDiscoveryImportBtn").addEventListener("click", async () => {
  try {
    const data = await requestJson("/api/stb_discovery/import", {method: "POST", body: "{}"});
    alert(`已导入 ${data.imported} 个频道到频道列表。`);
    state.channelListSection = "list";
    showTab("channelList");
  } catch (err) { alert(err.message); }
});

// ── IPTV auth helper ──────────────────────────────────────────────────────

function _iptvAuthPayload() {
  return {
    interface: $("iptvAuthIface").value,
    mac: $("iptvAuthMac").value.trim(),
    hostname: $("iptvAuthHostname").value.trim(),
    vendor_class: $("iptvAuthOption60").value.trim(),
    requested_ip: $("iptvAuthRequestedIp").value.trim(),
    gateway: $("iptvAuthGateway").value.trim(),
    route_mode: $("iptvAuthRouteMode").value,
  };
}

function _setAuthField(id, value, fallback = "未捕获") {
  const el = $(id);
  if (el) el.textContent = value || fallback;
}

async function loadIptvAuthSummary() {
  try {
    const d = await requestJson("/api/stb-summary");
    _setAuthField("iptvAuthSummaryMac", d.mac);
    _setAuthField("iptvAuthSummaryHostname", d.hostname);
    _setAuthField("iptvAuthSummaryIp", d.assigned_ip);
    _setAuthField("iptvAuthSummaryGateway", d.gateway);
    _setAuthField("iptvAuthSummaryOption60", d.vendor_class);
    _setAuthField("iptvAuthSummaryToken", d.has_token ? "已捕获" : "");
    _setAuthField("iptvAuthSummaryCounts", `FCC ${d.fcc_count || 0} 条 / 频道 ${d.channel_count || 0} 个`, "0 / 0");
    if (!$("iptvAuthMac").value && d.mac) $("iptvAuthMac").value = d.mac;
    if (!$("iptvAuthHostname").value && d.hostname) $("iptvAuthHostname").value = d.hostname;
    if (!$("iptvAuthOption60").value && d.vendor_class) $("iptvAuthOption60").value = d.vendor_class;
    if (!$("iptvAuthRequestedIp").value && d.assigned_ip) $("iptvAuthRequestedIp").value = d.assigned_ip;
    if (!$("iptvAuthGateway").value && d.gateway) $("iptvAuthGateway").value = d.gateway;
    return d;
  } catch (_) { return null; }
}

function _renderIptvAuthStatus(d) {
  const badge = $("iptvAuthBadge");
  const status = $("iptvAuthStatus");
  const snap = d.snapshot || {};
  const ipv4 = (snap.ipv4 || []).map(x => `${x.local}/${x.prefixlen}`).join(", ") || "无 IPv4";
  const tools = d.tools || {};
  const caps = d.caps || {};
  const backup = d.backup || {};
  const ok = d.auth_ready && tools.ip && tools.udhcpc && caps.root && caps.net_admin_hint && caps.net_raw_hint;
  badge.className = `chip ${d.has_iptv_ip ? "ok" : ok ? "warning" : "neutral"}`;
  badge.textContent = d.has_iptv_ip ? "已获取 IPTV 地址" : ok ? "可尝试认证" : "需检查权限/参数";
  const lines = [
    `<strong>接口：${escapeHtml(d.interface || "-")}</strong>`,
    `当前 MAC：<span class="mono">${escapeHtml(snap.mac || "-")}</span>`,
    `当前 IPv4：<span class="mono">${escapeHtml(ipv4)}</span>`,
    `工具：ip=${tools.ip ? "可用" : "缺失"}，udhcpc=${tools.udhcpc ? "可用" : "缺失"}`,
    `权限：root=${caps.root ? "是" : "否"}，NET_ADMIN=${caps.net_admin_hint ? "可用" : "不可用"}，NET_RAW=${caps.net_raw_hint ? "可用" : "不可用"}`,
    `备份：${backup.has_initial ? `已有初始备份，历史 ${backup.history_count || 0} 次` : "尚未创建"}`,
  ];
  status.innerHTML = lines.map(line => `<div>${line}</div>`).join("");
  status.className = "result-box " + (d.has_iptv_ip ? "ok" : ok ? "warning" : "muted");
}

async function refreshIptvAuthStatus() {
  await loadIptvAuthSummary();
  const iface = $("iptvAuthIface").value || $("interface").value || $("stbDiscoveryIface").value;
  if (!iface) return;
  if (!$("iptvAuthIface").value) $("iptvAuthIface").value = iface;
  try {
    const d = await requestJson(`/api/iptv-auth/status?interface=${encodeURIComponent(iface)}`);
    _renderIptvAuthStatus(d);
  } catch (err) {
    $("iptvAuthBadge").className = "chip warning";
    $("iptvAuthBadge").textContent = "检测失败";
    $("iptvAuthStatus").textContent = `检测失败：${err.message}`;
    $("iptvAuthStatus").className = "result-box error";
  }
}

async function applyIptvAuth() {
  const btn = $("iptvAuthApplyBtn");
  btn.disabled = true; btn.textContent = "执行中…";
  $("iptvAuthApplyResult").textContent = "正在执行认证，请不要断开当前管理网络…";
  $("iptvAuthApplyResult").className = "result-box warning";
  try {
    const payload = {..._iptvAuthPayload(), confirm: $("iptvAuthConfirm").value.trim()};
    const d = await requestJson("/api/iptv-auth/apply", {method: "POST", body: JSON.stringify(payload)});
    const ips = (d.snapshot?.ipv4 || []).map(x => `${x.local}/${x.prefixlen}`).join(", ") || "无 IPv4";
    const mcastOk = d.snapshot?.has_multicast_route;
    const mcastLine = mcastOk ? "组播路由 224.0.0.0/4 ✓" : "⚠ 组播路由未设置，请检查路由模式";
    $("iptvAuthApplyResult").textContent =
      `认证执行完成：${d.interface} 当前 IPv4：${ips}\n${mcastLine}\n→ 请重启 rtp2httpd 以在此接口上重新加入组播组，否则无法收流。`;
    $("iptvAuthApplyResult").className = "result-box ok";
    await refreshIptvAuthStatus();
  } catch (err) {
    $("iptvAuthApplyResult").textContent = `认证执行失败：${err.message}`;
    $("iptvAuthApplyResult").className = "result-box error";
  } finally {
    btn.disabled = false; btn.textContent = "实验性一键认证";
  }
}

async function restoreIptvAuth() {
  const btn = $("iptvAuthRestoreBtn");
  btn.disabled = true; btn.textContent = "恢复中…";
  try {
    const payload = {interface: $("iptvAuthIface").value, confirm: $("iptvAuthRestoreConfirm").value.trim()};
    const d = await requestJson("/api/iptv-auth/restore", {method: "POST", body: JSON.stringify(payload)});
    const ips = (d.snapshot?.ipv4 || []).map(x => `${x.local}/${x.prefixlen}`).join(", ") || "无 IPv4";
    $("iptvAuthApplyResult").textContent = `已恢复：${d.interface} 当前 IPv4：${ips}`;
    $("iptvAuthApplyResult").className = "result-box ok";
    await refreshIptvAuthStatus();
  } catch (err) {
    $("iptvAuthApplyResult").textContent = `恢复失败：${err.message}`;
    $("iptvAuthApplyResult").className = "result-box error";
  } finally {
    btn.disabled = false; btn.textContent = "恢复到初始设置";
  }
}

function initIptvAuthTab() {
  if (!$("iptvAuthIface").value && $("interface")?.value) $("iptvAuthIface").value = $("interface").value;
  refreshIptvAuthStatus();
}

$("iptvAuthRefreshBtn").addEventListener("click", refreshIptvAuthStatus);
$("iptvAuthApplyBtn").addEventListener("click", applyIptvAuth);
$("iptvAuthRestoreBtn").addEventListener("click", restoreIptvAuth);

$("iptvAuthExportBtn").addEventListener("click", async function () {
  const iface = $("iptvAuthIface").value;
  if (!iface) { alert("请先选择 IPTV 上游接口。"); return; }
  const btn = this;
  btn.disabled = true;
  try {
    const data = await requestJson(`/api/iptv-auth/backup-export?interface=${encodeURIComponent(iface)}`);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `iptv-auth-backup-${iface}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (e) {
    alert("导出失败：" + e.message);
  } finally {
    btn.disabled = false;
  }
});

$("iptvAuthImportBtn").addEventListener("click", function () {
  $("iptvAuthImportFile").value = "";
  $("iptvAuthImportFile").click();
});

$("iptvAuthImportFile").addEventListener("change", async function () {
  const file = this.files[0];
  if (!file) return;
  const btn = $("iptvAuthImportBtn");
  btn.disabled = true;
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    await requestJson("/api/iptv-auth/backup-import", { method: "POST", body: JSON.stringify(data) });
    alert(`接口 ${data.interface} 的初始备份已导入，恢复功能现在可用。`);
  } catch (e) {
    alert("导入失败：" + e.message);
  } finally {
    btn.disabled = false;
  }
});
// ── Playback diagnostics tab ──────────────────────────────────────────────

function initDiagnoseTab() {
  // Pre-fill from the main settings form (already populated by loadSettings)
  if (!$("diagHost").value) $("diagHost").value = $("httpHost").value || "";
  if (!$("diagPort").value || $("diagPort").value === "0")
    $("diagPort").value = $("httpPort").value || "5140";
  if (!$("diagConfigPath").value && state.settings?.rtp2httpd_config_path)
    $("diagConfigPath").value = state.settings.rtp2httpd_config_path;
  // Pre-fill channel from first channel in list (if any)
  if (!$("diagChannel").value && state.channelList && state.channelList.length) {
    const first = state.channelList[0];
    if (first.host && first.port) $("diagChannel").value = `${first.host}:${first.port}`;
  }
}

async function runDiagnose() {
  const btn = $("diagRunBtn");
  btn.disabled = true; btn.textContent = "诊断中…";
  $("diagResult").textContent = "正在检测，请稍候…";
  $("diagResult").className = "result-box warning";
  $("diagChecklist").innerHTML = "";
  try {
    const body = {
      http_host: $("diagHost").value.trim(),
      http_port: parseInt($("diagPort").value) || 5140,
      channel: $("diagChannel").value.trim(),
      config_path: $("diagConfigPath").value.trim(),
    };
    const d = await requestJson("/api/diagnose", {method: "POST", body: JSON.stringify(body)});
    $("diagResult").textContent = d.verdict || "诊断完成。";
    const allOk = d.checks.every(c => c.ok !== false);
    $("diagResult").className = "result-box " + (allOk ? "ok" : "warning");
    const checkIcon = ok => ok === true ? "✓" : ok === false ? "✗" : "–";
    const checkCls  = ok => ok === true ? "diag-ok" : ok === false ? "diag-fail" : "diag-skip";
    let html = "";
    const sections = d.sections?.length
      ? d.sections
      : [{title: "诊断项", checks: d.checks || []}];
    for (const section of sections) {
      html += `<div class="diag-section"><div class="diag-section-title">${escapeHtml(section.title || "诊断项")}</div><table class="diag-table">`;
      for (const c of (section.checks || [])) {
        html += `<tr class="${checkCls(c.ok)}"><td class="diag-icon">${checkIcon(c.ok)}</td><td class="diag-item">${escapeHtml(c.item)}</td><td class="diag-detail mono small">${escapeHtml(c.detail || "")}</td></tr>`;
      }
      html += "</table></div>";
    }
    if (d.conclusions?.length) {
      html += '<div class="diag-conclusions"><strong>排查建议：</strong><ul>';
      for (const line of d.conclusions) html += `<li>${escapeHtml(line)}</li>`;
      html += "</ul></div>";
    }
    $("diagChecklist").innerHTML = html;
  } catch (err) {
    $("diagResult").textContent = `诊断请求失败：${err.message}`;
    $("diagResult").className = "result-box error";
  } finally {
    btn.disabled = false; btn.textContent = "运行诊断";
  }
}

$("diagRunBtn").addEventListener("click", runDiagnose);

// ── Channel group view ────────────────────────────────────────────────────

let _groupViewActive = false;

function _qualityBadge(qg) {
  if (qg === "4K高清") return '<span class="badge ultra">4K</span>';
  if (qg === "高清频道") return '<span class="badge hd">HD</span>';
  if (qg === "普通频道") return '<span class="badge info">SD</span>';
  return '<span class="badge neutral">—</span>';
}

function _roleBadge(role, manual = false) {
  if (role === "primary") {
    return `<span class="source-role ${manual ? "manual" : "primary"}">${manual ? "手动主源" : "自动主源"}</span>`;
  }
  return '<span class="source-role alt">备选线路</span>';
}

function _lineTech(ch) {
  const resolution = ch.width && ch.height
    ? `${ch.width}x${ch.height}`
    : (ch.resolution_label && ch.resolution_label !== "未识别" ? ch.resolution_label : "未识别");
  const codec = ch.codec_name || "编码未知";
  const fps = ch.frame_rate ? `${ch.frame_rate}fps` : "";
  const packets = Number(ch.packets || 0) > 0 ? `${ch.packets} 包` : "";
  return [codec, resolution, fps, packets].filter(Boolean);
}

function _lineFcc(ch) {
  const parts = [];
  if (ch.fcc_ip && ch.fcc_port) parts.push(`FCC ${ch.fcc_ip}:${ch.fcc_port}`);
  if (ch.fec_port) parts.push(`FEC ${ch.fec_port}`);
  return parts.length ? parts : ["无 FCC/FEC"];
}

function _lineStatus(ch) {
  const status = ch.probe_status || "not_probed";
  const label = status === "ok" ? "探测成功"
    : status === "partial" ? "部分识别"
    : status === "failed" ? "探测失败"
    : "未探测";
  const when = ch.probed_at || ch.updated_at || ch.last_seen || ch.epg_matched_at;
  const detail = ch.probe_message && ch.probe_message !== "未识别" ? ch.probe_message : "";
  return {label, detail, when: formatDateTime(when)};
}

function renderChannelGroups(groups) {
  const tbody = $("clGroupTableBody");
  if (!groups.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">暂无频道组，请先导入频道。</td></tr>';
    return;
  }
  const rows = [];
  for (const g of groups) {
    const p = g.primary;
    const hasAlts = g.alternates.length > 0;
    const pStatus = _lineStatus(p);
    rows.push(`<tr data-group="${escapeHtml(g.group_key)}">
      <td><button class="expand-btn" data-group="${escapeHtml(g.group_key)}" aria-expanded="false">${hasAlts ? "▶" : ""}</button></td>
      <td>
        <div class="line-stack">
          <span class="line-title">${escapeHtml(p.name || "")}</span>
          <span class="line-sub mono">${escapeHtml(p.key || "")}</span>
          <span class="line-sub">${g.count} 条线路，${g.alternates.length} 条备选</span>
        </div>
      </td>
      <td>${_roleBadge("primary", Boolean(p.is_primary))}</td>
      <td>${_qualityBadge(p.quality_group)}</td>
      <td>
        <div class="line-meta">${_lineTech(p).map(x => `<span>${escapeHtml(x)}</span>`).join("")}</div>
        <div class="line-sub">${_lineFcc(p).map(escapeHtml).join(" · ")}</div>
      </td>
      <td class="line-status">
        <strong>${escapeHtml(pStatus.label)}</strong>
        ${pStatus.detail ? `<div class="line-sub">${escapeHtml(pStatus.detail)}</div>` : ""}
        <div class="line-sub">${escapeHtml(pStatus.when)}</div>
      </td>
      <td class="mono small">${escapeHtml(p.tvg_id || p.tvg_name || "—")}</td>
      <td><button class="secondary xs-btn diag-ch-btn" data-key="${escapeHtml(p.key||"")}">诊断</button></td>
    </tr>`);
    for (const alt of g.alternates) {
      const altStatus = _lineStatus(alt);
      rows.push(`<tr class="alt-row hidden" data-parent="${escapeHtml(g.group_key)}">
        <td></td>
        <td>
          <div class="line-stack">
            <span class="line-title">${escapeHtml(alt.name || "")}</span>
            <span class="line-sub mono">${escapeHtml(alt.key || "")}</span>
          </div>
        </td>
        <td>${_roleBadge("alt")}</td>
        <td>${_qualityBadge(alt.quality_group)}</td>
        <td>
          <div class="line-meta">${_lineTech(alt).map(x => `<span>${escapeHtml(x)}</span>`).join("")}</div>
          <div class="line-sub">${_lineFcc(alt).map(escapeHtml).join(" · ")}</div>
        </td>
        <td class="line-status">
          <strong>${escapeHtml(altStatus.label)}</strong>
          ${altStatus.detail ? `<div class="line-sub">${escapeHtml(altStatus.detail)}</div>` : ""}
          <div class="line-sub">${escapeHtml(altStatus.when)}</div>
        </td>
        <td class="mono small">${escapeHtml(alt.tvg_id || alt.tvg_name || "—")}</td>
        <td><button class="secondary xs-btn set-primary-btn"
            data-group="${escapeHtml(g.group_key)}"
            data-key="${escapeHtml(alt.key||"")}">设为主源</button></td>
      </tr>`);
    }
  }
  tbody.innerHTML = rows.join("");

  // expand/collapse
  tbody.querySelectorAll(".expand-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const gk = btn.dataset.group;
      const expanded = btn.getAttribute("aria-expanded") === "true";
      btn.setAttribute("aria-expanded", String(!expanded));
      btn.textContent = expanded ? "▶" : "▼";
      tbody.querySelectorAll(`tr[data-parent="${CSS.escape(gk)}"]`).forEach(tr => {
        tr.classList.toggle("hidden", expanded);
      });
    });
  });

  // set-primary
  tbody.querySelectorAll(".set-primary-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      try {
        await requestJson("/api/channels/set-primary", {
          method: "POST",
          body: JSON.stringify({group_key: btn.dataset.group, channel_key: btn.dataset.key}),
        });
        await loadChannelGroups();
      } catch (err) { alert(err.message); }
    });
  });

  tbody.querySelectorAll(".diag-ch-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $("diagChannel").value = btn.dataset.key || "";
      showTab("diagnose");
    });
  });
}

async function loadChannelGroups() {
  try {
    const d = await requestJson("/api/channels/groups");
    state.channelGroups = d.groups || [];
    filterAndRenderGroupView();
  } catch (err) {
    $("clGroupTableBody").innerHTML = `<tr><td colspan="8" class="empty">加载失败：${escapeHtml(err.message)}</td></tr>`;
  }
}

function filterAndRenderGroupView() {
  const groups = state.channelGroups || [];
  const name = ($("clFilterName").value || "").trim().toLowerCase();
  const category = $("clFilterCategory").value;
  const quality = $("clFilterQuality").value;
  let filtered = groups;
  if (name) filtered = filtered.filter(g =>
    (g.primary.name || "").toLowerCase().includes(name) ||
    g.alternates.some(a => (a.name || "").toLowerCase().includes(name))
  );
  if (category) filtered = filtered.filter(g => g.primary.category === category);
  if (quality) filtered = filtered.filter(g => g.primary.quality_group === quality);
  renderChannelGroups(filtered);
  const total = (state.channelList || []).length;
  $("clChannelCount").textContent = filtered.length === groups.length
    ? `${groups.length} 组 / ${total} 条`
    : `${filtered.length} / ${groups.length} 组 · ${total} 条`;
}

let _groupViewInit = false;
$("clGroupViewBtn").addEventListener("click", () => {
  _groupViewActive = !_groupViewActive;
  $("clGroupViewBtn").textContent = _groupViewActive ? "平铺视图" : "分组视图";
  $("clFlatView").hidden = _groupViewActive;
  $("clGroupView").hidden = !_groupViewActive;
  if (_groupViewActive) loadChannelGroups();
  else {
    // restore flat count
    const total = (state.channelList || []).length;
    $("clChannelCount").textContent = `${total} 个`;
  }
});
