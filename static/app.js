const $ = (id) => document.getElementById(id);

function formatTimestampUtc8(date) {
  const utc8 = new Date(date.getTime() + 8 * 3600 * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${utc8.getUTCFullYear()}-${pad(utc8.getUTCMonth() + 1)}-${pad(utc8.getUTCDate())}_${pad(utc8.getUTCHours())}-${pad(utc8.getUTCMinutes())}-${pad(utc8.getUTCSeconds())}`;
}

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
  logPoller: null,
  channelList: [],
  selectedChannelKeys: new Set(),
  channelCategory: "",
  channelSubscription: "",
  channelCapabilities: new Set(),
  channelListSection: "subscription",
  subscription: null,
  ignoredKeys: _loadIgnoredKeys(),
};

async function requestJsonRaw(url, options = {}) {
  const response = await fetch(url, {
    headers: {"Content-Type": "application/json"},
    ...options,
  });
  let payload;
  try { payload = JSON.parse(await response.text()); }
  catch { throw new Error(`服务器返回了非 JSON 响应（HTTP ${response.status}），请稍后重试`); }
  if (!response.ok || payload.success === false) {
    throw new Error(payload.error || "请求失败");
  }
  return payload.data;
}

const queueSettingsRequest = createSettingsQueue(options => requestJsonRaw("/api/settings", options));
function requestJson(url, options = {}) {
  if (url === "/api/settings" && (options.method || "GET").toUpperCase() === "POST") {
    return queueSettingsRequest(options);
  }
  return requestJsonRaw(url, options);
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
  const selectedInterface = $("stbDiscoveryIface")?.value || $("iptvAuthIface")?.value || state.settings?.interface || "";
  return {
    interface: selectedInterface,
    media_interface: $("mediaInterface")?.value.trim() || "",
    http_host: $("httpHost").value.trim(),
    http_port: Number($("httpPort").value || 5140),
    rtp2httpd_path_prefix: $("rtp2httpdPathPrefix")?.value.trim() || "",
    rtp2httpd_config_path: $("diagConfigPath")?.value.trim() || "",
    path_mode: $("pathMode").value,
    duration: 0,
    auto_probe: false,
    auto_epg: true,
    catchup_enabled: $("catchupEnabled")?.checked ?? false,
    catchup_days: Number($("catchupDays")?.value ?? 7),
    catchup_auto_refresh_enabled: $("catchupAutoRefreshEnabled")?.checked ?? false,
    catchup_auto_refresh_hours: Number($("catchupAutoRefreshHours")?.value ?? 12),
    timeshift_host: $("timeshiftHost")?.value.trim() || "",
    catchup_source_mode: document.querySelector('input[name="catchupSourceMode"]:checked')?.value || "aptv",
    catchup_source_template: $("catchupSourceTemplate")?.value.trim() || "",
    fcc_type: $("fccType")?.value || "",
    pre_export_health_check: $("preExportHealthCheck")?.checked ?? false,
  };
}

function showHome() {
  $("homePage").hidden = false;
  $("workbenchPage").hidden = true;
  document.querySelectorAll("[data-page='home']").forEach((item) => item.classList.add("active"));
  document.querySelectorAll("[data-nav-tab]").forEach((item) => item.classList.remove("active"));
  hideChannelListSections();
}

function showChannelListSection(sectionName = "subscription") {
  const allowed = new Set(["subscription", "list", "export", "epg", "snapshots"]);
  const target = allowed.has(sectionName) ? sectionName : "subscription";
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


function showTab(tabName) {
  $("homePage").hidden = true;
  $("workbenchPage").hidden = false;
  $("stbDiscoveryTab").hidden = tabName !== "stbDiscovery";
  $("iptvAuthTab").hidden = tabName !== "iptvAuth";
  $("channelListTab").hidden = tabName !== "channelList";
  $("diagnoseTab").hidden = tabName !== "diagnose";
  if (tabName === "channelList") {
    showChannelListSection(state.channelListSection || "subscription");
    loadSubscription();
    loadChannelList();
    loadSnapshots();
    loadEpgSettings();
  } else {
    hideChannelListSections();
  }
  if (tabName === "stbDiscovery") {
    loadSavedOperatorCount();
    loadStbDiscoveryState().catch(() => {});
  }
  if (tabName === "iptvAuth") {
    initIptvAuthTab();
  }
  if (tabName === "diagnose") initDiagnoseTab();
  document.querySelectorAll("[data-page='home']").forEach((item) => item.classList.remove("active"));
  document.querySelectorAll("[data-nav-tab]").forEach((item) => {
    item.classList.toggle("active", item.dataset.navTab === tabName);
  });
}

function setRuntimeBadge(health) {
  const badge = $("runtimeBadge");
  if (!badge) return;
  const captureOk = Boolean(health.runtime?.ok);
  if (captureOk) {
    badge.className = "chip ok";
    badge.textContent = "抓包环境正常";
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
    if (!badge) return;
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
  if (!$("snifferInsight")) return;
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
  if (!badge) return;
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
  for (const id of ["stbDiscoveryIface", "iptvAuthIface"]) {
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

function renderCatchupAutoRefreshStatus(data) {
  const box = $("catchupAutoRefreshStatus");
  if (!box) return;
  const parts = [];
  parts.push(data.enabled ? `已开启，每 ${data.interval_hours} 小时刷新` : "未开启自动刷新");
  if (data.running) parts.push("正在刷新");
  if (data.last_success_at) parts.push(`上次成功：${formatDateTime(data.last_success_at)}`);
  else if (data.last_run_at) parts.push(`上次尝试：${formatDateTime(data.last_run_at)}`);
  if (data.next_run_at) parts.push(`下次刷新：${formatDateTime(data.next_run_at)}`);
  if (data.token_expires_at) parts.push(`门户 Cookie 过期：${formatDateTime(data.token_expires_at)}`);
  else if (data.token_expiry_note) parts.push(`有效期：${data.token_expiry_note}`);
  if (data.last_result) parts.push(`最近更新：${data.last_result.updated ?? 0}/${data.last_result.total ?? 0}，模式：${data.last_result.profile || "auto"}`);
  if (data.last_error) parts.push(`最近错误：${data.last_error}`);
  box.textContent = parts.join("；");
  box.className = "result-box " + (data.last_error ? "warning" : (data.enabled ? "ok" : "muted"));
}

async function loadCatchupAutoRefreshStatus() {
  try {
    const data = await requestJson("/api/catchup/refresh/status");
    renderCatchupAutoRefreshStatus(data);
  } catch (err) {
    const box = $("catchupAutoRefreshStatus");
    if (box) {
      box.textContent = "自动刷新状态加载失败：" + err.message;
      box.className = "result-box warning";
    }
  }
}

async function loadSettings() {
  const data = await requestJson("/api/settings");
  state.settings = data;
  if ($("iptvAuthIface") && data.interface) $("iptvAuthIface").value = data.interface;
  $("httpHost").value = data.http_host || "";
  $("mediaInterface").value = data.media_interface || "";
  $("httpPort").value = data.http_port ?? 5140;
  if ($("rtp2httpdPathPrefix")) $("rtp2httpdPathPrefix").value = data.rtp2httpd_path_prefix || "";
  if ($("diagConfigPath")) $("diagConfigPath").value = data.rtp2httpd_config_path || "";
  $("pathMode").value = data.path_mode || "rtp";
  if ($("catchupEnabled")) {
    $("catchupEnabled").checked = !!data.catchup_enabled;
    const block = $("catchupSettingsBlock");
    if (block) block.style.display = data.catchup_enabled ? "" : "none";
  }
  $("catchupDays").value = data.catchup_days ?? 7;
  if ($("catchupAutoRefreshEnabled")) $("catchupAutoRefreshEnabled").checked = !!data.catchup_auto_refresh_enabled;
  if ($("catchupAutoRefreshHours")) $("catchupAutoRefreshHours").value = data.catchup_auto_refresh_hours ?? 12;
  if ($("timeshiftHost")) $("timeshiftHost").value = data.timeshift_host || "";
  const _csmEl = document.querySelector(`input[name="catchupSourceMode"][value="${data.catchup_source_mode || 'aptv'}"]`);
  if (_csmEl) _csmEl.checked = true;
  if ($("catchupSourceTemplate")) $("catchupSourceTemplate").value = data.catchup_source_template || "";
  updateCatchupSourceUI();
  if ($("iptvPassword")) $("iptvPassword").value = data.iptv_password || "";
  if ($("epgUserId")) $("epgUserId").value = data.epg_user_id || "";
  if ($("epgStbId")) $("epgStbId").value = data.epg_stb_id || "";
  if ($("epgDes3Key")) {
    $("epgDes3Key").value = data.epg_des3_key || "";
    $("epgDes3Key").placeholder = "8 / 16 / 24 位密钥";
  }
  if ($("epgDes3KeyStatus")) {
    $("epgDes3KeyStatus").textContent = data.epg_des3_key_configured
      ? "已本机保存并明文显示；导出时可单独选择是否包含在备份中。"
      : "明文显示在本机管理页面；导出时可单独选择是否包含在备份中。";
  }
  if ($("epgAuthHost")) $("epgAuthHost").value = data.epg_auth_host || "";
  if ($("epgAuthProfile")) $("epgAuthProfile").value = data.epg_auth_profile || "auto";
  if ($("epgCryptoMode")) $("epgCryptoMode").value = data.epg_crypto_mode || "auto";
  if ($("epgDesPadding")) $("epgDesPadding").value = data.epg_des_padding || "pkcs5";
  if ($("epgStbType")) $("epgStbType").value = data.epg_stb_type || "";
  if ($("epgStbVersion")) $("epgStbVersion").value = data.epg_stb_version || "";
  if ($("epgSoftwareVersion")) $("epgSoftwareVersion").value = data.epg_software_version || "";
  if ($("epgUserAgent")) $("epgUserAgent").value = data.epg_user_agent || "";
  if ($("epgAccessUserName")) $("epgAccessUserName").value = data.epg_access_user_name || "";
  if ($("refreshBacktvBtn")) $("refreshBacktvBtn").style.display = data.catchup_enabled ? "" : "none";
  loadCatchupAutoRefreshStatus().catch(() => {});
  if ($("fccType") && data.fcc_type !== undefined) $("fccType").value = data.fcc_type || "";
  if ($("preExportHealthCheck")) $("preExportHealthCheck").checked = !!data.pre_export_health_check;
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
  $("logsBtn").classList.add("active");
  setLogsDrawerOpen(true);
  appendLogs().catch(() => {});
  if (state.logPoller) clearInterval(state.logPoller);
  state.logPoller = setInterval(() => appendLogs().catch(() => {}), 1000);
}

function closeLogs() {
  state.logsOpen = false;
  document.body.classList.remove("logs-open");
  localStorage.setItem("logsOpen", "0");
  $("logsBtn").classList.remove("active");
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
    const channels = selectedChannelRows();
    const data = await requestJson("/api/export", {method: "POST", body: JSON.stringify({...formSettings(), channels})});
    $("clExportResult").className = "result-box";
    const health = data.health_check;
    const healthText = health?.checked
      ? `导出前检查 ${health.groups_checked} 个多来源组、${health.checked} 条源：可用 ${health.ok}，失败 ${health.failed}，超时 ${health.timeout}${health.limit_reached ? "，已达检查上限" : ""}。`
      : (health?.message || "");
    $("clExportResult").textContent = `共 ${data.count} 条来源，分组后主源 ${data.best_count ?? data.count} 个。${healthText ? `\n${healthText}` : ""}`;
    const a = document.createElement("a");
    a.href = data.bundle ? `/api/download/bundles/${data.bundle}/${filename}` : `/api/download/${filename}`;
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
    renderChannelCategoryTabs(data.categories || []);
    renderChannelFilterTabs();
    syncSelectedChannelKeys();
    filterAndRenderChannelList();
  } catch (err) { console.warn("loadChannelList:", err.message); }
}

function subscriptionUrl(path) {
  return `${window.location.origin}${path}`;
}

function renderSubscription(data) {
  state.subscription = data;
  const urls = data.urls || {};
  const ids = {
    best: "subscriptionBestUrl",
    all: "subscriptionAllUrl",
    hls: "subscriptionHlsUrl",
    rtp2httpd: "subscriptionRtp2httpdUrl",
    rtp2httpd_all: "subscriptionRtp2httpdAllUrl",
    epg: "subscriptionEpgUrl",
  };
  Object.entries(ids).forEach(([kind, id]) => { if ($(id)) $(id).value = subscriptionUrl(urls[kind] || ""); });
  const total = Number(data.total_candidates || 0);
  const badge = $("subscriptionCandidateBadge");
  badge.className = total ? "chip ok" : "chip warning";
  badge.textContent = `${total} 个已订阅`;
  $("subscriptionSummary").textContent = total
    ? `当前订阅包含 ${total} 个频道，其中回看 ${data.catchup_candidates || 0} 个、FCC ${data.fcc_candidates || 0} 个。主订阅使用固定频道 ID，不暴露运营商 RTSP 或组播源地址。`
    : "当前没有已订阅频道。请到「频道库」勾选频道后加入订阅。";
  if ($("rtp2httpdSubscriptionSummary")) {
    $("rtp2httpdSubscriptionSummary").textContent = `rtp2httpd 最佳频道订阅包含 ${data.rtp2httpd_best_count || 0} 个去重后的逻辑频道；全部线路订阅包含 ${data.rtp2httpd_all_count || 0} 条实际线路。两者均直接输出原始 RTP 地址并保留 FCC/FEC。`;
  }
}

async function loadSubscription() {
  try {
    renderSubscription(await requestJson("/api/subscription"));
  } catch (err) {
    if ($("subscriptionSummary")) {
      $("subscriptionSummary").textContent = `订阅中心加载失败：${err.message}`;
      $("subscriptionSummary").className = "result-box error";
    }
  }
}

async function updateSubscriptionCandidates(action, stableIds = []) {
  try {
    const data = await requestJson("/api/subscription/candidates", {
      method: "POST", body: JSON.stringify({action, stable_ids: stableIds}),
    });
    state.selectedChannelKeys.clear();
    renderSubscription(data);
    await loadChannelList();
  } catch (err) { alert(err.message); }
}

function renderChannelCategoryTabs(categories) {
  const tabs = $("clCategoryTabs");
  if (!tabs) return;
  const known = categories.length ? categories : ["央视频道", "卫视频道", "其它频道"];
  const current = state.channelCategory;
  const counts = new Map();
  (state.channelList || []).forEach((channel) => {
    const category = channel.category || "其它频道";
    counts.set(category, (counts.get(category) || 0) + 1);
  });
  const items = [["", "全部频道", (state.channelList || []).length], ...known.map((category) => [category, category, counts.get(category) || 0])];
  tabs.innerHTML = items.map(([value, label, count]) => `
    <button class="category-tab ${value === current ? "active" : ""}" type="button" data-category="${escapeHtml(value)}">
      ${escapeHtml(label)} <span>${count}</span>
    </button>`).join("");
  tabs.querySelectorAll(".category-tab").forEach((button) => {
    button.addEventListener("click", () => {
      state.channelCategory = button.dataset.category || "";
      renderChannelCategoryTabs(known);
      filterAndRenderChannelList();
    });
  });
}

function channelQuality(channel) {
  const text = [channel.name, channel.resolution_label, channel.quality_group].join(" ").toUpperCase();
  const width = Number(channel.width || 0);
  const height = Number(channel.height || 0);
  if (width >= 3840 || height >= 2160 || /(?:4K|UHD|2160)/.test(text)) return "4K";
  if (channel.is_hd || width >= 1280 || height >= 720 || /(?:HD|720|1080)/.test(text)) return "HD";
  return "";
}

function hasCapability(channel, capability) {
  if (capability === "fcc") return Boolean(channel.has_fcc);
  if (capability === "catchup") return Boolean(channel.has_catchup);
  if (capability === "timeshift") return Boolean(channel.has_timeshift);
  return channelQuality(channel) === "4K";
}

function renderChannelFilterTabs() {
  const subscriptionTabs = $("clSubscriptionTabs");
  const capabilityTabs = $("clCapabilityTabs");
  const channels = state.channelList || [];
  const subscribed = channels.filter((channel) => channel.subscription_candidate).length;
  const subscriptionItems = [["", "全部", channels.length], ["subscribed", "已订阅", subscribed], ["unsubscribed", "未订阅", channels.length - subscribed]];
  subscriptionTabs.innerHTML = subscriptionItems.map(([value, label, count]) => `
    <button class="category-tab ${value === state.channelSubscription ? "active" : ""}" type="button" data-subscription="${value}">${label} <span>${count}</span></button>`).join("");
  subscriptionTabs.querySelectorAll(".category-tab").forEach((button) => button.addEventListener("click", () => {
    state.channelSubscription = button.dataset.subscription || "";
    renderChannelFilterTabs();
    filterAndRenderChannelList();
  }));
  const capabilityItems = [["fcc", "FCC"], ["catchup", "回看"], ["timeshift", "时移"], ["4k", "4K"]];
  capabilityTabs.innerHTML = capabilityItems.map(([key, label]) => {
    const count = channels.filter((channel) => hasCapability(channel, key)).length;
    return `<button class="category-tab ${state.channelCapabilities.has(key) ? "active" : ""}" type="button" data-capability="${key}">${label} <span>${count}</span></button>`;
  }).join("");
  capabilityTabs.querySelectorAll(".category-tab").forEach((button) => button.addEventListener("click", () => {
    const key = button.dataset.capability || "";
    if (state.channelCapabilities.has(key)) state.channelCapabilities.delete(key);
    else state.channelCapabilities.add(key);
    renderChannelFilterTabs();
    filterAndRenderChannelList();
  }));
}

function syncSelectedChannelKeys() {
  const available = new Set((state.channelList || []).map((ch) => ch.key).filter(Boolean));
  state.selectedChannelKeys = new Set([...state.selectedChannelKeys].filter((key) => available.has(key)));
}

function setChannelSelected(key, selected) {
  if (!key) return;
  if (selected) state.selectedChannelKeys.add(key);
  else state.selectedChannelKeys.delete(key);
}

function visibleFlatKeys() {
  return [...document.querySelectorAll("#clChannelTableBody tr[data-key]")]
    .map((row) => row.dataset.key)
    .filter(Boolean);
}

function selectedChannelRows() {
  const selected = state.selectedChannelKeys || new Set();
  if (selected.size > 0) return (state.channelList || []).filter((ch) => selected.has(ch.key));
  const candidates = new Set(state.subscription?.candidate_ids || []);
  return candidates.size
    ? (state.channelList || []).filter((ch) => candidates.has(ch.stable_id))
    : [];
}

function refreshChannelSelectionControls() {
  document.querySelectorAll(".cl-check").forEach((cb) => {
    cb.checked = state.selectedChannelKeys.has(cb.dataset.key || cb.closest("tr")?.dataset.key);
  });
  const flatKeys = visibleFlatKeys();
  const flatAll = flatKeys.length > 0 && flatKeys.every((key) => state.selectedChannelKeys.has(key));
  const flatSelect = $("clSelectAll");
  if (flatSelect) flatSelect.checked = flatAll;
  const selectedCount = state.selectedChannelKeys.size;
  const selectionBar = $("clSelectionBar");
  if (selectionBar) selectionBar.hidden = selectedCount === 0;
  const selectionCount = $("clSelectionCount");
  if (selectionCount) selectionCount.textContent = `已选择 ${selectedCount} 个频道`;
}

function filterAndRenderChannelList() {
  const name = ($("clFilterName").value || "").trim().toLowerCase();
  const category = state.channelCategory;
  const subscription = state.channelSubscription;
  let filtered = state.channelList || [];
  if (name) filtered = filtered.filter(ch => [ch.name, ch.key, ch.tvg_id, ch.tvg_name].some((value) => String(value || "").toLowerCase().includes(name)));
  if (category) filtered = filtered.filter(ch => ch.category === category);
  if (subscription) filtered = filtered.filter(ch => subscription === "subscribed" ? ch.subscription_candidate : !ch.subscription_candidate);
  if (state.channelCapabilities.size) filtered = filtered.filter((channel) => [...state.channelCapabilities].every((capability) => hasCapability(channel, capability)));
  renderChannelList(_sortChannels(filtered));
}

function renderChannelList(channels) {
  const total = (state.channelList || []).length;
  const subscribed = (state.channelList || []).filter((channel) => channel.subscription_candidate).length;
  $("clChannelCount").textContent = channels.length === total
    ? `共 ${total} 个 · 已订阅 ${subscribed}`
    : `显示 ${channels.length} / ${total} · 已订阅 ${subscribed}`;
  const tbody = $("clChannelTableBody");
  if (!channels.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">频道列表为空，请先完成运营商频道发现并导入。</td></tr>';
    refreshChannelSelectionControls();
    return;
  }
  tbody.innerHTML = channels.map((ch) => {
    const addr = ch.key || `${ch.host || ""}:${ch.port ?? ""}`;
    const epg = ch.tvg_id || "-";
    const checked = state.selectedChannelKeys.has(ch.key) ? "checked" : "";
    const quality = channelQuality(ch);
    const provenance = ch.provenance?.sources || [];
    const sourceLabel = ch.source_state === "historical" ? "历史来源（不用于当前订阅）" : "当前来源";
    const sourceDetails = provenance.map(source => `${source.pcap || ""} · ${source.parser || ""} v${source.parser_version || ""}`).join("\n");
    const capabilities = [
      ch.has_fcc ? '<span class="capability-badge">FCC</span>' : "",
      ch.has_catchup ? '<span class="capability-badge">回看</span>' : "",
      ch.has_timeshift ? '<span class="capability-badge">时移</span>' : "",
    ].filter(Boolean).join("") || '<span class="muted small">—</span>';
    return `
    <tr data-key="${escapeHtml(ch.key || "")}">
      <td><input type="checkbox" class="cl-check" data-key="${escapeHtml(ch.key || "")}" ${checked}></td>
      <td><div class="channel-title">${escapeHtml(ch.name || "")}</div><div class="line-sub">${escapeHtml(ch.category || "其它频道")} · <span title="${escapeHtml(sourceDetails)}">${sourceLabel}</span></div></td>
      <td class="mono small">${escapeHtml(addr)}</td>
      <td class="mono small">${escapeHtml(epg)}</td>
      <td>${quality ? `<span class="quality-badge ${quality === "4K" ? "uhd" : ""}">${quality}</span>` : '<span class="muted small">—</span>'}</td>
      <td><div class="capability-list">${capabilities}</div></td>
      <td>${ch.subscription_candidate ? '<span class="badge hd">已订阅</span>' : '<span class="muted small">未订阅</span>'}</td>
      <td><button class="secondary xs-btn channel-edit-btn" type="button" data-key="${escapeHtml(ch.key || "")}">编辑</button></td>
    </tr>`;
  }).join("");
  tbody.querySelectorAll(".cl-check").forEach((cb) => {
    cb.addEventListener("change", () => {
      setChannelSelected(cb.dataset.key, cb.checked);
      refreshChannelSelectionControls();
    });
  });
  tbody.querySelectorAll(".channel-edit-btn").forEach((btn) => {
    btn.addEventListener("click", () => openChannelEdit(btn.dataset.key || ""));
  });
  refreshChannelSelectionControls();
}

let activeChannelEditKey = "";

function openChannelEdit(key) {
  const channel = (state.channelList || []).find((item) => item.key === key);
  if (!channel) return;
  activeChannelEditKey = key;
  $("channelEditName").value = channel.name || "";
  $("channelEditCategory").value = channel.category || "";
  $("channelEditEpgId").value = channel.tvg_id || "";
  $("channelEditHd").checked = !!channel.is_hd;
  $("channelEditAddress").textContent = key;
  $("channelEditRestoreOriginal").disabled = !channel.original_metadata;
  $("channelEditRestoreEdited").disabled = !channel.edited_metadata;
  $("channelEditDialog").showModal();
}

function closeChannelEdit() {
  activeChannelEditKey = "";
  $("channelEditDialog").close();
}

async function restoreChannelMetadata(source) {
  if (!activeChannelEditKey) return;
  try {
    const data = await requestJson(`/api/channels/${encodeURIComponent(activeChannelEditKey)}/metadata/restore`, {
      method: "POST", body: JSON.stringify({source}),
    });
    const channel = data.channel;
    $("channelEditName").value = channel.name || "";
    $("channelEditCategory").value = channel.category || "";
    $("channelEditEpgId").value = channel.tvg_id || "";
    $("channelEditHd").checked = !!channel.is_hd;
    await loadChannelList();
  } catch (err) { alert(err.message); }
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
  await Promise.all([appendLogs(), checkVersion()]);
  if (localStorage.getItem("logsOpen") === "1") openLogs();
  else setLogsDrawerOpen(false);
  loadIptvAuthSummary().catch(() => {});
  loadSavedOperatorCount().catch(() => {});
}

document.querySelectorAll("[data-page='home']").forEach((item) => item.addEventListener("click", showHome));
document.querySelectorAll("[data-nav-tab]").forEach((item) => item.addEventListener("click", () => showTab(item.dataset.navTab)));
document.querySelectorAll("[data-home-tab]").forEach((item) => item.addEventListener("click", () => showTab(item.dataset.homeTab)));
document.querySelectorAll("[data-cl-section]").forEach((item) => {
  item.addEventListener("click", () => showChannelListSection(item.dataset.clSection));
});
$("useEpg").addEventListener("change", () => { $("epgSourceRow").hidden = !$("useEpg").checked; });
$("useLogo").addEventListener("change", () => { $("logoSourceRow").hidden = !$("useLogo").checked; });
$("refreshInterfacesBtn").addEventListener("click", () => loadInterfaces().catch((err) => alert(err.message)));
function collectExportSettings() {
  return {
    media_interface: $("mediaInterface")?.value.trim() || "",
    http_host: $("httpHost").value.trim(),
    http_port: Number($("httpPort").value || 5140),
    rtp2httpd_path_prefix: $("rtp2httpdPathPrefix")?.value.trim() || "",
    path_mode: $("pathMode").value,
    fcc_type: $("fccType")?.value || "",
    catchup_enabled: $("catchupEnabled")?.checked ?? false,
    catchup_days: Number($("catchupDays")?.value ?? 7),
    catchup_auto_refresh_enabled: $("catchupAutoRefreshEnabled")?.checked ?? false,
    catchup_auto_refresh_hours: Number($("catchupAutoRefreshHours")?.value ?? 12),
    timeshift_host: $("timeshiftHost")?.value.trim() || "",
    catchup_source_mode: document.querySelector('input[name="catchupSourceMode"]:checked')?.value || "aptv",
    catchup_source_template: $("catchupSourceTemplate")?.value.trim() || "",
    iptv_password: $("iptvPassword")?.value || "",
    epg_user_id: $("epgUserId")?.value.trim() || "",
    epg_stb_id: $("epgStbId")?.value.trim() || "",
    epg_des3_key: $("epgDes3Key")?.value.trim() || "",
    epg_auth_host: $("epgAuthHost")?.value.trim() || "",
    epg_auth_profile: $("epgAuthProfile")?.value || "auto",
    epg_crypto_mode: $("epgCryptoMode")?.value || "auto",
    epg_des_padding: $("epgDesPadding")?.value || "pkcs5",
    epg_stb_type: $("epgStbType")?.value.trim() || "",
    epg_stb_version: $("epgStbVersion")?.value.trim() || "",
    epg_software_version: $("epgSoftwareVersion")?.value.trim() || "",
    epg_user_agent: $("epgUserAgent")?.value.trim() || "",
    epg_access_user_name: $("epgAccessUserName")?.value.trim() || "",
    pre_export_health_check: $("preExportHealthCheck")?.checked ?? false,
  };
}

let exportSettingsSaveTimer = null;
let exportSettingsEditSerial = 0;
function savingStatus(text, failed = false) {
  const status = $("exportSettingsSaveStatus");
  if (status) { status.textContent = text; status.className = failed ? "danger-text small" : "muted small"; }
  const retry = $("exportSettingsRetry");
  if (retry) retry.hidden = !failed;
}
async function autoSaveExportSettings() {
  clearTimeout(exportSettingsSaveTimer);
  const serial = ++exportSettingsEditSerial;
  savingStatus("正在保存…");
  try {
    await requestJson("/api/settings", {method: "POST", body: JSON.stringify(collectExportSettings())});
    if (serial === exportSettingsEditSerial) savingStatus("已保存");
    await loadCatchupAutoRefreshStatus();
  } catch (err) {
    if (serial === exportSettingsEditSerial) savingStatus(`保存失败：${err.message}`, true);
  }
}
function scheduleExportSettingsSave() {
  ++exportSettingsEditSerial;
  savingStatus("有未保存的修改…");
  clearTimeout(exportSettingsSaveTimer);
  exportSettingsSaveTimer = setTimeout(autoSaveExportSettings, 600);
}
$("exportSettingsRetry")?.addEventListener("click", autoSaveExportSettings);

const EXPORT_SETTINGS_TEXT_INPUT_IDS = [
  "mediaInterface", "httpHost", "httpPort", "rtp2httpdPathPrefix", "catchupDays", "timeshiftHost", "catchupSourceTemplate",
  "iptvPassword", "epgUserId", "epgStbId", "epgDes3Key", "epgAuthHost",
  "epgStbType", "epgStbVersion", "epgSoftwareVersion", "epgUserAgent", "epgAccessUserName", "catchupAutoRefreshHours",
];
const EXPORT_SETTINGS_IMMEDIATE_IDS = [
  "pathMode", "fccType", "catchupEnabled", "catchupAutoRefreshEnabled",
  "epgAuthProfile", "epgCryptoMode", "epgDesPadding", "preExportHealthCheck",
];
EXPORT_SETTINGS_TEXT_INPUT_IDS.forEach((id) => $(id)?.addEventListener("input", scheduleExportSettingsSave));
EXPORT_SETTINGS_IMMEDIATE_IDS.forEach((id) => $(id)?.addEventListener("change", autoSaveExportSettings));
document.querySelectorAll('input[name="catchupSourceMode"]').forEach((el) => el.addEventListener("change", autoSaveExportSettings));
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
$("channelEditCancel").addEventListener("click", closeChannelEdit);
$("channelEditRestoreOriginal").addEventListener("click", () => restoreChannelMetadata("original"));
$("channelEditRestoreEdited").addEventListener("click", () => restoreChannelMetadata("edited"));
$("channelEditForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!activeChannelEditKey) return;
  const btn = $("channelEditSave");
  btn.disabled = true;
  try {
    await requestJson(`/api/channels/${encodeURIComponent(activeChannelEditKey)}/metadata`, {
      method: "POST",
      body: JSON.stringify({
        name: $("channelEditName").value.trim(),
        category: $("channelEditCategory").value.trim(),
        tvg_id: $("channelEditEpgId").value.trim(),
        is_hd: $("channelEditHd").checked,
      }),
    });
    await loadChannelList();
    closeChannelEdit();
  } catch (err) { alert(err.message); }
  finally { btn.disabled = false; }
});
$("clSelectAll").addEventListener("change", function() {
  visibleFlatKeys().forEach((key) => setChannelSelected(key, this.checked));
  refreshChannelSelectionControls();
});
$("clClearSelBtn").addEventListener("click", () => {
  state.selectedChannelKeys.clear();
  refreshChannelSelectionControls();
});
$("clAddSelectedCandidateBtn").addEventListener("click", async () => {
  const ids = [...new Set((state.channelList || [])
    .filter((channel) => state.selectedChannelKeys.has(channel.key))
    .map((channel) => channel.stable_id)
    .filter(Boolean))];
  if (!ids.length) { alert("请先在频道库中勾选至少一个频道"); return; }
  await updateSubscriptionCandidates("add", ids);
});
$("clRemoveSelectedCandidateBtn").addEventListener("click", async () => {
  const ids = [...new Set((state.channelList || [])
    .filter((channel) => state.selectedChannelKeys.has(channel.key))
    .map((channel) => channel.stable_id)
    .filter(Boolean))];
  if (!ids.length) { alert("请先在频道库中勾选至少一个频道"); return; }
  await updateSubscriptionCandidates("remove", ids);
});
$("clDeleteSelectedBtn").addEventListener("click", async () => {
  const selectedKeys = [...state.selectedChannelKeys];
  if (!selectedKeys.length) { alert("请先勾选要删除的频道"); return; }
  if (!confirm(`清理选中的 ${selectedKeys.length} 条频道库记录？此操作仅清理本地记录和编辑，不删除运营商映射，也不会移出订阅。如需停止订阅，请使用“移出订阅”。`)) return;
  try {
    await requestJson("/api/channels/delete", {method: "POST", body: JSON.stringify({keys: selectedKeys})});
    state.selectedChannelKeys.clear();
    await loadChannelList();
  } catch (err) { alert(err.message); }
});
$("clRefreshBtn").addEventListener("click", () => loadChannelList());
$("clFilterName").addEventListener("input", filterAndRenderChannelList);
document.querySelectorAll(".copy-subscription-btn").forEach((btn) => btn.addEventListener("click", async () => {
  const key = btn.dataset.subscriptionUrl;
  const inputIds = {
    best: "subscriptionBestUrl",
    all: "subscriptionAllUrl",
    hls: "subscriptionHlsUrl",
    rtp2httpd: "subscriptionRtp2httpdUrl",
    rtp2httpd_all: "subscriptionRtp2httpdAllUrl",
    epg: "subscriptionEpgUrl",
  };
  const value = $(inputIds[key] || "subscriptionBestUrl").value;
  const labels = {
    best: "主订阅", all: "兼容别名", hls: "HLS 兼容订阅",
    rtp2httpd: "rtp2httpd 最佳频道订阅", rtp2httpd_all: "rtp2httpd 全部线路订阅", epg: "XMLTV EPG",
  };
  const status = $("subscriptionCopyStatus");
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = value;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      if (!document.execCommand("copy")) throw new Error("浏览器拒绝访问剪贴板");
      textarea.remove();
    }
    status.hidden = false;
    status.className = "result-box ok compact-result";
    status.textContent = `已复制${labels[key] || "订阅地址"}。`;
  } catch (_) {
    status.hidden = false;
    status.className = "result-box error compact-result";
    status.textContent = "复制失败：浏览器未授权剪贴板访问，请检查网页权限后重试。";
  }
}));
$("subscriptionPreviewBtn").addEventListener("click", () => window.open($("subscriptionBestUrl").value, "_blank", "noopener"));
$("subscriptionDownloadBtn").addEventListener("click", () => {
  const a = document.createElement("a");
  a.href = $("subscriptionBestUrl").value;
  a.download = "iptv-subscription.m3u";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
});
$("subscriptionResetBestBtn").addEventListener("click", async () => {
  if (!confirm("将订阅恢复为当前频道库的最佳频道。是否继续？")) return;
  await updateSubscriptionCandidates("reset_to_best");
});
$("backupExportBtn").addEventListener("click", () => showBackupExportDialog());
$("backupImportBtn").addEventListener("click", () => {
  $("backupImportFile").value = "";
  $("backupImportFile").click();
});

const BACKUP_MODULES = [
  ["credentials", "密码与密钥（敏感）"],
  ["pcap_archives", "历史原始 PCAP 与协议清单（敏感）"],
  ["settings", "应用与导出设置"],
  ["channels", "频道库"],
  ["operator_channels", "运营商频道表"],
  ["discovered_channels", "已发现频道"],
  ["fcc", "FCC 记录"],
  ["stb_token", "机顶盒认证信息"],
  ["iptv_auth_backups", "IPTV 认证备份"],
  ["channel_snapshots", "频道列表快照"],
  ["subscription_candidates", "订阅频道清单"],
];
let pendingGlobalBackup = null;
let pendingAuthBackupConflicts = [];

function updateBackupExportConfirmState() {
  const moduleInputs = [...document.querySelectorAll("#backupExportModules input")];
  const selected = moduleInputs.filter((input) => input.checked).map((input) => input.value);
  $("backupExportConfirm").disabled = !selected.length;
  const includeCredentials = Boolean(document.querySelector('#backupExportModules input[value="credentials"]:checked'));
  const includePcaps = Boolean(document.querySelector('#backupExportModules input[value="pcap_archives"]:checked'));
  if ($("backupExportAll")) {
    $("backupExportAll").checked = moduleInputs.length > 0 && selected.length === moduleInputs.length;
    $("backupExportAll").indeterminate = selected.length > 0 && selected.length < moduleInputs.length;
  }
  const summary = $("backupExportSummary");
  if (summary) {
    summary.className = `result-box ${includeCredentials || includePcaps ? "warning" : "muted"}`;
    if (includeCredentials && includePcaps) {
      summary.textContent = "已选择明文凭据和历史 PCAP：将生成可用于换容器/换机器的迁移 ZIP，请仅保存在可信私有位置。";
    } else if (includePcaps) {
      summary.textContent = "已选择历史 PCAP：将生成带 SHA-256 校验的 ZIP；PCAP 可能包含认证流量。";
    } else if (includeCredentials) {
      summary.textContent = "已选择“密码与密钥”：IPTV 密码和 DES/DES3 密钥将以明文写入 JSON，请仅保存到可信位置。";
    } else {
      summary.textContent = "当前导出轻量 JSON，不包含密码、密钥和原始 PCAP。";
    }
  }
}

function showBackupExportDialog() {
  $("backupExportModules").innerHTML = BACKUP_MODULES.map(([key, label]) => `
    <label class="backup-module-row">
      <input type="checkbox" value="${escapeHtml(key)}" ${key === "credentials" || key === "pcap_archives" ? "" : "checked"}>
      <span>${escapeHtml(label)}</span>
      ${key === "credentials" ? "<small>以明文写入</small>" : key === "pcap_archives" ? "<small>与协议清单一起写入 ZIP</small>" : ""}
    </label>`).join("");
  $("backupExportModules").querySelectorAll("input").forEach((input) => input.addEventListener("change", updateBackupExportConfirmState));
  updateBackupExportConfirmState();
  $("backupExportDialog").showModal();
}

$("backupExportAll")?.addEventListener("change", function () {
  document.querySelectorAll("#backupExportModules input").forEach((input) => { input.checked = this.checked; });
  updateBackupExportConfirmState();
});

function backupModuleDetail(key, value) {
  if (key === "operator_channels") {
    return `${Object.keys(value || {}).length} 条，可能含短期回看 Token`;
  }
  if (key === "channels" || key === "discovered_channels" || key === "fcc") {
    return `${Object.keys(value || {}).length} 条`;
  }
  if (key === "iptv_auth_backups") {
    return `${Object.keys(value?.interfaces || {}).length} 个接口`;
  }
  if (key === "credentials") return "含 IPTV 密码和 DES/DES3 密钥";
  if (key === "channel_snapshots") return `${Object.keys(value || {}).length} 个快照`;
  return "已包含";
}

function updateBackupRestoreConfirmState() {
  $("backupRestoreConfirm").disabled = !document.querySelector("#backupRestoreModules input:checked");
}

function confirmTwice(firstMessage, secondMessage) {
  return confirm(firstMessage) && confirm(secondMessage);
}

function showBackupRestoreDialog(backup, filename, authConflicts = []) {
  const modules = BACKUP_MODULES.filter(([key]) => backup[key] !== null && backup[key] !== undefined);
  if (!modules.length) throw new Error("不是可恢复的全局备份文件");
  pendingGlobalBackup = backup;
  pendingAuthBackupConflicts = authConflicts;
  const version = backup._app_version ? `，来自 v${backup._app_version}` : "";
  const schemaVersion = Number(backup.schema_version || backup._version || 1);
  const legacyNote = backup._legacy_credentials_migrated ? " 已从旧版 settings 中识别出密码或密钥，并作为独立敏感模块等待选择。" : "";
  $("backupRestoreSummary").textContent = `文件：${filename}${version}，备份格式 v${schemaVersion}。请选择要恢复的模块；未勾选的内容不会被修改。完整恢复回看需要同时选择“应用与导出设置”和“运营商频道表”，恢复后再执行回看刷新。${legacyNote}`;
  $("backupRestoreModules").innerHTML = modules.map(([key, label]) => {
    const hasAuthConflict = key === "iptv_auth_backups" && authConflicts.length > 0;
    const isSensitive = key === "credentials";
    const detail = hasAuthConflict
      ? `与本机 ${authConflicts.join("、")} 快照冲突，需明确勾选才覆盖`
      : backupModuleDetail(key, backup[key]);
    return `
    <label class="backup-module-row">
      <input type="checkbox" value="${escapeHtml(key)}" ${hasAuthConflict || isSensitive ? "" : "checked"}>
      <span>${escapeHtml(label)}</span>
      <small>${escapeHtml(detail)}</small>
    </label>`;
  }).join("");
  $("backupRestoreModules").querySelectorAll("input").forEach((input) => input.addEventListener("change", updateBackupRestoreConfirmState));
  updateBackupRestoreConfirmState();
  $("backupRestoreDialog").showModal();
}

$("backupImportFile").addEventListener("change", async function () {
  const file = this.files[0];
  if (!file) return;
  const box = $("backupStatus");
  if (file.name.toLowerCase().endsWith(".zip")) {
    if (!confirmTwice(
      "迁移 ZIP 可能覆盖当前设置、频道、认证资料并恢复原始 PCAP。是否继续？",
      "再次确认：即将校验并恢复完整迁移包，是否执行？",
    )) return;
    box.hidden = false; box.className = "result-box warning";
    box.textContent = "正在校验并恢复备份 ZIP……";
    const formData = new FormData();
    formData.append("confirmed", "true"); formData.append("file", file, file.name);
    try {
      const resp = await fetch("/api/backup/disaster-import", {method: "POST", body: formData});
      const body = await resp.json().catch(() => ({}));
      if (!resp.ok || !body.success) throw new Error(body.error || `恢复失败：${resp.status}`);
      const result = body.data || {};
      box.className = "result-box ok";
      box.textContent = `备份恢复完成：模块 ${(result.restored || []).length} 项，PCAP ${result.pcap_archives_restored || 0} 个，协议清单 ${result.protocol_manifests_restored || 0} 个，已存在且一致的文件 ${result.archive_files_skipped || 0} 个。\n换机器时请再恢复 IPTV 网卡/DHCP/路由，然后执行一次回看刷新。页面将在 3 秒后刷新。`;
      setTimeout(() => location.reload(), 3000);
    } catch (err) {
      box.className = "result-box error";
      box.textContent = `备份 ZIP 恢复失败：${err.message}`;
    }
    return;
  }
  try {
    const text = await file.text();
    if (file.name.toLowerCase().endsWith(".json")) {
      try {
        const inspection = await requestJson("/api/backup/inspect", {
          method: "POST", body: JSON.stringify({backup: JSON.parse(text)}),
        });
        showBackupRestoreDialog(inspection.backup, file.name, inspection.auth_conflicts || []);
        return;
      } catch (_) {
        // channels.json is also JSON, but is a channel export rather than a global backup.
      }
    }
    box.hidden = false; box.className = "result-box warning";
    box.textContent = "正在导入频道列表…";
    const result = await requestJson("/api/channels/import-export", {
      method: "POST", body: JSON.stringify({content: text, filename: file.name}),
    });
    box.className = "result-box ok";
    box.textContent = `频道列表导入完成：新增或更新 ${result.saved} 条${result.skipped ? `，跳过 ${result.skipped} 条不支持的记录` : ""}。`;
    state.channelListSection = "list";
    showTab("channelList");
  } catch (err) {
    box.hidden = false; box.className = "result-box error";
    box.textContent = `导入失败：${err.message}`;
  }
});
$("backupRestoreCancel").addEventListener("click", () => $("backupRestoreDialog").close());
$("backupRestoreSelectAll").addEventListener("click", () => {
  document.querySelectorAll("#backupRestoreModules input").forEach((input) => { input.checked = true; });
  updateBackupRestoreConfirmState();
});
$("backupRestoreClearAll").addEventListener("click", () => {
  document.querySelectorAll("#backupRestoreModules input").forEach((input) => { input.checked = false; });
  updateBackupRestoreConfirmState();
});
$("backupRestoreForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const modules = [...document.querySelectorAll("#backupRestoreModules input:checked")].map((input) => input.value);
  if (!pendingGlobalBackup || !modules.length) return;
  const btn = $("backupRestoreConfirm");
  const box = $("backupStatus");
  btn.disabled = true;
  box.hidden = false; box.className = "result-box warning";
  box.textContent = "正在恢复所选模块…";
  try {
    const result = await requestJson("/api/backup/import", {
      method: "POST", body: JSON.stringify({
        backup: pendingGlobalBackup,
        modules,
        overwrite_auth_backups: modules.includes("iptv_auth_backups") && pendingAuthBackupConflicts.length > 0,
      }),
    });
    $("backupRestoreDialog").close();
    pendingGlobalBackup = null;
    pendingAuthBackupConflicts = [];
    box.className = "result-box ok";
    const warnings = (result.warnings || []).length ? `\n注意：${result.warnings.join(" ")}` : "";
    box.textContent = `恢复完成：${result.restored.join("、") || "无"}${result.skipped.length ? `；备份中没有：${result.skipped.join("、")}` : ""}。${warnings}\n页面将在 2 秒后刷新。`;
    loadSavedOperatorCount().catch(() => {});
    loadIptvAuthSummary().catch(() => {});
    setTimeout(() => location.reload(), 2000);
  } catch (err) {
    box.className = "result-box error";
    box.textContent = `恢复失败：${err.message}`;
  } finally { btn.disabled = false; }
});
$("backupExportCancel").addEventListener("click", () => $("backupExportDialog").close());
$("backupExportSelectAll").addEventListener("click", () => {
  document.querySelectorAll("#backupExportModules input").forEach((input) => { input.checked = true; });
  updateBackupExportConfirmState();
});
$("backupExportClearAll").addEventListener("click", () => {
  document.querySelectorAll("#backupExportModules input").forEach((input) => { input.checked = false; });
  updateBackupExportConfirmState();
});
$("backupExportForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const modules = [...document.querySelectorAll("#backupExportModules input:checked")].map((input) => input.value);
  if (!modules.length) return;
  const btn = $("backupExportConfirm");
  const box = $("backupStatus");
  btn.disabled = true;
  try {
    if (modules.includes("pcap_archives")) {
      if (!confirmTwice(
        "所选备份包含原始 PCAP，可能包含 IPTV 认证流量；如同时选中密码与密钥，将以明文保存。是否继续？",
        "再次确认：即将生成并下载完整迁移备份，请只在可信本地环境保存。是否执行？",
      )) return;
      let frame = document.querySelector('iframe[name="migrationBackupDownloadFrame"]');
      if (!frame) {
        frame = document.createElement("iframe");
        frame.name = "migrationBackupDownloadFrame";
        frame.hidden = true;
        document.body.appendChild(frame);
      }
      const form = document.createElement("form");
      form.method = "POST"; form.action = "/api/backup/disaster-export";
      form.target = frame.name; form.hidden = true;
      const addField = (name, value) => {
        const input = document.createElement("input");
        input.type = "hidden"; input.name = name; input.value = value; form.appendChild(input);
      };
      addField("confirmed", "true");
      modules.forEach((module) => addField("modules", module));
      document.body.appendChild(form); form.submit(); form.remove();
      $("backupExportDialog").close();
      box.hidden = false; box.className = "result-box warning";
      box.textContent = "正在生成迁移备份 ZIP……历史 PCAP 较大时需要等待，下载会自动开始。";
      return;
    }
    const resp = await fetch("/api/backup/export", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({modules})});
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error || `导出失败：${resp.status}`);
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `iptv-sniffer-backup-${formatTimestampUtc8(new Date())}.json`;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
    $("backupExportDialog").close();
    box.hidden = false; box.className = "result-box ok";
    box.textContent = `备份已导出：${modules.map((key) => BACKUP_MODULES.find((item) => item[0] === key)?.[1] || key).join("、")}。`;
  } catch (err) {
    box.hidden = false; box.className = "result-box error";
    box.textContent = `导出失败：${err.message}`;
  } finally { btn.disabled = false; }
});
$("backupClearAllBtn")?.addEventListener("click", async () => {
  if (!confirmTwice(
    "将清除全部本地配置：设置、频道列表、运营商频道表、发现的频道、FCC 记录、回看 Token、IPTV 认证备份、频道快照。此操作不可恢复，建议先点「导出到本地」备份。是否继续？",
    "再次确认：所有本地配置即将永久清除，是否执行？",
  )) return;
  const btn = $("backupClearAllBtn");
  btn.disabled = true; btn.textContent = "清除中…";
  const box = $("backupStatus");
  box.hidden = false; box.className = "result-box warning";
  box.textContent = "正在清除本地配置…";
  try {
    const result = await requestJson("/api/backup/clear-all", {method: "POST", body: JSON.stringify({confirmed: true})});
    box.className = "result-box ok";
    box.textContent = `已清除：${result.cleared.join("、") || "无"}。页面将在 2 秒后刷新。`;
    setTimeout(() => location.reload(), 2000);
  } catch (err) {
    box.className = "result-box error";
    box.textContent = `清除失败：${err.message}`;
  } finally { btn.disabled = false; btn.textContent = "清除所有配置"; }
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

  // DHCP chaddr already gives us the STB MAC, so prefill it instead of making
  // the user read it off the device label or a DHCP lease.  Only fills an empty
  // field so it never overrides a value the user typed deliberately.
  const macInput = $("stbDiscoveryMac");
  if (macInput && !macInput.value.trim() && state.detected_mac) {
    macInput.value = state.detected_mac;
  }

  const box = $("stbDiscoveryStatus");
  const isCapturing = status === "capturing";
  const isAnalyzing = status === "analyzing";
  const isDone = status === "done";
  const isError = status === "error";

  $("stbDiscoveryStartBtn").disabled = isCapturing || isAnalyzing;
  $("stbDiscoveryStopBtn").disabled = !isCapturing;
  $("stbDiscoveryResetBtn").disabled = isCapturing || isAnalyzing;
  const latestArchive = state.latest_archive || null;
  const exportAvailable = !!state.pcap_available || !!latestArchive;
  if ($("stbDiscoveryPcapBtn")) {
    $("stbDiscoveryPcapBtn").disabled = !exportAvailable;
    $("stbDiscoveryPcapBtn").title = state.pcap_available
      ? `导出当前抓包文件（${Math.round((state.pcap_size || 0) / 1024)} KB）`
      : latestArchive
        ? `导出已归档 PCAP（${Math.round((latestArchive.size || 0) / 1024)} KB）`
        : "完成一次 STB 开机捕获后可导出";
  }
  if ($("stbDiscoveryPcapBackupBtn")) {
    $("stbDiscoveryPcapBackupBtn").disabled = !latestArchive;
    $("stbDiscoveryPcapBackupBtn").title = latestArchive
      ? "下载当前选中的 PCAP、对应协议清单和说明"
      : "完成一次 STB 开机捕获后可导出持久化备份";
  }

  if (isCapturing) {
    const elapsed = state.started_at ? Math.round(Date.now() / 1000 - state.started_at) : 0;
    const liveCount = state.live_channel_count || 0;
    const liveParts = [];
    if (liveCount > 0) liveParts.push(`已发现 ${liveCount} 个频道`);
    if (state.live_has_auth) liveParts.push("已捕获认证信息");
    if (state.live_last_error) liveParts.push(`实时分析提示：${state.live_last_error}`);
    const liveHint = liveParts.length ? `\n${liveParts.join("\n")}。` : "";
    const target = state.stb_mac
      ? `${escapeHtml(state.stb_mac)}`
      : escapeHtml(state.stb_ip || "");
    box.textContent = `正在捕获 ${target} 的流量（${elapsed} 秒）…请立即重启机顶盒。\n一般约 30 秒可捕获到认证信息，约 60 秒可捕获到频道信息。${liveHint}`;
    box.className = "result-box ok";
  } else if (isAnalyzing) {
    box.textContent = "正在分析 pcap 数据，提取频道信息…";
    box.className = "result-box warning";
  } else if (isDone) {
    const n = state.channel_count || 0;
    const diag = state.diagnostics || {};
    let text = n > 0
      ? `捕获完成，共发现 ${n} 个频道。`
      : "捕获完成，未发现频道。请确认机顶盒已完成开机流程。";
    // A wrong MAC still yields a valid filter, so tcpdump records nothing and
    // the user is left with a bare "0 channels".  Say what actually happened.
    if (diag.mac_not_seen && n === 0) {
      text = `抓包中未出现 MAC ${diag.mac_requested || ""}，其他设备或 DHCP 的数据仍可能被捕获。\n`
        + "请确认填写的是机顶盒的 MAC（不是光猫的），且抓包点能看到机顶盒与 IPTV 网关之间的流量。";
      box.className = "result-box error";
    } else {
      box.className = n > 0 ? "result-box ok" : "result-box warning";
    }
    box.textContent = text;
    renderStbDiscoveryChannels(state.channels || []);
    loadIptvAuthSummary().catch(() => {});
  } else if (isError) {
    box.textContent = `捕获出错：${escapeHtml(state.error || "未知错误")}`;
    box.className = "result-box error";
  } else {
    box.textContent = "等待开始…";
    box.className = "result-box muted";
  }
  renderStbDiscoveryDiagnostics(state);
}

function formatBytes(size) {
  const bytes = Math.max(0, Number(size || 0));
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} B`;
}

// 诊断结论按「数据在哪一环断掉」排序，从采集到解析逐级收窄，
// 这样用户看到的是可执行的下一步，而不是一堆计数。
function stbDiagnosticsConclusions(diag) {
  const notes = [];
  const pcapSize = Number(diag.pcap_size || 0);
  const streams = Number(diag.stream_count || 0);
  const matched = Number(diag.matched_response_streams || 0);
  const channels = Number(diag.channels || 0);
  if (pcapSize <= 0 || diag.packet_count === 0) {
    notes.push("没有捕获到完整数据包：检查抓包点和过滤条件，并查看 tcpdump 错误；"
      + "容器抓包还需检查网络模式及 NET_RAW/NET_ADMIN 权限。");
  } else if (diag.identity_source === "unresolved") {
    notes.push("已抓到数据，但尚未确认机顶盒 IP：请在捕获期间重启机顶盒以获得 DHCP ACK，或填写当前 IP 后重试。");
  } else if (diag.mac_not_seen && channels <= 0) {
    notes.push(`可统计的数据包中没有出现 MAC ${diag.mac_requested || ""}：确认填的是机顶盒的 MAC，`
      + "且抓包点能看到机顶盒与 IPTV 网关之间的流量。");
  } else if (streams <= 0) {
    notes.push("抓到了数据但没有重组出任何 TCP 流：过滤条件可能过窄，"
      + "或该网口上看不到机顶盒与 IPTV 网关之间的单播流量。");
  } else if (matched <= 0) {
    notes.push(`重组出 ${streams} 条 TCP 流，但没有一条响应流指向机顶盒 IP：`
      + "确认机顶盒 IP 填写正确（DHCP 可能分配了别的地址），并在捕获期间重启机顶盒。");
  } else if (channels <= 0) {
    notes.push(`匹配到 ${matched} 条响应流，但没有解析出频道表：`
      + "可能未覆盖开机频道表下发、响应不含频道表或协议尚不支持；请检查协议清单后再决定是否延长抓包。");
  } else {
    notes.push(`解析完成（未验证实际播放）：抓到 ${formatBytes(pcapSize)} 数据、${streams} 条 TCP 流、`
      + `${matched} 条响应流，解析出 ${channels} 个频道。`);
  }
  return notes;
}

function renderStbDiscoveryDiagnostics(state) {
  const details = $("stbDiscoveryDiagnostics");
  const tbody = $("stbDiscoveryDiagBody");
  const conclusion = $("stbDiscoveryDiagConclusion");
  if (!details || !tbody || !conclusion) return;
  const diag = state.diagnostics || {};
  const rows = [];
  const addRow = (label, value, mono) => rows.push(
    `<tr><td class="diag-item">${escapeHtml(label)}</td>`
    + `<td class="${mono ? "stb-diag-value" : ""}">${escapeHtml(String(value))}</td></tr>`
  );
  if (diag.pcap_size !== undefined) addRow("抓包大小", formatBytes(diag.pcap_size));
  if (diag.packet_count !== undefined) addRow("完整数据包", Number(diag.packet_count).toLocaleString("zh-CN"), true);
  if (diag.effective_stb_ip) addRow("实际解析 IP", diag.effective_stb_ip, true);
  if (diag.identity_source) addRow("IP 依据", ({dhcp_ack: "目标 MAC 对应的 DHCP ACK", provided_ip: "用户填写的 IP", unresolved: "尚未确认"})[diag.identity_source] || "未知");
  if (diag.mac_requested) addRow("过滤 MAC", diag.mac_requested, true);
  if (diag.mac_supported === false) addRow("MAC 统计", "当前链路不支持，无法判断是否出现");
  else if (diag.mac_seen_count !== undefined) addRow("该 MAC 出现次数", Number(diag.mac_seen_count).toLocaleString("zh-CN"), true);
  if (diag.stream_count !== undefined) addRow("TCP 流", Number(diag.stream_count).toLocaleString("zh-CN"), true);
  if (diag.matched_response_streams !== undefined) addRow("匹配响应流", Number(diag.matched_response_streams).toLocaleString("zh-CN"), true);
  if (diag.channels !== undefined) addRow("解析出频道", Number(diag.channels).toLocaleString("zh-CN"), true);
  if (!rows.length) {
    details.hidden = true;
    return;
  }
  details.hidden = false;
  tbody.innerHTML = rows.join("");
  conclusion.innerHTML = "<ul>"
    + stbDiagnosticsConclusions(diag).map((note) => `<li>${escapeHtml(note)}</li>`).join("")
    + "</ul>";
}

function renderStbDiscoveryArchives(archives) {
  const select = $("stbDiscoveryArchiveSelect");
  if (!select) return;
  const previous = select.value;
  select.innerHTML = "";
  const summary = $("stbDiscoveryArchiveSummary");
  if (summary) {
    summary.textContent = `${archives?.length || 0} 份`;
    summary.className = `chip ${archives?.length ? "ok" : "neutral"}`;
  }
  if (!archives?.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "暂无历史抓包";
    select.appendChild(option);
  }
  for (const archive of archives || []) {
    const option = document.createElement("option");
    option.value = archive.name || "";
    const size = Math.max(0, Number(archive.size || 0));
    const sizeLabel = size >= 1024 * 1024
      ? `${(size / 1024 / 1024).toFixed(1)} MB`
      : `${Math.max(1, Math.round(size / 1024))} KB`;
    const capturedAt = formatDateTime(archive.created_at);
    option.textContent = `${capturedAt} · ${sizeLabel}${archive.has_manifest ? " · 含协议清单" : ""}`;
    option.title = archive.name || "";
    select.appendChild(option);
  }
  select.disabled = !archives?.length;
  if ($("stbDiscoveryArchiveDeleteBtn")) {
    $("stbDiscoveryArchiveDeleteBtn").disabled = !archives?.length;
  }
  if (previous && [...select.options].some((option) => option.value === previous)) {
    select.value = previous;
  }
}

async function loadStbDiscoveryState() {
  const [status, archiveResult] = await Promise.all([
    requestJson("/api/stb_discovery/status"),
    requestJson("/api/stb_discovery/archives"),
  ]);
  renderStbDiscoveryStatus(status);
  renderStbDiscoveryArchives(archiveResult.archives || []);
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
      <td>${escapeHtml(ch.category || ch.operator_group || "")}</td>
      <td class="mono">${escapeHtml(ch.ip || "")}:${escapeHtml(String(ch.port || ""))}</td>
      <td>${channelQuality(ch) || "—"}</td>
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
        loadStbDiscoveryState().catch(() => {});
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
  const mac = ($("stbDiscoveryMac").value || "").trim();
  const iface = ($("stbDiscoveryIface").value || "").trim() || "any";
  if (!ip && !mac) { alert("请填写机顶盒 IP 或 MAC 地址"); return; }
  try {
    const data = await requestJson("/api/stb_discovery/start", {method: "POST", body: JSON.stringify({stb_ip: ip, stb_mac: mac, interface: iface})});
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
    if (data.status !== "capturing" && data.status !== "analyzing") loadStbDiscoveryState().catch(() => {});
  } catch (err) { alert(err.message); }
});

$("stbDiscoveryResetBtn").addEventListener("click", async () => {
  try {
    stopStbDiscoveryPoll();
    const data = await requestJson("/api/stb_discovery/reset", {method: "POST", body: "{}"});
    renderStbDiscoveryStatus(data);
    loadStbDiscoveryState().catch(() => {});
    $("stbDiscoveryResultSection").hidden = true;
    loadIptvAuthSummary().catch(() => {});
  } catch (err) { alert(err.message); }
});

$("stbDiscoveryImportBtn").addEventListener("click", async () => {
  try {
    const data = await requestJson("/api/stb_discovery/import", {method: "POST", body: "{}"});
    let msg = `已导入 ${data.imported} 个频道到频道列表。`;
    if (data.timeshift_host_detected) {
      msg += `\n已自动检测到回看服务器：${data.timeshift_host_detected}`;
      if ($("timeshiftHost")) $("timeshiftHost").value = data.timeshift_host_detected;
      updateCatchupSourceUI();
    }
    if (data.epg_creds_detected) {
      const c = data.epg_creds_detected;
      if (c.epg_user_id && $("epgUserId")) $("epgUserId").value = c.epg_user_id;
      if (c.epg_stb_id && $("epgStbId")) $("epgStbId").value = c.epg_stb_id;
      if (c.epg_auth_host && $("epgAuthHost")) $("epgAuthHost").value = c.epg_auth_host;
      if (c.epg_stb_type && $("epgStbType")) $("epgStbType").value = c.epg_stb_type;
      if (c.epg_stb_version && $("epgStbVersion")) $("epgStbVersion").value = c.epg_stb_version;
      if (c.epg_user_agent && $("epgUserAgent")) $("epgUserAgent").value = c.epg_user_agent;
      if (c.epg_access_user_name && $("epgAccessUserName")) $("epgAccessUserName").value = c.epg_access_user_name;
      const fields = [
        c.epg_user_id && `UserID=${c.epg_user_id}`,
        c.epg_stb_id && `STBID=${c.epg_stb_id}`,
        c.epg_auth_host && `EPG=${c.epg_auth_host}`,
        c.epg_stb_type && "STBType",
        c.epg_stb_version && "STBVersion",
        c.epg_user_agent && "UserAgent",
        c.epg_access_user_name && "AccessUserName",
      ].filter(Boolean);
      msg += `\n已自动提取 EPG 认证信息：${fields.join("，")}`;
    }
    if (data.portal_auth_detected) {
      const p = data.portal_auth_detected;
      const fields = [
        p.ctc_auth_info && "CTCGetAuthInfo",
        p.upload_user_token && "uploadAuthInfo UserToken",
        p.x_frame_session_id && "X-Frame-SessionID",
      ].filter(Boolean);
      if (fields.length) msg += `\n已捕获门户认证字段：${fields.join("，")}`;
    }
    alert(msg);
    state.channelListSection = "list";
    showTab("channelList");
  } catch (err) { alert(err.message); }
});

$("stbDiscoveryPcapBtn").addEventListener("click", () => {
  const a = document.createElement("a");
  const archive = $("stbDiscoveryArchiveSelect")?.value || "";
  a.href = archive ? `/api/stb_discovery/pcap?archive=${encodeURIComponent(archive)}` : "/api/stb_discovery/pcap";
  a.download = "";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
});

$("stbDiscoveryPcapBackupBtn")?.addEventListener("click", () => {
  const a = document.createElement("a");
  const archive = $("stbDiscoveryArchiveSelect")?.value || "";
  a.href = archive ? `/api/stb_discovery/archive-backup?archive=${encodeURIComponent(archive)}` : "/api/stb_discovery/archive-backup";
  a.download = "";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
});

$("stbDiscoveryArchiveDeleteBtn")?.addEventListener("click", async () => {
  const select = $("stbDiscoveryArchiveSelect");
  const archive = select?.value || "";
  if (!archive) return;
  const label = select.selectedOptions?.[0]?.textContent || archive;
  if (!confirmTwice(
    `将永久删除选中的原始 PCAP 及其协议清单：\n${label}\n\n此操作不可恢复，是否继续？`,
    `再次确认：即将永久删除 ${label}，是否执行？`,
  )) return;
  const btn = $("stbDiscoveryArchiveDeleteBtn");
  const status = $("stbDiscoveryArchiveStatus");
  btn.disabled = true;
  status.hidden = false; status.className = "result-box warning compact-result";
  status.textContent = "正在删除选中抓包……";
  try {
    const result = await requestJson(`/api/stb_discovery/archives/${encodeURIComponent(archive)}`, {
      method: "DELETE", body: JSON.stringify({confirmed: true}),
    });
    status.className = "result-box ok compact-result";
    status.textContent = `已删除 ${result.name}${result.artifacts_deleted ? " 及对应协议清单" : ""}。`;
    await loadStbDiscoveryState();
  } catch (err) {
    status.className = "result-box error compact-result";
    status.textContent = `删除失败：${err.message}`;
    btn.disabled = false;
  }
});

// ── catchup-source mode UI ────────────────────────────────────────────────

function updateCatchupSourceUI() {
  const mode = document.querySelector('input[name="catchupSourceMode"]:checked')?.value || "aptv";
  const templateEl = $("catchupSourceTemplate");
  const previewEl = $("catchupHlsPreview");
  if (!templateEl || !previewEl) return;
  if (mode === "custom") {
    templateEl.style.display = "";
    previewEl.style.display = "none";
  } else if (mode === "hls") {
    templateEl.style.display = "none";
    const host = $("timeshiftHost")?.value.trim() || "回看服务器";
    previewEl.textContent = `http://${host}/timeshift/{channel_id}/{start}/{duration}/index.m3u8`;
    previewEl.style.display = "";
  } else {
    templateEl.style.display = "none";
    previewEl.style.display = "none";
  }
}

document.querySelectorAll('input[name="catchupSourceMode"]').forEach(el =>
  el.addEventListener("change", updateCatchupSourceUI));
$("timeshiftHost")?.addEventListener("input", updateCatchupSourceUI);
$("catchupEnabled")?.addEventListener("change", function() {
  const block = $("catchupSettingsBlock");
  if (block) block.style.display = this.checked ? "" : "none";
  if ($("refreshBacktvBtn")) $("refreshBacktvBtn").style.display = this.checked ? "" : "none";
  loadCatchupAutoRefreshStatus().catch(() => {});
});

$("refreshBacktvBtn")?.addEventListener("click", async () => {
  const btn = $("refreshBacktvBtn");
  const orig = btn.textContent;
  btn.textContent = "刷新中…";
  btn.disabled = true;
  try {
    const result = await requestJson("/api/catchup/refresh", {method: "POST", body: JSON.stringify({
      iptv_password: $("iptvPassword")?.value || "",
      epg_user_id: $("epgUserId")?.value.trim() || "",
      epg_stb_id: $("epgStbId")?.value.trim() || "",
      epg_des3_key: $("epgDes3Key")?.value.trim() || "",
      epg_auth_host: $("epgAuthHost")?.value.trim() || "",
      epg_auth_profile: $("epgAuthProfile")?.value || "auto",
      epg_crypto_mode: $("epgCryptoMode")?.value || "auto",
      epg_des_padding: $("epgDesPadding")?.value || "pkcs5",
      epg_stb_type: $("epgStbType")?.value.trim() || "",
      epg_stb_version: $("epgStbVersion")?.value.trim() || "",
      epg_software_version: $("epgSoftwareVersion")?.value.trim() || "",
      epg_user_agent: $("epgUserAgent")?.value.trim() || "",
      epg_access_user_name: $("epgAccessUserName")?.value.trim() || "",
    })});
    alert(`回看地址刷新完成：更新 ${result.updated} / ${result.total} 个频道（EPG：${result.epg_host}，模式：${result.profile || "auto"}）`);
    await loadCatchupAutoRefreshStatus();
  } catch (err) {
    const message = String(err.message || "请求失败");
    alert(message.startsWith("刷新失败") ? message : "刷新失败：" + message);
  } finally {
    btn.textContent = orig;
    btn.disabled = false;
  }
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
    `备份：${backup.has_initial ? "已有初始备份" : "尚未创建"}`,
  ];
  status.innerHTML = lines.map(line => `<div>${line}</div>`).join("");
  status.className = "result-box " + (d.has_iptv_ip ? "ok" : ok ? "warning" : "muted");
}

function _renderIptvTcStatus(d) {
  const badge = $("iptvTcBadge");
  const status = $("iptvTcStatus");
  if (!badge || !status) return;
  const tools = d.tools || {};
  const hasBpf = Boolean(d.egress_bpf_present);
  const suspected = Boolean(d.suspected_igmp_block);
  badge.className = `chip ${suspected ? "warning" : hasBpf ? "warning" : "ok"}`;
  badge.textContent = suspected ? "疑似拦截" : hasBpf ? "发现 egress BPF" : "未发现拦截";
  const lines = [
    `<strong>接口：${escapeHtml(d.interface || "-")}</strong>`,
    `工具：tc=${tools.tc ? "可用" : "缺失"}，ip=${tools.ip ? "可用" : "缺失"}`,
    `XDP：${d.xdp_present ? "存在" : "未发现"}，clsact：${d.clsact_present ? "存在" : "未发现"}，egress BPF：${hasBpf ? "存在" : "未发现"}`,
    `clsact 丢包计数：<span class="mono">${escapeHtml(d.clsact_dropped ?? 0)}</span>`,
    `解除命令预览：<span class="mono">${escapeHtml(d.command_preview || "-")}</span>`,
    suspected
      ? "判断：疑似选定网口的 egress BPF 正在影响 IGMP/组播切换，可在确认后临时解除。"
      : hasBpf
        ? "判断：发现 egress BPF。若播放诊断显示 FCC 成功但组播无回流，可尝试临时解除。"
        : "判断：未发现典型 egress BPF 拦截。若仍无组播回流，请继续检查上游链路或 rtp2httpd 配置。",
  ];
  status.innerHTML = lines.map(line => `<div>${line}</div>`).join("");
  status.className = "result-box " + (suspected || hasBpf ? "warning" : "ok");
}

async function refreshIptvTcStatus() {
  const iface = $("iptvAuthIface").value || $("stbDiscoveryIface").value;
  if (!iface) return;
  try {
    const d = await requestJson(`/api/iptv-auth/egress-bpf/status?interface=${encodeURIComponent(iface)}`);
    _renderIptvTcStatus(d);
  } catch (err) {
    $("iptvTcBadge").className = "chip warning";
    $("iptvTcBadge").textContent = "检测失败";
    $("iptvTcStatus").textContent = `组播拦截检测失败：${err.message}`;
    $("iptvTcStatus").className = "result-box error";
  }
}

function _renderIptvTcWatch(data) {
  const badge = $("iptvTcWatchBadge");
  const status = $("iptvTcWatchStatus");
  if (!badge || !status) return;
  const cfg = data.config || {};
  const runtime = data.runtime || {};
  $("iptvTcAutoFix").checked = Boolean(cfg.enabled);
  $("iptvTcWatchInterval").value = cfg.interval_seconds || 30;
  const enabled = Boolean(cfg.enabled);
  const lastStatus = runtime.last_status || {};
  const lastResult = runtime.last_result || {};
  badge.className = `chip ${enabled ? "ok" : "neutral"}`;
  badge.textContent = enabled ? "自动修复开启" : "已关闭";
  const lines = [
    `<strong>状态：${enabled ? "开启" : "关闭"}</strong>`,
    `接口：<span class="mono">${escapeHtml(cfg.interface || "-")}</span>，间隔：<span class="mono">${escapeHtml(cfg.interval_seconds || 30)} 秒</span>`,
    `检查次数：<span class="mono">${escapeHtml(runtime.check_count || 0)}</span>，自动修复次数：<span class="mono">${escapeHtml(runtime.fix_count || 0)}</span>`,
    `上次检测：${formatDateTime(runtime.last_checked_at)}，上次修复：${formatDateTime(runtime.last_action_at)}`,
    runtime.last_error ? `最近错误：${escapeHtml(runtime.last_error)}` : "最近错误：无",
    lastStatus.interface ? `最近判断：${lastStatus.suspected_igmp_block ? "疑似拦截" : "未触发"}，egress BPF：${lastStatus.egress_bpf_present ? "存在" : "未发现"}，drop=${escapeHtml(lastStatus.clsact_dropped ?? 0)}` : "最近判断：暂无",
    lastResult.backup_path ? `最近修复备份：<span class="mono">${escapeHtml(lastResult.backup_path)}</span>` : "",
  ].filter(Boolean);
  status.innerHTML = lines.map(line => `<div>${line}</div>`).join("");
  status.className = "result-box " + (runtime.last_error ? "error" : enabled ? "ok" : "muted");
}

async function refreshIptvTcWatchStatus() {
  try {
    const d = await requestJson("/api/iptv-auth/egress-bpf/watch");
    _renderIptvTcWatch(d);
  } catch (err) {
    $("iptvTcWatchBadge").className = "chip warning";
    $("iptvTcWatchBadge").textContent = "状态异常";
    $("iptvTcWatchStatus").textContent = `自动修复状态读取失败：${err.message}`;
    $("iptvTcWatchStatus").className = "result-box error";
  }
}

async function saveIptvTcWatch() {
  const iface = $("iptvAuthIface").value || $("stbDiscoveryIface").value;
  const enabled = $("iptvTcAutoFix").checked;
  if (enabled && !iface) { alert("请先选择 IPTV 上游接口。"); return; }
  if (enabled && !confirmTwice(
    "开启后将持续检查选定网口，并在命中条件时自动解除 egress BPF。是否继续？",
    "再次确认：即将开启 egress BPF 自动修复，是否执行？",
  )) return;
  const btn = $("iptvTcWatchSaveBtn");
  btn.disabled = true; btn.textContent = "保存中…";
  try {
    const payload = {
      enabled,
      interface: iface,
      interval_seconds: Number($("iptvTcWatchInterval").value || 30),
      confirmed: enabled,
    };
    const d = await requestJson("/api/iptv-auth/egress-bpf/watch", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    _renderIptvTcWatch(d);
    $("iptvTcWatchStatus").className = "result-box ok";
  } catch (err) {
    $("iptvTcWatchStatus").textContent = `自动修复保存失败：${err.message}`;
    $("iptvTcWatchStatus").className = "result-box error";
  } finally {
    btn.disabled = false; btn.textContent = "保存自动修复";
  }
}

async function refreshIptvAuthStatus() {
  await loadIptvAuthSummary();
  const iface = $("iptvAuthIface").value || $("stbDiscoveryIface").value;
  if (!iface) return;
  if (!$("iptvAuthIface").value) $("iptvAuthIface").value = iface;
  try {
    const d = await requestJson(`/api/iptv-auth/status?interface=${encodeURIComponent(iface)}`);
    _renderIptvAuthStatus(d);
    await refreshIptvTcStatus();
    await refreshIptvTcWatchStatus();
  } catch (err) {
    $("iptvAuthBadge").className = "chip warning";
    $("iptvAuthBadge").textContent = "检测失败";
    $("iptvAuthStatus").textContent = `检测失败：${err.message}`;
    $("iptvAuthStatus").className = "result-box error";
  }
}

async function clearIptvEgressBpf() {
  const iface = $("iptvAuthIface").value || $("stbDiscoveryIface").value;
  if (!iface) { alert("请先选择 IPTV 上游接口。"); return; }
  if (!confirmTwice(
    `将临时解除 ${iface} 的 egress BPF 过滤器，并保存执行前快照。是否继续？`,
    `再次确认：即将修改 ${iface} 的流量控制设置，是否执行？`,
  )) return;
  const btn = $("iptvTcFixBtn");
  btn.disabled = true; btn.textContent = "解除中…";
  $("iptvTcStatus").textContent = "正在临时解除选定接口的 egress BPF，并保存检测快照…";
  $("iptvTcStatus").className = "result-box warning";
  try {
    const d = await requestJson("/api/iptv-auth/egress-bpf/clear", {
      method: "POST",
      body: JSON.stringify({interface: iface, confirmed: true}),
    });
    const after = d.after || {};
    _renderIptvTcStatus(after);
    const message = d.changed
      ? `已临时解除 ${d.interface} 的 egress BPF。\n备份：${d.backup_path}\n请重新播放或运行播放诊断确认组播回流。`
      : `未发现需要解除的 egress BPF。\n备份：${d.backup_path}`;
    $("iptvTcStatus").textContent = message;
    $("iptvTcStatus").className = "result-box ok";
    await refreshIptvTcWatchStatus();
  } catch (err) {
    $("iptvTcStatus").textContent = `临时解除失败：${err.message}`;
    $("iptvTcStatus").className = "result-box error";
  } finally {
    btn.disabled = false; btn.textContent = "临时解除 egress BPF";
  }
}

async function applyIptvAuth() {
  const iface = $("iptvAuthIface").value || $("stbDiscoveryIface").value;
  if (!confirmTwice(
    `实验性一键认证将修改 ${iface || "选定网口"} 的 MAC、IPv4 地址和 IPTV 路由。请确保当前管理连接不依赖该网口。是否继续？`,
    "再次确认：即将执行 IPTV 网卡认证和路由变更，是否执行？",
  )) return;
  const btn = $("iptvAuthApplyBtn");
  btn.disabled = true; btn.textContent = "执行中…";
  $("iptvAuthApplyResult").textContent = "正在执行认证，请不要断开当前管理网络…";
  $("iptvAuthApplyResult").className = "result-box warning";
  try {
    const payload = {..._iptvAuthPayload(), confirmed: true};
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
  const iface = $("iptvAuthIface").value;
  if (!confirmTwice(
    `将把 ${iface || "选定网口"} 恢复到执行 IPTV 认证前的初始状态。是否继续？`,
    "再次确认：即将恢复网口地址与路由设置，是否执行？",
  )) return;
  const btn = $("iptvAuthRestoreBtn");
  btn.disabled = true; btn.textContent = "恢复中…";
  try {
    const payload = {interface: iface, confirmed: true};
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
  if (!$("iptvAuthIface").value && $("stbDiscoveryIface")?.value) $("iptvAuthIface").value = $("stbDiscoveryIface").value;
  refreshIptvAuthStatus();
}

$("iptvAuthRefreshBtn").addEventListener("click", refreshIptvAuthStatus);
$("iptvAuthApplyBtn").addEventListener("click", applyIptvAuth);
$("iptvAuthRestoreBtn").addEventListener("click", restoreIptvAuth);
$("iptvTcRefreshBtn").addEventListener("click", refreshIptvTcStatus);
$("iptvTcFixBtn").addEventListener("click", clearIptvEgressBpf);
$("iptvTcWatchSaveBtn").addEventListener("click", saveIptvTcWatch);
$("iptvTcWatchRefreshBtn").addEventListener("click", refreshIptvTcWatchStatus);
$("iptvAuthIface").addEventListener("change", refreshIptvAuthStatus);

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
    const allOk = d.checks.length > 0 && d.checks.every(c => c.ok === true);
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

// ── Channel list sort ─────────────────────────────────────────────────────

let _clSort = { col: null, dir: 1 }; // dir: 1=asc, -1=desc

function _sortChannels(channels) {
  if (!_clSort.col) return channels;
  const col = _clSort.col;
  const dir = _clSort.dir;
  return [...channels].sort((a, b) => {
    let va, vb;
    if (col === "name")     { va = a.name || ""; vb = b.name || ""; }
    else if (col === "addr"){ va = a.key || ""; vb = b.key || ""; }
    else if (col === "category") { va = a.category || ""; vb = b.category || ""; }
    else                    { va = a.tvg_id || ""; vb = b.tvg_id || ""; }
    return dir * va.localeCompare(vb, "zh");
  });
}

function _updateSortHeaders() {
  document.querySelectorAll(".cl-table th.sortable").forEach(th => {
    th.classList.remove("sort-asc", "sort-desc");
    if (th.dataset.sort === _clSort.col) {
      th.classList.add(_clSort.dir === 1 ? "sort-asc" : "sort-desc");
    }
  });
}

document.querySelectorAll(".cl-table th.sortable").forEach(th => {
  th.addEventListener("click", () => {
    const col = th.dataset.sort;
    if (_clSort.col === col) {
      _clSort.dir *= -1;
    } else {
      _clSort.col = col;
      _clSort.dir = 1;
    }
    _updateSortHeaders();
    filterAndRenderChannelList();
  });
});


async function refreshMediaTasks() {
  const box = $("mediaTasks");
  if (!box) return;
  try {
    const data = await requestJson("/api/media/tasks");
    const tasks = data.active || [];
    const names = {hls: "直播", catchup: "回看", snapshot: "截图", diagnose: "诊断"};
    box.innerHTML = `<div>正在运行 ${tasks.length} / ${data.limit}</div>` + tasks.map(task =>
      `<div class="button-row"><span>${escapeHtml(names[task.kind] || task.kind)} · ${escapeHtml(task.key || "")} · ${Number(task.elapsed_seconds)} 秒</span><button type="button" class="secondary xs-btn" data-cancel-media="${escapeHtml(task.id)}" ${task.cancel_requested ? "disabled" : ""}>${task.cancel_requested ? "正在取消" : "取消任务"}</button></div>`).join("");
  } catch (error) { box.textContent = `获取任务失败：${error.message}`; }
}
$("mediaRefreshBtn")?.addEventListener("click", refreshMediaTasks);
$("mediaTasks")?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-cancel-media]");
  if (!button) return;
  button.disabled = true;
  try {
    await requestJson(`/api/media/tasks/${encodeURIComponent(button.dataset.cancelMedia)}`, {method: "DELETE"});
    await refreshMediaTasks();
  } catch (error) { $("mediaTasks").textContent = `取消失败：${error.message}`; }
});
