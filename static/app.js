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
  logPoller: null,
  channelList: [],
  selectedChannelKeys: new Set(),
  channelListSection: "list",
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
  const selectedInterface = $("stbDiscoveryIface")?.value || $("iptvAuthIface")?.value || state.settings?.interface || "";
  return {
    interface: selectedInterface,
    http_host: $("httpHost").value.trim(),
    http_port: Number($("httpPort").value || 5140),
    rtp2httpd_config_path: $("diagConfigPath")?.value.trim() || "",
    path_mode: $("pathMode").value,
    duration: 0,
    auto_probe: false,
    auto_epg: true,
    catchup_enabled: $("catchupEnabled")?.checked ?? false,
    catchup_days: Number($("catchupDays")?.value ?? 7),
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


function showTab(tabName) {
  $("homePage").hidden = true;
  $("workbenchPage").hidden = false;
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

async function loadSettings() {
  const data = await requestJson("/api/settings");
  state.settings = data;
  if ($("iptvAuthIface") && data.interface) $("iptvAuthIface").value = data.interface;
  $("httpHost").value = data.http_host || "";
  $("httpPort").value = data.http_port ?? 5140;
  if ($("diagConfigPath")) $("diagConfigPath").value = data.rtp2httpd_config_path || "";
  $("pathMode").value = data.path_mode || "rtp";
  if ($("catchupEnabled")) {
    $("catchupEnabled").checked = !!data.catchup_enabled;
    const block = $("catchupSettingsBlock");
    if (block) block.style.display = data.catchup_enabled ? "" : "none";
  }
  $("catchupDays").value = data.catchup_days ?? 7;
  if ($("timeshiftHost")) $("timeshiftHost").value = data.timeshift_host || "";
  const _csmEl = document.querySelector(`input[name="catchupSourceMode"][value="${data.catchup_source_mode || 'aptv'}"]`);
  if (_csmEl) _csmEl.checked = true;
  if ($("catchupSourceTemplate")) $("catchupSourceTemplate").value = data.catchup_source_template || "";
  updateCatchupSourceUI();
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
      ? `导出前检查 ${health.groups_checked} 个多线路组、${health.checked} 条源：可用 ${health.ok}，失败 ${health.failed}，超时 ${health.timeout}${health.limit_reached ? "，已达检查上限" : ""}。`
      : (health?.message || "");
    $("clExportResult").textContent = `共 ${data.count} 条线路，分组后主源 ${data.best_count ?? data.count} 个。${healthText ? `\n${healthText}` : ""}`;
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
    syncSelectedChannelKeys();
    filterAndRenderChannelList();
  } catch (err) { console.warn("loadChannelList:", err.message); }
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

function visibleGroupKeys() {
  return [...document.querySelectorAll("#clGroupTableBody tr[data-key]")]
    .map((row) => row.dataset.key)
    .filter(Boolean);
}

function selectedChannelRows() {
  const selected = state.selectedChannelKeys || new Set();
  return selected.size > 0
    ? (state.channelList || []).filter((ch) => selected.has(ch.key))
    : (state.channelList || []);
}

function refreshChannelSelectionControls() {
  document.querySelectorAll(".cl-check").forEach((cb) => {
    cb.checked = state.selectedChannelKeys.has(cb.dataset.key || cb.closest("tr")?.dataset.key);
  });
  const flatKeys = visibleFlatKeys();
  const flatAll = flatKeys.length > 0 && flatKeys.every((key) => state.selectedChannelKeys.has(key));
  const flatSelect = $("clSelectAll");
  if (flatSelect) flatSelect.checked = flatAll;
  const groupKeys = visibleGroupKeys();
  const groupAll = groupKeys.length > 0 && groupKeys.every((key) => state.selectedChannelKeys.has(key));
  const groupSelect = $("clGroupSelectAll");
  if (groupSelect) groupSelect.checked = groupAll;
}

function filterAndRenderChannelList() {
  if (_groupViewActive) { filterAndRenderGroupView(); return; }
  const name = ($("clFilterName").value || "").trim().toLowerCase();
  const category = $("clFilterCategory").value;
  let filtered = state.channelList || [];
  if (name) filtered = filtered.filter(ch => (ch.name || "").toLowerCase().includes(name));
  if (category) filtered = filtered.filter(ch => ch.category === category);
  renderChannelList(_sortChannels(filtered));
}

function renderChannelList(channels) {
  const total = (state.channelList || []).length;
  $("clChannelCount").textContent = channels.length === total
    ? `${channels.length} 个`
    : `${channels.length} / ${total} 个`;
  const tbody = $("clChannelTableBody");
  if (!channels.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">频道列表为空，请先完成运营商频道发现并导入。</td></tr>';
    refreshChannelSelectionControls();
    return;
  }
  tbody.innerHTML = channels.map((ch) => {
    const addr = ch.key || `${ch.host || ""}:${ch.port ?? ""}`;
    const epg = ch.tvg_id || "-";
    const checked = state.selectedChannelKeys.has(ch.key) ? "checked" : "";
    return `
    <tr data-key="${escapeHtml(ch.key || "")}">
      <td><input type="checkbox" class="cl-check" data-key="${escapeHtml(ch.key || "")}" ${checked}></td>
      <td>${escapeHtml(ch.name || "")}</td>
      <td class="mono small">${escapeHtml(addr)}</td>
      <td>${escapeHtml(ch.category || "")}</td>
      <td class="mono small">${escapeHtml(epg)}</td>
    </tr>`;
  }).join("");
  tbody.querySelectorAll(".cl-check").forEach((cb) => {
    cb.addEventListener("change", () => {
      setChannelSelected(cb.dataset.key, cb.checked);
      refreshChannelSelectionControls();
    });
  });
  refreshChannelSelectionControls();
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
$("saveExportSettingsBtn").addEventListener("click", async () => {
  try {
    await requestJson("/api/settings", {method: "POST", body: JSON.stringify({
      http_host: $("httpHost").value.trim(),
      http_port: Number($("httpPort").value || 5140),
      path_mode: $("pathMode").value,
      fcc_type: $("fccType")?.value || "",
      catchup_enabled: $("catchupEnabled")?.checked ?? false,
      catchup_days: Number($("catchupDays")?.value ?? 7),
      timeshift_host: $("timeshiftHost")?.value.trim() || "",
      catchup_source_mode: document.querySelector('input[name="catchupSourceMode"]:checked')?.value || "aptv",
      catchup_source_template: $("catchupSourceTemplate")?.value.trim() || "",
      pre_export_health_check: $("preExportHealthCheck")?.checked ?? false,
    })});
    alert("导出设置已保存");
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
  visibleFlatKeys().forEach((key) => setChannelSelected(key, this.checked));
  refreshChannelSelectionControls();
});
$("clGroupSelectAll").addEventListener("change", function() {
  visibleGroupKeys().forEach((key) => setChannelSelected(key, this.checked));
  refreshChannelSelectionControls();
});
$("clSelectAllBtn").addEventListener("click", () => {
  const keys = _groupViewActive ? visibleGroupKeys() : visibleFlatKeys();
  keys.forEach((key) => setChannelSelected(key, true));
  refreshChannelSelectionControls();
});
$("clClearSelBtn").addEventListener("click", () => {
  const keys = _groupViewActive ? visibleGroupKeys() : visibleFlatKeys();
  keys.forEach((key) => setChannelSelected(key, false));
  refreshChannelSelectionControls();
});
$("clDeleteSelectedBtn").addEventListener("click", async () => {
  const selectedKeys = [...state.selectedChannelKeys];
  if (!selectedKeys.length) { alert("请先勾选要删除的频道"); return; }
  if (!confirm(`确定删除选中的 ${selectedKeys.length} 个频道？`)) return;
  try {
    await requestJson("/api/channels/delete", {method: "POST", body: JSON.stringify({keys: selectedKeys})});
    state.selectedChannelKeys.clear();
    await loadChannelList();
  } catch (err) { alert(err.message); }
});
$("clRefreshBtn").addEventListener("click", () => loadChannelList());
$("clFilterName").addEventListener("input", filterAndRenderChannelList);
$("clFilterCategory").addEventListener("change", filterAndRenderChannelList);
$("backupExportBtn").addEventListener("click", async () => {
  const btn = $("backupExportBtn");
  btn.disabled = true;
  try {
    const resp = await fetch("/api/backup/export");
    if (!resp.ok) throw new Error(`导出失败：${resp.status}`);
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const ts = new Date().toISOString().slice(0, 10);
    a.href = url; a.download = `iptv-sniffer-backup-${ts}.json`;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
    const box = $("backupStatus");
    box.hidden = false; box.className = "result-box ok";
    box.textContent = "配置已导出到本地文件。";
  } catch (err) {
    const box = $("backupStatus");
    box.hidden = false; box.className = "result-box error";
    box.textContent = `导出失败：${err.message}`;
  } finally { btn.disabled = false; }
});
$("backupImportBtn").addEventListener("click", () => {
  $("backupImportFile").value = "";
  $("backupImportFile").click();
});
$("backupImportFile").addEventListener("change", async function () {
  const file = this.files[0];
  if (!file) return;
  const btn = $("backupImportBtn");
  btn.disabled = true; btn.textContent = "导入中…";
  const box = $("backupStatus");
  box.hidden = false; box.className = "result-box warning";
  box.textContent = "正在导入，请稍候…";
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    const result = await requestJson("/api/backup/import", {method: "POST", body: JSON.stringify(data)});
    box.className = "result-box ok";
    box.textContent = `导入完成：已恢复 ${result.restored.join("、") || "无"}；跳过 ${result.skipped.join("、") || "无"}。页面将在 2 秒后刷新。`;
    loadSavedOperatorCount().catch(() => {});
    loadIptvAuthSummary().catch(() => {});
    setTimeout(() => location.reload(), 2000);
  } catch (err) {
    box.className = "result-box error";
    box.textContent = `导入失败：${err.message}`;
  } finally { btn.disabled = false; btn.textContent = "导入本地配置"; }
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
    box.textContent = `正在捕获 ${escapeHtml(state.stb_ip || "")} 的流量（${elapsed} 秒）…请立即重启机顶盒。${liveHint ? liveHint.slice(1) + "。" : ""}`;
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
    let msg = `已导入 ${data.imported} 个频道到频道列表。`;
    if (data.timeshift_host_detected) {
      msg += `\n已自动检测到回看服务器：${data.timeshift_host_detected}`;
      if ($("timeshiftHost")) $("timeshiftHost").value = data.timeshift_host_detected;
      updateCatchupSourceUI();
    }
    alert(msg);
    state.channelListSection = "list";
    showTab("channelList");
  } catch (err) { alert(err.message); }
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
  if (!$("iptvTcConfirm").placeholder && d.confirmation_text) $("iptvTcConfirm").placeholder = d.confirmation_text;
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
  if (!$("iptvTcWatchConfirm").placeholder && data.confirmation_text) $("iptvTcWatchConfirm").placeholder = data.confirmation_text;
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
  const btn = $("iptvTcWatchSaveBtn");
  btn.disabled = true; btn.textContent = "保存中…";
  try {
    const payload = {
      enabled,
      interface: iface,
      interval_seconds: Number($("iptvTcWatchInterval").value || 30),
      confirm: $("iptvTcWatchConfirm").value.trim(),
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
  const confirmText = $("iptvTcConfirm").value.trim();
  const btn = $("iptvTcFixBtn");
  btn.disabled = true; btn.textContent = "解除中…";
  $("iptvTcStatus").textContent = "正在临时解除选定接口的 egress BPF，并保存检测快照…";
  $("iptvTcStatus").className = "result-box warning";
  try {
    const d = await requestJson("/api/iptv-auth/egress-bpf/clear", {
      method: "POST",
      body: JSON.stringify({interface: iface, confirm: confirmText}),
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
    const res = await requestJson("/api/iptv-auth/backup-import", { method: "POST", body: JSON.stringify(data) });
    let msg = `接口 ${data.interface} 的初始备份已导入，恢复功能现在可用。`;
    if (res.warn_no_ipv4) msg += "\n\n⚠️ 注意：此备份捕获时网卡尚无 IPv4 地址，执行恢复后将自动尝试普通 DHCP 补救，若失败需手动配置 IP。";
    alert(msg);
    await refreshIptvAuthStatus();
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

// ── Channel group view ────────────────────────────────────────────────────

let _groupViewActive = false;

function _roleBadge(role, manual = false) {
  if (role === "primary") {
    return `<span class="source-role ${manual ? "manual" : "primary"}">${manual ? "手动主源" : "自动主源"}</span>`;
  }
  return '<span class="source-role alt">备选线路</span>';
}

function _lineTech(ch) {
  const codec = ch.codec_name || "编码未知";
  const fps = ch.frame_rate ? `${ch.frame_rate}fps` : "";
  const packets = Number(ch.packets || 0) > 0 ? `${ch.packets} 包` : "";
  return [codec, fps, packets].filter(Boolean);
}

function _lineFcc(ch) {
  const parts = [];
  if (ch.fcc_ip && ch.fcc_port) parts.push(`FCC ${ch.fcc_ip}:${ch.fcc_port}`);
  if (ch.fec_port) parts.push(`FEC ${ch.fec_port}`);
  return parts.length ? parts : ["无 FCC/FEC"];
}

function _lineStatus(ch) {
  const status = ch.export_health_status || "";
  const label = status === "ok" ? "播放可用"
    : status === "failed" ? "播放失败"
    : status === "timeout" ? "播放超时"
    : status === "error" ? "检查异常"
    : "未检查";
  const when = ch.export_health_checked_at || ch.updated_at || ch.last_seen || ch.epg_matched_at;
  const detail = ch.export_health_message || "";
  return {label, detail, when: formatDateTime(when)};
}

function renderChannelGroups(groups) {
  const tbody = $("clGroupTableBody");
  if (!groups.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">暂无频道组，请先导入频道。</td></tr>';
    refreshChannelSelectionControls();
    return;
  }
  const rows = [];
  for (const g of groups) {
    const p = g.primary;
    const hasAlts = g.alternates.length > 0;
    const pStatus = _lineStatus(p);
    const pChecked = state.selectedChannelKeys.has(p.key) ? "checked" : "";
    rows.push(`<tr data-group="${escapeHtml(g.group_key)}" data-key="${escapeHtml(p.key || "")}">
      <td><input type="checkbox" class="cl-check" data-key="${escapeHtml(p.key || "")}" ${pChecked}></td>
      <td><button class="expand-btn" data-group="${escapeHtml(g.group_key)}" aria-expanded="false">${hasAlts ? "▶" : ""}</button></td>
      <td>
        <div class="line-stack">
          <span class="line-title">${escapeHtml(p.name || "")}</span>
          <span class="line-sub mono">${escapeHtml(p.key || "")}</span>
          <span class="line-sub">${g.count} 条线路，${g.alternates.length} 条备选</span>
        </div>
      </td>
      <td>${_roleBadge("primary", Boolean(p.is_primary))}</td>
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
      const altChecked = state.selectedChannelKeys.has(alt.key) ? "checked" : "";
      rows.push(`<tr class="alt-row hidden" data-parent="${escapeHtml(g.group_key)}" data-key="${escapeHtml(alt.key || "")}">
        <td><input type="checkbox" class="cl-check" data-key="${escapeHtml(alt.key || "")}" ${altChecked}></td>
        <td></td>
        <td>
          <div class="line-stack">
            <span class="line-title">${escapeHtml(alt.name || "")}</span>
            <span class="line-sub mono">${escapeHtml(alt.key || "")}</span>
          </div>
        </td>
        <td>${_roleBadge("alt")}</td>
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
  tbody.querySelectorAll(".cl-check").forEach((cb) => {
    cb.addEventListener("change", () => {
      setChannelSelected(cb.dataset.key, cb.checked);
      refreshChannelSelectionControls();
    });
  });
  refreshChannelSelectionControls();

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
    refreshChannelSelectionControls();
  }
}

function filterAndRenderGroupView() {
  const groups = state.channelGroups || [];
  const name = ($("clFilterName").value || "").trim().toLowerCase();
  const category = $("clFilterCategory").value;
  let filtered = groups;
  if (name) filtered = filtered.filter(g =>
    (g.primary.name || "").toLowerCase().includes(name) ||
    g.alternates.some(a => (a.name || "").toLowerCase().includes(name))
  );
  if (category) filtered = filtered.filter(g => g.primary.category === category);
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
    filterAndRenderChannelList();
  }
});
