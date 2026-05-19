# IPTV Sniffer Web v0.9.6

适用于 **OpenWrt / iStoreOS / 飞牛 NAS / 其它 Linux Docker 宿主机** 的 IPTV 组播嗅探、运营商频道发现与 `rtp2httpd` 播放列表统一工作台。

v0.6 起基于以下两个开源项目的思路重构而来，并整合为单一 Web 图形化工作台：

- [`zzzz0317/beijing-unicom-iptv-playlist`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist)：参考其多源播放列表、代理地址转换与 M3U 生成思路；
- [`zzzz0317/beijing-unicom-iptv-playlist-sniffer`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist-sniffer)：参考其对机顶盒 `channelAcquire` 请求和 `UserToken` 的嗅探方式。

特别感谢以上项目作者的公开实现与整理工作。

另参考并致谢：

- [`CGG888/SrcBox`](https://github.com/CGG888/SrcBox)：参考其对 FCC 快速换台、UDP/RTP/IGMP 多协议流识别以及 XMLTV EPG 模糊匹配的工程实现思路。

EPG 与台标来源参考并致谢：

- [`epg.51zmt.top`](https://epg.51zmt.top:8001/)：老张的 EPG / 51zmt 数据；
- [`wanglindl/TVlogo`](https://github.com/wanglindl/TVlogo)：频道台标 M3U 资源。

---

## 核心特性

- **运营商频道发现（主入口）**：填写机顶盒 IP，重启机顶盒，系统自动从 STB 开机 TCP 流量中解析运营商 EPG 门户的完整频道表，一键导入频道名称、组播地址与 FCC 参数；
- **嗅探整理（补充入口）**：网页选择接口后实时嗅探 IPTV 组播流，自动过滤无效组播，自动识别编码、分辨率、截图和 EPG，嗅探结果可导入频道列表；
- **频道列表**：统一管理所有已导入的频道，支持勾选特定频道后生成播放列表；
- **定时 EPG 刷新**：定时自动刷新所有配置的 EPG 来源，保持频道 EPG 与台标信息持续更新；
- 抓包时解析 `ChannelFCCIP` / `ChannelFCCPort`，保存到 `data/fcc.json`；
- 抓包时识别 `POST /bj_stb/V1/STB/channelAcquire` 中的 `UserToken`，保存到 `data/playlist_token.json`；
- 抓包后使用 `ffprobe` 自动识别编码、分辨率、帧率和流内频道名，并生成 4K / 高清 / 普通频道分组；
- 支持 XMLTV EPG 与 TVlogo 缓存匹配，导出时写入 `tvg-id` / `tvg-name` / `tvg-logo`；
- 有效候选右侧自动显示截图（ffmpeg 直连组播抓帧），点击可放大；
- 导出直连 M3U、rtp2httpd 外部源 M3U、JSON、TXT、CSV。

---

## 快速开始

**方式一：Docker Hub 拉取（推荐）**

```bash
mkdir -p data output
docker run -d \
  --name iptv-sniffer-web \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -e TZ=Asia/Shanghai \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/output:/app/output \
  roninriddle/iptv-sniffer-web:latest
```

**方式二：本地构建**

```bash
mkdir -p data output
docker compose up -d --build
```

打开：

```text
http://宿主机IP:8787
```

---

## 网络前置条件

本项目只负责抓包分析和播放列表生成，**不负责把 IPTV 专网引入宿主机**。运行前请确认：

| 项目 | 说明 |
|---|---|
| IPTV 流量可达 | 宿主机能收到机顶盒组播包 |
| 抓包接口正确 | 选择 IPTV 流量真实进来的那张网卡 |
| 支持 VLAN Tagged | v0.9.4 起支持 802.1Q / QinQ 帧；单线复用场景无需额外配置 |

**典型部署方式：**

1. **交换机端口镜像**：管理型交换机将机顶盒端口流量镜像到 Docker 宿主机网口
2. **OpenWrt / iStoreOS**：IPTV 流量经由路由器本机，直接在路由器上部署容器
3. **NAS 双网口**：一个网口接 IPTV 专网，另一个接管理网络；在 IPTV 接口上抓包

光猫桥接、VLAN 引入、IGMP Proxy / Snooping、防火墙配置等属于网络基础设施配置，请参考你的路由器 / 运营商文档。

---

## NanoPi R4S + iStoreOS 被动抓包部署

### 推荐网络拓扑

```text
ONT（光猫）
  └─ IPTV 专口（如华为 B850 LAN2，192.168.100.x DHCP）
       └─ NanoPi R4S  eth0（被动监听，无 IP 地址）
                           ← tcpdump 抓取 STB 开机 TCP 流量

NanoPi R4S  eth1（LAN，192.168.x.x）
  └─ 家庭内网交换机
       ├─ 机顶盒（STB）
       ├─ 电视 / 手机 / 电脑
       └─ 上级路由器（可选）
```

R4S 默认：`eth1` = LAN，`eth0` = WAN。将 `eth0` 改为 `proto=none` 被动监听模式，直连光猫 IPTV 专口，即可用 tcpdump 嗅探 STB 开机流量，**无需为 eth0 分配 IP 地址**。

### 为什么 eth0 不需要 IP

tcpdump 工作在第 2 层（数据链路层），只需网卡处于 UP 状态并能收到帧，无需 IP 地址。为 eth0 配置 IP 反而可能：

- 触发 `udhcpc` 修改系统默认路由，中断 SSH 会话；
- 产生不必要的 ARP / DHCP 广播，干扰光猫侧的 IPTV 认证。

被动监听模式下 eth0 无 IP、无路由、无 DHCP，仅接收帧并交给 tcpdump。

### 部署向导

容器内置 **部署向导（"部署向导"标签页）**，可自动读取宿主机 `/etc/config/network`，分析 UCI 配置，并生成一键配置脚本。

**启用向导（需挂载宿主机配置文件）**：

在 `docker-compose.yml` 中取消注释以下行：

```yaml
volumes:
  - ./data:/app/data
  - ./output:/app/output
  - /etc/config/network:/host/etc/config/network:ro   # ← 取消此行注释
```

或在 `docker run` 命令中追加：

```bash
-v /etc/config/network:/host/etc/config/network:ro
```

### R4S UCI 配置脚本

向导生成的脚本内容如下（也可直接复制到 iStoreOS SSH 中执行）：

```sh
#!/bin/sh
# IPTV Sniffer Web — iStoreOS eth0 被动抓包模式配置
# 备份当前配置
cp /etc/config/network /etc/config/network.backup-iptv-sniffer-$(date +%Y%m%d%H%M%S)
# 移除 WAN 接口（释放 eth0）
uci -q delete network.wan  || true
uci -q delete network.wan6 || true
# 创建被动监听接口
uci -q delete network.iptv_sniff || true
uci set network.iptv_sniff='interface'
uci set network.iptv_sniff.proto='none'
uci set network.iptv_sniff.device='eth0'
# 应用
uci commit network
/etc/init.d/network restart
```

> **注意**：执行后 eth0 不再绑定 WAN，路由器不再通过 eth0 上网。仅适用于 eth0 不承担上网任务的旁路嗅探场景。恢复：`cp /etc/config/network.backup-iptv-sniffer-* /etc/config/network && uci commit network && /etc/init.d/network restart`。

### 配置完成后的操作流程

1. 在 iStoreOS 宿主机 SSH 中执行上方脚本（或通过向导点击「复制脚本」后手动粘贴执行）；
2. 将光猫 IPTV 专口网线插入 R4S `eth0`；
3. 打开 IPTV Sniffer Web → **部署向导** → 点击「将 eth0 应用为抓包网卡」，自动同步到抓包接口选择框；
4. 前往 **运营商频道发现** → 填写机顶盒 IP → 点击「开始捕获」；
5. 重启机顶盒（拔插电源），等待系统解析频道表；
6. 点击「导入到频道列表」；
7. 前往 **频道列表** → 探测分辨率 → 下载 M3U。

---

## Docker 权限

Compose 中需要保留：

```yaml
network_mode: host
cap_add:
  - NET_ADMIN
  - NET_RAW
```

`rtp2httpd` 默认端口为 `5140`，页面默认使用 `/rtp/` 地址形式：

```text
http://rtp2httpd-host:5140/rtp/239.x.x.x:port
```

如果嗅探到了 FCC，播放地址会追加：

```text
?fcc=FCC服务器IP:FCC服务器端口
```

如果指定了 FCC 协议类型，会进一步追加 `&fcc-type=telecom` 或 `&fcc-type=huawei`。

如果运营商频道表中包含 FEC 端口，会追加：

```text
?fec=FEC端口
```

---

## 页面流程

1. **运营商频道发现（推荐）**：填写机顶盒 IP，点击「开始捕获」后重启机顶盒；系统自动解析频道表，点击「导入到频道列表」；
2. **嗅探整理（可选补充）**：选择抓包网卡，填写 `rtp2httpd` 地址、端口和路径模式；点击「继续抓包」切台；点击「导入到频道列表」；
3. 进入「频道列表」，勾选需要的频道，点击「一键探测分辨率」，再下载所需格式；
4. 在「定时 EPG」中配置定时刷新计划，保持 EPG 信息持续更新。

---

## 北京联通参考流程

北京联通 IPTV 对本项目的兼容性较好，推荐按以下步骤操作：

1. 确认宿主机能收到机顶盒 IPTV 流量（镜像端口或单线复用均可）
2. 进入「运营商频道发现」→ 填写机顶盒 IP → 选择抓包网卡 → 点击「开始捕获」
3. 重启机顶盒，等待系统自动解析频道表（含 FCC、FEC 信息）
4. 点击「导入到频道列表」
5. 进入「频道列表」→「一键探测分辨率」（可选，需要 ffprobe）
6. 在 rtp2httpd 配置区填写服务器地址，FCC 协议类型选 `telecom`
7. 点击「下载直连 M3U」或「下载源地址 M3U」
   - 直连 M3U：通过 rtp2httpd 代理播放，支持 FCC 快速换台
   - 源地址 M3U：作为 rtp2httpd 的 `external-m3u` 配置源

频道表更新：如果已经完成过一次捕获，可在「运营商频道发现」→「已保存频道表」直接重新导入，无需再重启机顶盒。

---

## 导出文件

文件会生成到 `output/`：

- `channels-direct.m3u`：可直接导入播放器的 HTTP 播放地址；
- `channels-rtp2httpd-source.m3u`：保留 `rtp://` / `udp://` 源地址，可作为 rtp2httpd `external-m3u`；
- `channels.json`：保留 `live` 源结构与 EPG 字段，便于二次转换或迁移；
- `channels.txt`：常见 IPTV 软件可用的 TXT 格式；
- `channels.csv`：频道、清晰度、EPG、FCC、源地址和播放地址明细。

M3U / TXT 会保留原始分类，并额外生成：

```text
4K高清
高清频道
普通频道
```

---

## 持久化文件

- `data/settings.json`：页面默认参数；
- `data/channels.json`：频道列表（所有已导入的频道）；
- `data/discovered_channels.json`：抓包自动识别到的频道名与频道号；
- `data/operator_channels.json`：运营商频道发现导入的频道表；
- `data/epg_cache.json`：XMLTV EPG 缓存与匹配索引；
- `data/fcc.json`：按组播地址记录的 FCC 服务器；
- `data/playlist_token.json`：嗅探到的 channelAcquire UserToken；
- `data/app.log`：完整运行日志。

---

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/version` | 应用名称与版本 |
| GET | `/api/health` | 抓包与 ffprobe 运行检查 |
| GET | `/api/metrics` | 运行指标、FCC 数、token 数、EPG 状态 |
| GET | `/api/interfaces` | 获取可抓包接口 |
| GET | `/api/settings` | 获取默认设置 |
| POST | `/api/settings` | 保存默认设置 |
| GET | `/api/schedule` | 获取定时任务状态 |
| POST | `/api/schedule` | 保存或停用定时 EPG 刷新任务 |
| POST | `/api/schedule/run-now` | 立即刷新所有 EPG 来源 |
| POST | `/api/capture/start` | 继续抓包（不清空已发现流，可多次追加） |
| POST | `/api/capture/stop` | 停止抓包 |
| POST | `/api/capture/reset` | 重置候选流（清空所有已发现流） |
| GET | `/api/streams` | 获取候选流 |
| GET | `/api/channels` | 获取频道列表 |
| POST | `/api/channels/save` | 导入频道到频道列表 |
| POST | `/api/channels/delete` | 从频道列表删除指定频道（传 keys 数组） |
| GET | `/api/fcc` | 获取 FCC 记录 |
| GET | `/api/stb-token` | 获取最近的 channelAcquire token 摘要 |
| GET | `/api/discovery` | 获取自动识别的频道名记录 |
| GET | `/api/epg/status` | 获取 EPG 缓存状态（含各来源统计） |
| GET | `/api/epg/sources` | 获取 EPG 与台标来源列表 |
| POST | `/api/epg/refresh` | 刷新单个 XMLTV EPG 来源 |
| POST | `/api/epg/refresh-all` | 立即刷新所有活跃 EPG 来源 |
| POST | `/api/probe` | 内部自动流信息识别 |
| POST | `/api/probe/batch` | 内部批量流信息识别 |
| POST | `/api/export` | 生成导出文件 |
| GET | `/api/download/<filename>` | 下载导出文件 |
| GET | `/api/stb_discovery/status` | 获取 STB 开机捕获状态 |
| POST | `/api/stb_discovery/start` | 启动 STB 开机捕获 |
| POST | `/api/stb_discovery/stop` | 停止捕获并分析 |
| POST | `/api/stb_discovery/import` | 将发现的频道导入到频道列表 |
| POST | `/api/stb_discovery/reset` | 重置捕获状态 |
| GET | `/api/operator_channels` | 获取运营商频道表 |
| GET | `/api/openwrt/network-analysis` | 读取宿主机 UCI 配置并分析接口用途（需挂载 `/host/etc/config/network`） |
| GET | `/api/openwrt/generate-script` | 生成 R4S eth0 被动抓包 UCI 配置脚本 |
| GET | `/api/logs` | 获取实时日志 |
| GET | `/api/logs/download` | 下载完整日志 |

---

## 环境变量

```text
RTP2HTTPD_HOST=
RTP2HTTPD_PORT=5140
EPG_URL=http://epg.51zmt.top:8000/e.xml.gz
LOGO_URL=https://raw.githubusercontent.com/wanglindl/TVlogo/main/TVlist.m3u
CAPTURE_SECONDS=30
MIN_PACKET_COUNT=3
PROBE_TIMEOUT_SECONDS=10
PROBE_ANALYZE_DURATION_US=8000000
PROBE_SIZE_BYTES=8000000
PROBE_BUFFER_SIZE=131072
CAPTURE_FILTER=(udp and dst net 224.0.0.0/4) or tcp
```

---

## 版本

- `v0.9.6`：修复部署向导前端 `requestJson()` 重复取 `.data` 导致向导始终显示"检测失败"；修复 `CUSetConfig` 频道表解析回归（单引号与双引号两种外层格式均可正确提取频道，属性值同时兼容单双引号）；新增回归测试套件覆盖 Ethernet / SLL / SLL2 pcap、单双引号频道表解析、FEC/FCC/fcc-type 导出 URL、OpenWrt UCI 解析器与分析器接口契约（25 项全部通过）；
- `v0.9.5`：新增 iStoreOS / OpenWrt 部署向导（"部署向导"标签页）：自动读取宿主机 `/etc/config/network`（需 `-v /etc/config/network:/host/etc/config/network:ro`），分析 UCI 接口用途，一键生成 eth0 被动监听配置脚本，支持复制 / 下载，并可将 eth0 同步为全局抓包接口；STB 开机 pcap 解析兼容 Linux cooked SLL（DLT=113）与 SLL2（DLT=276）链路类型（`tcpdump -i any` 抓包不再丢失频道数据）；运营商频道发现支持双引号 `CUSetConfig("Channel"...)` 格式；FEC 端口从运营商频道表全链路贯通至导出 URL；候选流预览地址同步携带 `fec_port` 与 `fcc_type`；
- `v0.9.4`：STB 开机捕获支持 802.1Q / QinQ VLAN Tagged 帧（单线复用 / trunk 镜像场景不再丢包）；FEC 端口全链路贯通（运营商频道表 → 频道存储 → 导出 URL 追加 `?fec=PORT`）；新增 FCC 协议类型选择（telecom / huawei），导出 URL 自动追加 `&fcc-type=VALUE`；README 补充 Docker Hub 拉取方式、网络前置条件说明与北京联通参考流程；
- `v0.9.2`：修复 STB 开机捕获 TCP 重组：按 seq 排序后拼接，跳过重传包，解决乱序或重传导致的频道表解析失败；修复多 EPG 来源优先级：首个刷新的 EPG 源固定为主源，后续刷新不再替换主源；修复 `epg_source` 字段：记录实际命中的 EPG 来源 URL 而非当前主源 URL；修复多源 EPG / 台标重启后丢失：`epg_cache.json` 现在持久化全部来源数据，重启后自动恢复；频道列表新增「一键探测分辨率」按钮；
- `v0.9.1`：修复频道列表地址列太窄（64px→170px），改用 `.cl-table` 专用 CSS 类；
- `v0.9.0`：启动时后台自动刷新全部 EPG 与台标；运营商频道页新增「已保存频道表」重新导入（无需重启机顶盒）；频道列表新增命名快照（保存/恢复/删除）；定时 EPG 页内联 EPG 与台标来源管理（添加/删除/恢复）；全量刷新同时更新台标；每个下载按钮直接触发生成并下载，移除「生成播放列表」按钮；回看（catchup）支持：导出 M3U 时对运营商标记的回看频道写入 `catchup="default" catchup-days=N` 属性；页面底部新增作者 Ronin Riddle；
- `v0.8.5`：频道列表地址列改用 key 直接渲染，修复端口为 0 时地址显示异常；清晰度/EPG 无数据时显示「-」而非空白；「刷新接口」改为「刷新网卡」，运营商频道的抓包网卡改为下拉选择并随刷新同步更新；
- `v0.8.4`：修复「刷新接口」移回顶部 header；rtp2httpd 配置移至频道列表导出区；恢复运营商频道名称自动内嵌至嗅探结果；
- `v0.8.3`：新增「频道列表」独立页面，运营商频道与嗅探结果均通过「导入到频道列表」汇入；导出功能移至频道列表，支持勾选特定频道导出；「定时 EPG」重做为 EPG 来源管理与定时刷新，删除 M3U 更新功能；运营商频道发现移除自动名称内嵌，「刷新接口」按钮移至嗅探整理；README 同步更新；
- `v0.8.2`：STB 开机捕获页面（运营商频道发现）；运营商频道表持久化；EPG 匹配覆盖所有已配置来源；批量写入 FCC 记录；多来源 EPG 索引合并；
- `v0.8.0`：STB 开机抓包 TCP 重组与频道解析（getchannellistHWCU.jsp / VSP JSON）；运营商频道导入自动批量写入 FCC；
- `v0.7.5`：流信息列点击弹出详情窗口；ffprobe 探测补充音频流、节目码率等字段；内置 EPG/台标来源支持删除与恢复；
- `v0.7.0–v0.7.4`：多项 Bug 修复与性能优化，包括 auto_probe_done 清空 Bug、截图协议修复、EPG 自动来源检测优化等；
- `v0.6.4–v0.6.9`：首页重做、双 Tab 工作区、定时任务、累积抓包模式、多种 EPG/台标来源管理等；
- `v0.6`：基于上述两个开源项目思路重构为统一 Web 工作台。
