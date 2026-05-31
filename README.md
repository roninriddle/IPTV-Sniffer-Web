# IPTV Sniffer Web v0.9.93

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

| 功能 | 说明 |
|---|---|
| **运营商频道发现** | 填写机顶盒 IP，重启机顶盒，自动从 STB 开机流量解析频道表（名称/组播/FCC/FEC）；同步捕获 DHCP 认证信息（MAC/IP/Option60/Option61/Option125） |
| **频道线路组** | 同名频道自动归组（tvg-id > 规范化名称），4K>HD>SD>未识别优先级自动选主源；支持手动设为主源；分组视图展开备线 |
| **播放链路诊断** | 检测 rtp2httpd 可达性、FCC 响应、认证状态与配置完整性，给出排查结论 |
| **四档导出** | `channels-best.m3u`（主源直连）/ `channels-all.m3u`（全部直连）/ `channels-rtp2httpd-best.m3u`（主源源地址）/ `channels-rtp2httpd-all.m3u`（全部源地址）；旧文件名兼容保留 |
| **嗅探整理** | 实时嗅探组播流，ffprobe 自动识别 4K/1080p/720p，截图预览，支持 802.1Q/QinQ VLAN |
| **EPG & 台标** | XMLTV EPG + TVlogo 缓存匹配，定时自动刷新，导出写入 tvg-id/tvg-logo |
| **iStoreOS 部署向导** | 读取宿主机 `/etc/config/network`，生成 eth0 被动抓包 UCI 脚本（proto=none）；支持 SLL/SLL2 pcap |
| **顶部认证摘要栏** | 捕获到 DHCP 信息后顶部显示 MAC/IPTV IP/网关/UserToken/FCC 状态 |

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

**本地测试**

```bash
python -m pip install -r requirements-dev.txt
pytest -q
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

- `channels-best.m3u`：每个频道组只导出自动选择的主线路，适合直接导入播放器；
- `channels-all.m3u`：导出所有线路，每条线路只出现一次，适合人工比较多清晰度/多线路；
- `channels-rtp2httpd-best.m3u`：主线路的 `rtp://` / `udp://` 源文件，可作为 rtp2httpd `external-m3u`；
- `channels-rtp2httpd-all.m3u`：全部线路的 rtp2httpd 源文件，适合保留备线；
- `channels-direct.m3u`：兼容旧文件名，内容同 `channels-best.m3u`；
- `channels-rtp2httpd-source.m3u`：兼容旧文件名，内容同 `channels-rtp2httpd-best.m3u`；
- `channels.json`：保留 `live` 源结构与 EPG 字段，便于二次转换或迁移；
- `channels.txt`：常见 IPTV 软件可用的 TXT 格式；
- `channels.csv`：频道、清晰度、EPG、FCC、源地址和播放地址明细。

`best` 每个频道组只保留一条主线路；`all` 保留同名频道的所有备选线路，但不再重复写入“原分类 + 清晰度分类”两份 M3U 条目。

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
RTP2HTTPD_CONFIG_PATH=/host/vol1/@appconf/rtp2httpd/rtp2httpd.conf
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

- `v0.9.93`：播放诊断改为分层输出（rtp2httpd / 网络接口 / 接入认证 / FCC / 组播链路 / 频道资产）；支持读取 rtp2httpd 配置文件并展示 upstream-interface / external-m3u；频道线路分组视图增强主源、备线、技术信息、FCC/FEC 与最近状态；嗅探页明确自动抓流整理流程；
- `v0.9.92`：修复嗅探整理页横向溢出；修复实时日志抽屉打开后仍停在屏幕外的问题；明确 best/all 导出文件语义；
- `v0.9.91`：修复播放诊断页初始化——从 DOM 表单（httpHost/httpPort）读取配置，不再依赖未初始化的 state.settings；刷新网卡按钮移至「运营商频道」操作栏；README 整理合并历史版本条目；
- `v0.9.9`：首页拓扑三场景统一（镜像口 / R4S eth0 被动抓包 / IGMP Proxy）；首页与部署向导合并；新增频道线路组（tvg-id > 规范化名称归组，评分自动选主源，支持手动设为主源，分组视图展开备线）；导出重构为四档（best/all × 直连/源地址）；旧文件名别名保留；
- `v0.9.8`：STB 开机捕获同步捕获 DHCP（UDP 67/68），解析机顶盒 MAC / IPTV IP / 网关 / Option 60/61/125；结果展示在「运营商频道」→「机顶盒认证信息」卡片；顶部摘要栏显示认证与频道状态；新增播放链路诊断页（rtp2httpd 可达性 / FCC 响应 / 认证状态 / 配置检查 / 排查结论）；导航重排：首页/部署向导 → 运营商频道 → 频道线路 → 播放诊断 → 嗅探整理 → 定时EPG；
- `v0.9.7`：运营商导入自动从 `is_hd` 推导清晰度分组；4K 识别修复（is_hd 推导的高清不再阻止 ffprobe 重探；enrich 时优先用实测宽高重算 quality_group）；频道列表新增名称/分类/清晰度筛选行；
- `v0.9.6`：修复部署向导 .data 双重解包；修复 CUSetConfig 单/双引号解析回归；属性值兼容 key="val" 与 key='val'；新增 29 项回归测试（Ethernet/SLL/SLL2 pcap、频道表解析、FEC/FCC URL、UCI 解析）；
- `v0.9.5`：iStoreOS/OpenWrt 被动抓包部署向导（读取 `/host/etc/config/network`，生成 UCI 脚本）；STB pcap 兼容 SLL/SLL2（DLT=113/276）；CUSetConfig 双引号格式支持；FEC 端口全链路贯通；候选流预览地址带 fec_port 和 fcc_type；
- `v0.9.4`：STB 开机捕获支持 802.1Q/QinQ VLAN Tagged 帧；FCC 协议类型（telecom/huawei）导出追加 `&fcc-type=VALUE`；FEC 端口全链路；
- `v0.9.0–v0.9.3`：EPG 多来源优先级修复；TCP 重组 seq 排序去重；频道列表快照；定时 EPG 页内联来源管理；catchup/回看属性导出；
- `v0.6–v0.8.5`：统一 Web 工作台初版（v0.6）；STB 开机抓包 TCP 重组与频道解析（v0.8）；运营商频道发现页面（v0.8.2）；频道列表独立页面、导出区移至频道列表（v0.8.3）；EPG/台标来源管理（v0.7–v0.8）；
