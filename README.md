# IPTV Sniffer Web v0.8.3

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

```bash
mkdir -p data output
docker compose up -d --build
```

打开：

```text
http://宿主机IP:8787
```

容器需要能看到机顶盒 IPTV 流量。推荐使用管理型交换机镜像机顶盒端口到 Docker 宿主机，或让 IPTV 流量真实经过运行 Docker 的 OpenWrt / iStoreOS。

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

---

## 页面流程

1. **运营商频道发现（推荐）**：填写机顶盒 IP，点击「开始捕获」后重启机顶盒；系统自动解析频道表，点击「导入到频道列表」；
2. **嗅探整理（可选补充）**：选择抓包网卡，填写 `rtp2httpd` 地址、端口和路径模式；点击「继续抓包」切台；点击「导入到频道列表」；
3. 进入「频道列表」，勾选需要的频道，点击「生成播放列表」下载各格式文件；
4. 在「定时 EPG」中配置定时刷新计划，保持 EPG 信息持续更新。

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

- `v0.8.3`：新增「频道列表」独立页面，运营商频道与嗅探结果均通过「导入到频道列表」汇入；导出功能移至频道列表，支持勾选特定频道导出；「定时 EPG」重做为 EPG 来源管理与定时刷新，删除 M3U 更新功能；运营商频道发现移除自动名称内嵌，「刷新接口」按钮移至嗅探整理；README 同步更新；
- `v0.8.2`：STB 开机捕获页面（运营商频道发现）；运营商频道表持久化；EPG 匹配覆盖所有已配置来源；批量写入 FCC 记录；多来源 EPG 索引合并；
- `v0.8.0`：STB 开机抓包 TCP 重组与频道解析（getchannellistHWCU.jsp / VSP JSON）；运营商频道导入自动批量写入 FCC；
- `v0.7.5`：流信息列点击弹出详情窗口；ffprobe 探测补充音频流、节目码率等字段；内置 EPG/台标来源支持删除与恢复；
- `v0.7.0–v0.7.4`：多项 Bug 修复与性能优化，包括 auto_probe_done 清空 Bug、截图协议修复、EPG 自动来源检测优化等；
- `v0.6.4–v0.6.9`：首页重做、双 Tab 工作区、定时任务、累积抓包模式、多种 EPG/台标来源管理等；
- `v0.6`：基于上述两个开源项目思路重构为统一 Web 工作台。
