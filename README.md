# IPTV Sniffer Web v0.6.7

适用于 **OpenWrt / iStoreOS / 飞牛 NAS / 其它 Linux Docker 宿主机** 的 IPTV 组播嗅探、频道整理与 `rtp2httpd` 播放列表统一工作台。

v0.6 起基于以下两个开源项目的思路重构而来，并整合为单一 Web 图形化工作台：

- [`zzzz0317/beijing-unicom-iptv-playlist`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist)：参考其多源播放列表、代理地址转换与 M3U 生成思路；
- [`zzzz0317/beijing-unicom-iptv-playlist-sniffer`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist-sniffer)：参考其对机顶盒 `channelAcquire` 请求和 `UserToken` 的嗅探方式。

特别感谢以上项目作者的公开实现与整理工作。本项目在其基础上重新组织为容器化 Web 应用，在统一页面内完成组播候选发现、FCC 字段记录、UserToken 记录、截图预览、流信息自动识别、多格式导出和定时 EPG 清单更新。

另参考并致谢：

- [`CGG888/SrcBox`](https://github.com/CGG888/SrcBox)：参考其对 FCC 快速换台、UDP/RTP/IGMP 多协议流识别以及 XMLTV EPG 模糊匹配的工程实现思路，用于优化本项目的 FCC 嗅探正则（补充 `udp://` 支持）与搜索窗口扩展。

EPG 与台标来源参考并致谢：

- [`epg.112114.xyz`](https://epg.112114.xyz/)：XMLTV EPG 数据；
- [`epg.51zmt.top`](https://epg.51zmt.top:8001/)：老张的 EPG / 51zmt 数据；
- [`wanglindl/TVlogo`](https://github.com/wanglindl/TVlogo)：频道台标 M3U 资源。

---

## 核心特性

- 网页选择接口后实时嗅探 IPTV 组播流；
- 首页为使用说明，工作区分为“嗅探整理”和“定时 EPG”两个 tab；
- 定时任务支持按小时或按天更新指定 M3U 的 EPG 与台标清单；
- 自动过滤 mDNS、SSDP、链路控制组播、低包数和无效候选；
- 抓包文本中优先自动读取频道名和频道号，识别失败时保留人工补全；
- 抓包时解析 `ChannelFCCIP` / `ChannelFCCPort`，保存到 `data/fcc.json`；
- 抓包时识别 `POST /bj_stb/V1/STB/channelAcquire` 中的 `UserToken`，保存到 `data/playlist_token.json`；
- 抓包后使用 `ffprobe` 自动识别编码、分辨率、帧率和流内频道名，并生成 4K / 普通频道分组；
- 支持 XMLTV EPG 与 TVlogo 缓存匹配，导出时写入 `tvg-id` / `tvg-name` / `tvg-logo`；
- 有效候选右侧自动显示 `rtp2httpd` JPEG 截图，点击可放大；
- 预览入口使用 `rtp2httpd` 内置播放器 `/player` 和直连流地址；
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

该格式与 rtp2httpd 官方 URL 说明一致。

---

## 页面流程

1. 首页先确认抓包拓扑；
2. 进入“嗅探整理”，选择抓包接口；
3. 填写 `rtp2httpd` 地址、端口和路径模式；
4. 点击”继续抓包”，在机顶盒上逐个切台；每次抓包结束后可再次点击”继续抓包”累积频道，”重置候选流”可清零重来；
5. 等待候选流、自动频道名、FCC、token、截图、流信息和 EPG 匹配结果自动出现在页面；
6. 自动频道名不准确时，在频道名称输入框中人工修正；
7. 保存草稿并生成播放列表；
8. 进入“定时 EPG”，填写要更新的 M3U 地址，按小时或按天生成更新后的 `scheduled-epg.m3u`。

未命名频道不会进入导出文件。

定时 EPG 任务只读取指定的 M3U，刷新 XMLTV EPG 与台标匹配结果，然后输出 `scheduled-epg.m3u`；它不会自动抓包，也不会改变频道播放地址。

---

## 导出文件

文件会生成到 `output/`：

- `channels-direct.m3u`：可直接导入播放器的 HTTP 播放地址；
- `channels-rtp2httpd-source.m3u`：保留 `rtp://` / `udp://` 源地址，可作为 rtp2httpd `external-m3u`；
- `scheduled-epg.m3u`：定时 EPG 任务输出的更新后 M3U；
- `channels.json`：保留 `live` 源结构与 EPG 字段，便于二次转换或迁移；
- `channels.txt`：常见 IPTV 软件可用的 TXT 格式；
- `channels.csv`：频道、清晰度、EPG、FCC、源地址和播放地址明细。

M3U / TXT 会保留原始分类，并额外生成：

```text
4K高清
普通频道
```

---

## 持久化文件

- `data/settings.json`：页面默认参数；
- `data/channels.json`：频道草稿与探测结果；
- `data/discovered_channels.json`：抓包自动识别到的频道名与频道号；
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
| GET | `/api/metrics` | 运行指标、自动频道名、FCC 数、token 数、EPG 状态 |
| GET | `/api/interfaces` | 获取可抓包接口 |
| GET | `/api/settings` | 获取默认设置 |
| POST | `/api/settings` | 保存默认设置 |
| GET | `/api/schedule` | 获取定时任务状态 |
| POST | `/api/schedule` | 保存或停用定时 EPG 任务 |
| POST | `/api/schedule/run-now` | 立即更新一次指定 M3U 的 EPG 清单 |
| POST | `/api/capture/start` | 继续抓包（不清空已发现流，可多次追加） |
| POST | `/api/capture/stop` | 停止抓包 |
| POST | `/api/capture/reset` | 重置候选流（清空所有已发现流） |
| GET | `/api/streams` | 获取候选流 |
| GET | `/api/fcc` | 获取 FCC 记录 |
| GET | `/api/stb-token` | 获取最近的 channelAcquire token 摘要 |
| GET | `/api/discovery` | 获取自动识别的频道名记录 |
| GET | `/api/epg/status` | 获取 EPG 缓存状态 |
| POST | `/api/epg/refresh` | 刷新 XMLTV EPG 缓存 |
| POST | `/api/channels/save` | 保存频道草稿 |
| POST | `/api/probe` | 内部自动流信息识别 |
| POST | `/api/probe/batch` | 内部批量流信息识别 |
| POST | `/api/export` | 生成导出文件 |
| GET | `/api/download/<filename>` | 下载导出文件 |
| GET | `/api/logs` | 获取实时日志 |
| GET | `/api/logs/download` | 下载完整日志 |

---

## 环境变量

```text
RTP2HTTPD_HOST=
RTP2HTTPD_PORT=5140
EPG_URL=https://epg.112114.xyz/pp.xml.gz
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

- `v0.6.7`：新增浏览器直接播放组播流（ffmpeg → HLS 代理，无需 rtp2httpd）；EPG/台标来源支持自助增删；新增"同 IP 保留最多包流"过滤；EPG 自动探测最优来源；抓包期间加快页面刷新频率；rtp2httpd 配置移至导出区；修复 HTML 属性中 Unicode 智能引号导致 DOM 查询失效的 Bug；
- `v0.6.6`：修复 CCTV/卫视频道被误归入"其它频道"的分类 Bug（识别名称后优先用名称重新分类）；截图改为 Flask + ffmpeg 直接从组播流抓帧，无需 rtp2httpd 即可显示；台标来源改为自动/手动切换，默认自动隐藏详细配置；频道列表改为按最新发现倒序排列；新增"删除勾选"功能；版本更新检测徽章；
- `v0.6.5`：抓包改为"继续抓包"累积模式，多次 30 秒抓包的频道自动叠加，"重置候选流"清零；修复跨次抓包缓冲区污染、EPG 分类双重赋值、output_name 边界校验错误和变量名遮蔽等 Bug；删除从未被调用的 auto-classify 端点；前端启动改为并行加载；
- `v0.6.4`：重做首页与双 tab 工作区，定时任务改为指定 M3U 的 EPG/台标清单更新；抓包后自动识别流信息并用流内名称或 EPG 名称回填频道名，移除手动检测按钮；
- `v0.6.3`：整理 EPG 与台标来源，优化页面比例、日志侧栏与编辑时表格刷新行为；
- `v0.6.2`：优化自动抓流补全链路，抓包自动读取频道名和频道号，后台自动识别流技术信息，并支持 XMLTV EPG 缓存、自动匹配和导出字段补全；
- `v0.6.1`：新增按小时/按天的自动嗅探定时任务；README 明确重构来源与致谢；JSON 导出文件改为 `channels.json`；
- `v0.6`：基于上述两个开源项目思路重构为统一 Web 工作台，新增 channelAcquire UserToken 记录、JSON 导出，并整合 FCC、截图预览和 rtp2httpd 外部 M3U 工作流；
- `v0.5.3`：默认 rtp2httpd 5140 端口，左侧常驻日志面板，使用 rtp2httpd 播放器/截图能力；
- `v0.5.2`：前移噪声组播过滤，失败未命名流自动隐藏，优化页面比例；
- `v0.5.1`：优化候选流自动过滤、表格布局和两种 M3U 导出；
- `v0.5`：新增 4K / 普通频道检测与清晰度汇总导出。
