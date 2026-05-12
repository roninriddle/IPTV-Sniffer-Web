# IPTV Sniffer Web v0.6

适用于 **OpenWrt / iStoreOS / 飞牛 NAS / 其它 Linux Docker 宿主机** 的 IPTV 组播嗅探、频道整理与 `rtp2httpd` 播放列表统一工作台。

v0.6 参考了 `zzzz0317/beijing-unicom-iptv-playlist` 的多源播放列表生成思路，以及 `zzzz0317/beijing-unicom-iptv-playlist-sniffer` 对机顶盒 `channelAcquire` 请求的嗅探方式：同一页面内完成组播候选发现、FCC 字段记录、UserToken 记录、截图预览、流信息检测和多格式导出。

---

## 核心特性

- 网页选择接口后实时嗅探 IPTV 组播流；
- 自动过滤 mDNS、SSDP、链路控制组播、低包数和无效候选；
- 抓包时解析 `ChannelFCCIP` / `ChannelFCCPort`，保存到 `data/fcc.json`；
- 抓包时识别 `POST /bj_stb/V1/STB/channelAcquire` 中的 `UserToken`，保存到 `data/playlist_token.json`；
- 使用 `ffprobe` 检测编码、分辨率、帧率，并生成 4K / 普通频道分组；
- 有效候选右侧自动显示 `rtp2httpd` JPEG 截图，点击可放大；
- 预览入口使用 `rtp2httpd` 内置播放器 `/player` 和直连流地址；
- 导出直连 M3U、rtp2httpd 外部源 M3U、ZZ 风格 JSON、TXT、CSV。

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

1. 选择抓包接口；
2. 填写 `rtp2httpd` 地址、端口和路径模式；
3. 点击“开始嗅探”，在机顶盒上逐个切台；
4. 等待候选流、FCC 和 token 信息出现在页面；
5. 为有效候选填写频道名称和分类；
6. 对勾选项执行流信息检测；
7. 保存草稿并生成播放列表。

未命名频道不会进入导出文件。

---

## 导出文件

文件会生成到 `output/`：

- `channels-direct.m3u`：可直接导入播放器的 HTTP 播放地址；
- `channels-rtp2httpd-source.m3u`：保留 `rtp://` / `udp://` 源地址，可作为 rtp2httpd `external-m3u`；
- `channels-zz.json`：保留 `live` 源结构，便于二次转换或迁移；
- `channels.txt`：常见 IPTV 软件可用的 TXT 格式；
- `channels.csv`：频道、清晰度、FCC、源地址和播放地址明细。

M3U / TXT 会保留原始分类，并额外生成：

```text
4K高清
普通频道
```

---

## 持久化文件

- `data/settings.json`：页面默认参数；
- `data/channels.json`：频道草稿与探测结果；
- `data/fcc.json`：按组播地址记录的 FCC 服务器；
- `data/playlist_token.json`：嗅探到的 channelAcquire UserToken；
- `data/app.log`：完整运行日志。

---

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/version` | 应用名称与版本 |
| GET | `/api/health` | 抓包与 ffprobe 运行检查 |
| GET | `/api/metrics` | 运行指标、FCC 数、token 数 |
| GET | `/api/interfaces` | 获取可抓包接口 |
| GET | `/api/settings` | 获取默认设置 |
| POST | `/api/settings` | 保存默认设置 |
| POST | `/api/capture/start` | 开始嗅探 |
| POST | `/api/capture/stop` | 停止嗅探 |
| POST | `/api/capture/reset` | 重置候选流 |
| GET | `/api/streams` | 获取候选流 |
| GET | `/api/fcc` | 获取 FCC 记录 |
| GET | `/api/stb-token` | 获取最近的 channelAcquire token 摘要 |
| POST | `/api/channels/save` | 保存频道草稿 |
| POST | `/api/probe` | 单条流信息检测 |
| POST | `/api/probe/batch` | 批量流信息检测 |
| POST | `/api/export` | 生成导出文件 |
| GET | `/api/download/<filename>` | 下载导出文件 |
| GET | `/api/logs` | 获取实时日志 |
| GET | `/api/logs/download` | 下载完整日志 |

---

## 环境变量

```text
RTP2HTTPD_HOST=
RTP2HTTPD_PORT=5140
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

- `v0.6`：统一 Web 工作台，新增 channelAcquire UserToken 记录、ZZ JSON 导出，并整合 FCC、截图预览和 rtp2httpd 外部 M3U 工作流；
- `v0.5.3`：默认 rtp2httpd 5140 端口，左侧常驻日志面板，使用 rtp2httpd 播放器/截图能力；
- `v0.5.2`：前移噪声组播过滤，失败未命名流自动隐藏，优化页面比例；
- `v0.5.1`：优化候选流自动过滤、表格布局和两种 M3U 导出；
- `v0.5`：新增 4K / 普通频道检测与清晰度汇总导出。
