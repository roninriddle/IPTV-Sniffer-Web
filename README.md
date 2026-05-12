# IPTV Sniffer Web v0.5.3

适用于 **OpenWrt / iStoreOS / 飞牛 NAS / 其它 Linux Docker 宿主机** 的 IPTV 组播频道抓包、流信息检测与播放列表生成工具。

容器启动后，通过网页完成：抓包、实时日志查看、频道命名分类、4K 检测、草稿保存，以及 `m3u / txt / csv` 导出。导出结果可用于 `rtp2httpd`。

---

## v0.5 新增

- 新增 **流信息检测 / 4K 判定**；
- 每条候选流可单独点击“检测流信息”；
- 支持对勾选流执行批量检测；
- 使用 `ffprobe` 读取：
  - 视频编码；
  - 分辨率；
  - 帧率；
  - 清晰度分组；
- 判定规则：
  - `宽度 >= 3840` 且 `高度 >= 2160` → `4K高清`；
  - 已识别视频流但未达到 4K → `普通频道`；
  - 未成功探测 → `未识别`；
- 导出时保留原始分类，同时额外复制到两个清晰度汇总分组：
  - `4K高清`
  - `普通频道`
- `m3u / txt / csv` 三种格式均带上新的清晰度分组结果。

> 4K 检测依赖当前流仍然可访问。执行检测时，建议保持机顶盒正在播放对应频道；若该组播流已经停止下发，检测可能失败。

---

## 核心特性

### 实时抓包与可视化

- 网页选择抓包网卡；
- 支持定时抓包与手动停止；
- 实时统计候选组播流、包计数、有效候选数；
- 直接解析 `tcpdump` 实时输出，不必等待抓包结束才看到结果；
- 页面实时刷新状态与候选流列表。

### 日志与状态

- 右侧抽屉式 **实时日志** 面板；
- 显示启动、接口选择、抓包状态、发现组播流、流信息检测、导出结果与异常；
- 支持下载完整日志文件；
- 提供 `/api/health` 与 `/api/metrics`。

### 频道整理

- 为每个候选流填写频道名称；
- 分类：央视频道 / 卫视频道 / 其它频道；
- 名称留空则不导出；
- 支持按名称自动分类；
- 支持批量给勾选频道设置分类；
- 频道草稿持久化到 `data/channels.json`；
- 流探测结果随频道草稿持久化。

### 流信息检测

- 检测编码、分辨率、帧率；
- 自动判断 4K / 普通频道；
- 单条检测、批量检测；
- 检测失败会回填原因并记录日志。

### 文件导出

- 输出 `channels.m3u`；
- 输出 `channels.txt`；
- 输出 `channels.csv`；
- 原始排序规则：央视频道 → 卫视频道 → 其它频道；
- 同组内按频道名称自然排序；
- 额外导出清晰度汇总分组：
  - 4K高清；
  - 普通频道；
- 同一频道会保留原分类，并在清晰度汇总分组中额外复制一份。

### 仓库化与容器化

- 版本号：`v0.5`；
- 模块化 Python 代码结构；
- Docker Compose 一键启动；
- Docker Healthcheck；
- Buildx 多架构配置：`linux/amd64` / `linux/arm64`；
- GitHub Actions：CI 构建检查与 tag 发布到 GHCR 的示例工作流。

---

## 使用前必读

本工具只能抓取 **Docker 宿主机实际可见的 IPTV 流量**。

### 方案一：管理型交换机镜像口抓包（推荐）

```text
光猫 IPTV 口 → 交换机 A 口
交换机 B 口 → 机顶盒
交换机 C 口 → 抓包设备 / Docker 宿主机
```

推荐交换机配置：

```text
源端口：B 口（机顶盒所在端口）
目标端口：C 口（抓包设备所在端口）
镜像方向：Both / 双向
```

补充说明：

- **首选镜像 B 口**，因为它直接对应机顶盒实际收发的 IPTV 流量；
- **A 口也可以镜像到 C 口**，但通常 B 口更利于判断哪些流真正送到了机顶盒；
- 若交换机支持镜像源端口方向选择，建议使用双向镜像。

### 方案二：没有管理型交换机

```text
光猫 IPTV 口
      ↓
OpenWrt / iStoreOS
      ↓
机顶盒
```

要求：

- IPTV 流量必须真实经过 OpenWrt / iStoreOS；
- Docker 容器运行在这台设备上；
- 在网页中选择实际承载 IPTV 流量的接口抓包。

### 典型不可用场景

```text
光猫 IPTV 口 → 机顶盒
普通 LAN → 飞牛 NAS / Docker
```

NAS / Docker 不在 IPTV 链路里，也没有镜像流量，通常抓不到频道地址。

---

## 快速开始

### 1. 克隆仓库

```bash
git clone <你的 GitHub 仓库地址>
cd iptv-sniffer-web
```

### 2. 启动容器

```bash
mkdir -p data output
docker compose up -d --build
```

或使用：

```bash
chmod +x start.sh stop.sh
./start.sh
```

### 3. 打开网页

```text
http://宿主机IP:8787
```

示例：

```text
http://192.168.10.2:8787
```

---

## Docker 权限说明

容器需要直接监听宿主机可见网卡，因此 Compose 中必须保留：

```yaml
network_mode: host
cap_add:
  - NET_ADMIN
  - NET_RAW
```

不建议默认使用 `privileged: true`。仅在某些 NAS Docker 管理界面无法配置 `cap_add` 时，才考虑临时改成特权容器。

---

## 网页使用流程

1. 阅读首页接线说明；
2. 选择抓包接口；
3. 填写 `rtp2httpd` 地址和端口；
4. 选择 `/rtp/` 或 `/udp/`；
5. 点击“开始抓包”；
6. 在机顶盒上逐个切换频道，每个频道建议停留 2–3 秒；
7. 点击“停止抓包”或等待定时结束；
8. 为候选流填写频道名称并选择分类；
9. 保持机顶盒仍在播放对应频道时，执行单条或批量“检测流信息”；
10. 保存频道草稿；
11. 生成并下载 `m3u / txt / csv`。

---

## 4K 检测说明

检测入口位于候选流表格中：

- 单条检测：点击某一行的“检测流信息”；
- 批量检测：勾选多行后点击“检测勾选流”。

检测结果包含：

- 编码；
- 分辨率；
- 帧率；
- 清晰度分组。

### 判定规则

```text
3840×2160 或更高 → 4K高清
已识别视频流但未达到 4K → 普通频道
未获取到有效视频流参数 → 未识别
```

### 检测失败的常见原因

- 该组播流已经停止下发；
- 机顶盒当前已经切走该频道；
- 采样窗口内没有等到足够的 PAT / PMT / 视频参数；
- 运营商流封装或网络环境导致 `ffprobe` 无法及时解析。

可尝试：

- 保持机顶盒停留在该频道；
- 重新点击检测；
- 必要时重新抓包后立即检测。

---

## 导出行为

### M3U

每个频道原本属于：

- 央视频道；
- 卫视频道；
- 其它频道。

在 v0.5 中，若该频道已成功探测，还会额外复制到：

- 4K高清；
- 普通频道。

### TXT

除原有分组外，会继续追加：

```text
4K高清,#genre#
普通频道,#genre#
```

### CSV

新增字段：

- 展示分组；
- 原始分类；
- 清晰度分组；
- 分辨率；
- 编码；
- 帧率。

同一频道会出现：

1. 一行原始分类；
2. 一行清晰度汇总分组。

---

## 项目结构

```text
iptv-sniffer-web/
├── app.py
├── config.py
├── models.py
├── utils.py
├── services/
│   ├── capture_service.py
│   ├── export_service.py
│   ├── log_service.py
│   ├── probe_service.py
│   └── storage_service.py
├── templates/
│   └── index.html
├── static/
│   ├── app.js
│   └── style.css
├── data/
│   └── .gitkeep
├── output/
│   └── .gitkeep
├── Dockerfile
├── docker-compose.yml
├── docker-bake.hcl
├── requirements.txt
├── start.sh
├── stop.sh
├── .dockerignore
├── .gitignore
└── .github/workflows/
    ├── docker-ci.yml
    └── docker-publish.yml
```

---

## 持久化文件

### `data/settings.json`

保存网页默认参数，例如：

- 默认接口；
- `rtp2httpd` 地址；
- 端口；
- `/rtp/` 或 `/udp/`；
- 默认抓包时长。

### `data/channels.json`

保存已命名的频道草稿，以及探测结果：

- 编码；
- 分辨率；
- 帧率；
- 4K / 普通频道判定。

### `data/app.log`

磁盘完整日志文件。网页中的“下载完整日志”即下载此文件。

### `output/`

导出文件：

- `channels.m3u`
- `channels.txt`
- `channels.csv`

---

## API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/version` | 应用名称与版本 |
| GET | `/api/health` | 健康检查、抓包依赖与 ffprobe 检查 |
| GET | `/api/metrics` | 运行指标 |
| GET | `/api/interfaces` | 获取可抓包接口 |
| GET | `/api/settings` | 获取保存的默认设置 |
| POST | `/api/settings` | 保存默认设置 |
| POST | `/api/capture/start` | 开始抓包 |
| POST | `/api/capture/stop` | 停止抓包 |
| POST | `/api/capture/reset` | 重置候选流 |
| GET | `/api/status` | 获取当前抓包状态 |
| GET | `/api/streams` | 获取实时候选组播流 |
| GET | `/api/channels` | 获取已保存频道草稿 |
| POST | `/api/channels/save` | 保存频道草稿 |
| POST | `/api/channels/auto-classify` | 按名称自动分类 |
| POST | `/api/probe` | 单条流信息检测 |
| POST | `/api/probe/batch` | 批量流信息检测 |
| POST | `/api/export` | 生成导出文件 |
| GET | `/api/download/<filename>` | 下载导出文件 |
| GET | `/api/logs` | 获取实时日志 |
| POST | `/api/logs/clear-memory` | 清空页面日志缓存 |
| GET | `/api/logs/download` | 下载磁盘完整日志 |

---

## 可调环境变量

```text
PROBE_TIMEOUT_SECONDS=10
PROBE_ANALYZE_DURATION_US=8000000
PROBE_SIZE_BYTES=8000000
PROBE_BUFFER_SIZE=131072
```

说明：

- `PROBE_TIMEOUT_SECONDS`：单次流探测总超时；
- `PROBE_ANALYZE_DURATION_US`：`ffprobe` 分析时长；
- `PROBE_SIZE_BYTES`：`ffprobe` 分析缓冲大小；
- `PROBE_BUFFER_SIZE`：UDP 接收缓冲参数。

---

## 版本

- `v0.5.3`：默认切换为 rtp2httpd 5140 端口，优化左侧常驻日志面板，改用 rtp2httpd 内置播放器/截图能力进行预览，并为有效候选新增可放大的截图缩略图；
- `v0.5.2`：前移噪声组播过滤，预览/探测失败的未命名流自动隐藏，并优化页面整体比例与自适应布局；
- `v0.5.1`：优化候选流自动过滤、表格布局、页面内预览播放器，并拆分直连 / rtp2httpd 源地址两种 M3U 导出；
- `v0.5`：新增 4K / 普通频道检测与清晰度汇总导出；
- `v0.4`：Web UI、实时日志、版本控制、健康检查、指标接口与仓库化结构。
