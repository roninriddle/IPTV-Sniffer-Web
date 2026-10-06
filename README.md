# IPTV Sniffer Web

当前测试版本：`v1.3.6-test`；稳定版本：`v1.3.3`。本 README 已合并 `1.3.3` 之后的变更、兼容说明、审计边界与发布指南，作为当前统一文档。

面向飞牛 NAS、Linux Docker 和交换机镜像口场景的 IPTV 频道发现、订阅管理与播放工作台。它捕获机顶盒开机流量，将频道加入订阅，并提供可长期固定使用的播放器订阅地址。

### 原始抓包归档与备份

每次完成机顶盒开机捕获后，原始 PCAP 会持久保存到数据卷的 `stb-captures/` 目录；容器重启、重新部署或网页重置都不会删除它。频道发现页可按时间、大小与协议清单状态查看历史抓包，下载原始 PCAP 或单份备份包，也可经二次确认删除选中 PCAP 及对应协议清单。

PCAP 可能包含认证报文，因此默认不会纳入轻量 JSON 备份，也不会通过状态接口或应用日志展示。需要换容器或换机器时，在统一备份对话框中点“全选（完整迁移）”，即可一次保存全部状态、凭据、原始 PCAP 和协议清单。请只保存在受信任的本地存储中。

> 仅在你有权使用的网络和 IPTV 服务中部署。镜像口用于被动捕获，不能替代具备 IPTV 上游访问能力的播放设备。

## 1.3.6-test 最新变更

- 修复 [Issue #9](https://github.com/roninriddle/IPTV-Sniffer-Web/issues/9)：IPTV DHCP 成功不再硬编码要求 `10.*` 地址；`172.*` 等运营商分配的可用 IPv4 租约也能正确完成认证流程。
- 完整修复 [Issue #6](https://github.com/roninriddle/IPTV-Sniffer-Web/issues/6)：保护初始 MAC 恢复点；对 `1.3.3` 已覆盖的初始快照，可从经 `last_apply` 验证的 `pre_apply` 历史自动恢复并修复备份。
- MAC 恢复命令失败会立即报错；执行后再次读取接口 MAC，不再出现“未恢复却显示成功”。
- 测试版发布分支改为通用 `codex/v*-test` 规则；版本、Compose 和 bake 标签统一为 `1.3.6-test`。
- 原 `1.3.5-test` 审计文档和旧 GitHub 推送指南已合并到本 README，不再维护重复文件。

## 1.3.3 之后的合并更新

- 保留现有管理认证语义；管理端口仍需由部署环境提供访问边界。
- 修复认证初始恢复点、DHCP 多客户端关联、回看自动刷新、订阅旧地址、HLS 分片入口、设置校验和组播诊断。
- 自动回看刷新保留重启前的期限，失败也按配置周期重试；仅持久化调度时间，不保存会话密钥。
- 当前运营商地址与历史来源分开；稳定订阅 ID 和来源证据可经 JSON 往返保留。频道列表显示历史标记，来源提示可查看 PCAP／解析器版本。
- JSON／灾备使用统一 schema 和文件数量／解压大小边界；恢复先暂存所有模块，写入故障回滚设置、凭据和 PCAP。此机制保证同步写入失败回滚，不提供断电时的跨文件原子事务；回滚本身失败时保留私有 `.restore-*/journal.json` 供人工恢复。
- 媒体任务最多同时 4 个（也受 Waitress 工作线程数限制），其中直播最多 2、回看最多 2、截图最多 1、诊断最多 1。满载返回 429／Retry-After；诊断页可查看和取消任务。截图缓存 30 秒、32 项、16 MiB，检查 JPEG 边界并避免重复生成。
- 可单独配置“媒体接收网口”，用于本应用的直播、截图及主动组播检测；留空兼容原 IPTV 接口设置。外部 rtp2httpd 的上游仍由它自己的配置决定。
- 诊断分别展示线上流量、加入组播请求、实际 IGMP、socket 接收、TS 同步、FCC 端口／切换、RTSP 和播放器首帧。没有执行的阶段显示未验证。
- 频道解析器拆分为 CTC SetConfig、VSP、ChannelAcquire；[合成样本矩阵](tests/fixtures/protocols/README.md)列出范围。订阅、恢复和调度已抽成独立服务，前端设置按顺序保存并提供失败重试。

风险收敛补充：EPG／M3U 下载限制 16 MiB，gzip 展开限制 64 MiB；仅接收 HTTP(S)，重定向也检查协议。回看地址限制 RTSP／HTTP(S)，FFmpeg 禁用文件等非网络输入协议；保留 IPTV 私网访问，未建立目的地址 ACL。经典 PCAP 支持大小端、微秒和纳秒，解析限制 128 MiB、单包 1 MiB、TCP 重组 32 MiB／262144 段／4096 流。抓包超过 16 MiB 暂停实时重复解析，约每 3 秒检查 128 MiB 自动停抓阈值；该阈值可能因检查间隔超出，不是硬磁盘配额。归档达到 1 GiB 后拒绝新抓包，不自动删除原始 PCAP。

EPG 每分钟检查所选主源是否需要刷新，12 小时周期；切换设置主源后优先匹配新源，其余已缓存来源作为补充。移除了重复启动刷新。运营商导入三张表一并暂存和回滚，回看刷新检测并发修改后拒绝覆盖；网页静态导出使用独立批次，24 小时过期、最多 100 批。旧固定文件名下载接口保留兼容，但新网页下载走批次 URL。

日志出口统一脱敏，每份 5 MiB、保留 3 个旧文件；已有历史日志不会被自动重写。回看 FFmpeg 持续读取 stderr，仅保留 32 KiB 尾部；RTSP 按 Session timeout 发送保活，GET_PARAMETER 不支持时退回 OPTIONS。RTP 序号缺口与迟到／重复计数不等同于网络丢包率，目前不做乱序重排。运营商长期兼容性仍需实流验收。

本地验证：`python -m pip install --require-hashes -r requirements-dev.lock`，然后执行 `python -m pytest -q`、`node --test tests/settings-queue.test.cjs`、`python tools/check_release.py`。运行时依赖使用带 SHA-256 的 `requirements.lock`，基础镜像固定 digest。

CI 配置在 Linux/macOS 上运行回归，在 amd64/arm64 上构建镜像并生成 CycloneDX SBOM、执行 Trivy 扫描；可修复的 HIGH/CRITICAL 问题阻止发布。发布复用同一事件 SHA 的质量检查，校验标签与应用／Compose／bake 版本，再进行推送。发布状态以对应标签的 GitHub Actions 结果及 Docker Hub 镜像标签为准；测试版不更新稳定版 latest。

## 1.3.4-test 兼容说明

- `channels.json` 改为带 `_format`、`schema_version: 2` 和 `items` 数组的结构，以保留同名多线路。新版兼容导入旧格式；旧版本不能导入新格式，跨旧版本请使用 M3U。
- 灾备 ZIP 导出和导入统一限制为 10,000 个文件、解压后 2 GiB；超过限制的导出返回错误。超过 256 项的包需用新版恢复，旧版仍会拒绝。
- 经典 PCAP 支持大小端、微秒和纳秒；pcapng 仍需先转换为经典 PCAP。
- 同步写入失败可回滚，但恢复不提供断电情况下的跨文件原子事务。
- 合成样本和隔离测试不能替代真实运营商环境的长期运行、FCC、RTSP、组播回流及播放器兼容性验收。

## 能做什么

| 能力 | 说明 |
| --- | --- |
| 频道发现 | 从机顶盒开机流量中解析频道表、组播地址、FCC/FEC 与 DHCP / IPTV 认证摘要。 |
| 订阅中心 | 从频道库选择已订阅频道；主订阅、HLS 订阅和 EPG 地址固定不变，频道源、FCC 或回看地址刷新后自动生效。 |
| 频道库 | 按频道平铺浏览和筛选；可查看组播地址、EPG、HD / 4K、FCC、回看、时移与订阅状态，并批量管理订阅。 |
| 导入与备份 | 导出或按模块恢复全局备份；也可重新导入本应用导出的 M3U、`rtp2httpd` 源文件和 `channels.json`。 |
| 静态导出 | 按已订阅频道导出播放器最佳/全部来源、`rtp2httpd` 源文件，以及飞牛影视 HLS 列表。 |
| EPG 与台标 | 匹配 XMLTV EPG 和 TVlogo；支持缓存刷新与重新匹配。 |
| 链路诊断 | 检查 `rtp2httpd`、IGMP、组播回流、FCC、镜像口和常见配置问题。 |
| 实验性认证助手 | 展示并备份接口状态，辅助完成 IPTV DHCP 认证、恢复接口状态及排查 egress BPF 组播拦截。 |

## 快速开始

创建持久化目录并启动正式镜像：

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
  roninriddle/iptv-sniffer-web:1.3.3
```

访问 `http://宿主机IP:8787`。

当前测试镜像使用 `roninriddle/iptv-sniffer-web:1.3.6-test`；测试版不会覆盖稳定版 `latest`。

本地构建与运行：

```bash
mkdir -p data output
docker compose up -d --build
```

本地测试：

```bash
python -m pip install -r requirements-dev.txt
pytest -q
```

`data/` 保存频道、认证摘要、设置及回看信息；不要在升级或重建容器时删除它。`output/` 保存导出的播放列表和备份文件。

## 推荐拓扑与权限

```text
光猫 IPTV 口 → 交换机
  ├─ 机顶盒端口（镜像源）
  └─ Docker 宿主机网口（镜像目标）
```

在管理型交换机中将机顶盒端口设为镜像源、Docker 宿主机网口设为镜像目标。容器必须使用 host 网络；在 FNOS 的「高级设置 → 功能」中开启：

- `NET_RAW`：抓包和原始网络访问；
- `NET_ADMIN`：仅在使用实验性认证助手或接口路由调整时需要。

镜像口可以捕获和解析 STB 流量，但通常不能主动向 IPTV 上游发送 IGMP/FCC 请求。若要通过 `rtp2httpd` 主动播放，仍需有设备完成 IPTV 认证并可访问 IPTV 上游。

## 使用流程

1. 配置镜像口并以 host 网络启动容器。
2. 在「运营商频道」选择镜像网口、填写机顶盒 IP，开始捕获后重启机顶盒，再导入发现的频道。
3. 打开「订阅中心」；首次升级会自动把原有最佳频道加入订阅。到「频道库」勾选频道后，可加入或移出订阅。
4. 播放器优先使用固定的 `http://宿主机IP:8787/playlist.m3u`。需要兼容 HLS 时使用 `/playlist-hls.m3u`，XMLTV 使用 `/epg.xml`。这些地址不包含组播、RTSP、FCC 或认证材料。
5. `rtp2httpd` 优先直接订阅 `/playlist-rtp2httpd.m3u`（最佳频道）或 `/playlist-rtp2httpd-all.m3u`（全部线路）；仅在需要离线副本时再到「订阅中心 → 高级设置 / 静态导出」生成文件。
6. 需要主动播放时，在「IPTV 认证」先查看捕获到的认证摘要；确认网络隔离与回退方案后，才使用实验性一键认证。
7. 播放异常时，在「播放诊断」填写 `rtp2httpd` 地址和频道地址，依次检查上游认证、IGMP、FCC 和组播回流。

## 固定订阅地址

| 地址 | 用途 |
| --- | --- |
| `/playlist.m3u` | 推荐的动态主订阅，使用稳定的 `/live/<频道ID>` 与 `/catchup/<频道ID>`。 |
| `/playlist-all.m3u` | 与主订阅内容相同的兼容别名；保留给已保存该地址的播放器配置。 |
| `/playlist-hls.m3u` | 将直播入口改为本机 HLS 兼容地址。 |
| `/playlist-rtp2httpd.m3u` | 每个逻辑频道选择一条最佳线路，直接输出原始 `rtp://` 地址及 FCC/FEC 参数。 |
| `/playlist-rtp2httpd-all.m3u` | 输出频道库中的全部实际线路，适合由 rtp2httpd 自行管理来源。 |
| `/epg.xml` | 已配置的 XMLTV EPG 订阅源。 |

默认端口为 `8787`，例如播放器填写 `http://192.168.3.6:8787/playlist.m3u`。如果部署时显式设置了 `WEB_PORT=8788`，则相应改为 `http://192.168.3.6:8788/playlist.m3u`。频道组播地址发生变化时，应用以运营商频道表中的当前记录更新内部转发目标，播放器不需要重新导入订阅。

稳定直播入口会以 `307` 临时跳转到当前 `rtp2httpd` 来源，并禁止缓存该响应。APTV、TiviMate 与 OTT Navigator 建议各做一次实机验证；若某播放器错误缓存跳转地址，应改用其重新加载订阅或关闭该播放器的播放列表缓存选项。

## 导入、备份与恢复

「导入频道 / 恢复备份」是统一入口：

- 全局备份可按频道库、运营商频道表、认证快照和设置等模块选择恢复，并兼容旧版备份与单接口认证备份；
- 普通“应用与导出设置”备份不含 IPTV 密码或 DES/DES3 密钥；“密码与密钥（敏感）”默认不选，主动选择后才以明文写入；
- 旧版 `settings` 中的密码和密钥会在导入检查阶段迁移为独立敏感模块，未选择该模块时不会修改或清空本机凭据；
- 完整恢复回看应依次恢复应用设置和运营商频道表，再执行一次回看刷新；备份中的回看 Token 可能已经过期；
- 可导入本应用先前导出的播放器 M3U、`rtp2httpd` 源 M3U，以及 `channels.json`，用于恢复频道库；
- 恢复认证快照时，如果本机存在同名接口，默认不覆盖；请先确认接口和网络状态再手动处理。

备份对话框中，密码/密钥与历史 PCAP 默认不选。更换容器或机器时，点顶部“全选（完整迁移）”导出迁移 ZIP：

- ZIP 包含全部普通备份模块、明文 IPTV 密码与 DES/DES3 密钥、所有已归档 PCAP、脱敏协议清单、部署说明及 SHA-256 校验清单；
- 只有选中历史 PCAP 时才生成 ZIP，未选 PCAP 时仍导出轻量 JSON；导出与 ZIP 恢复都会连续弹出两次确认，无需输入确认文本；
- ZIP 恢复前会校验所有文件，拒绝额外路径、损坏内容及同名不同内容的 PCAP；
- 已存在且校验值相同的 PCAP 会安全跳过，新文件以仅容器用户可读写权限落盘；
- 灾备包不包含 Docker 镜像、应用日志、HLS 临时文件、EPG 缓存、运行中的 DHCP 进程及 Cookie/JSESSIONID；
- 新宿主机仍需使用 host 网络、`NET_ADMIN` / `NET_RAW`，将专用 IPTV 网卡设为 NetworkManager 不托管，并恢复 IPTV DHCP 认证与路由。完成后只需刷新回看，无需再让机顶盒重新开机抓包。

导入仅接受 IPv4 组播来源。不要把来源不明的备份或播放列表直接用于实验性认证操作。

## `rtp2httpd` 配置示例

`rtp2httpd` 默认端口为 `5140`。建议直接订阅应用提供的动态原始源列表：

```ini
external-m3u = http://iptv-sniffer-host:8787/playlist-rtp2httpd.m3u
external-m3u-update-interval = 300
```

若需要保留每个逻辑频道的所有备选线路，将地址改为 `/playlist-rtp2httpd-all.m3u`。这两个入口禁止缓存，并且不会输出可能导致递归代理的本站 `/live/` 地址。

`rtp2httpd` 也可以由 OpenWrt / ImmortalWrt 的 UCI 管理，配置文件是 `/etc/config/rtp2httpd`，没有 `.conf` 后缀。把它挂载进容器并在播放诊断中填入路径即可，解析器同时识别 INI 与 UCI 两种格式：

```uci
config instance
	option upstream_interface 'eth1'
	option upstream_interface_multicast 'eth1'
	option upstream_interface_fcc 'eth1'
	option external_m3u 'file://overlay/rtt2http/utm.m3u8'
	list listen '[::]:5140'
	list listen '192.168.100.1:5140'
```

UCI 支持引号内的 URL 与行尾注释。诊断只读取唯一启用实例，并识别高级接口模式；多实例歧义或外部配置文件模式会要求选择实际配置文件。

当前版本支持填写机顶盒 MAC：选择实际以太网抓包接口，捕获到目标 MAC 对应的 DHCP ACK 后会自动使用分配的 IP 解析频道；未捕获 ACK 时仍以填写的 IP 为准。MAC 与 IP 都未知时不能开始捕获。按 MAC 过滤不支持 `any`，按 IP 或 API 全量捕获仍可使用它。捕获诊断展示完整包数、实际解析 IP 和计数；SLL/SLL2 无法统计 MAC 时不会误报 MAC 填错。

UCI 的下划线选项名等价于 INI 的连字符键名（`upstream_interface_fcc` 即 `upstream-interface-fcc`），`list listen` 会作为监听地址一并读出。若配置文件能被读取却解析不出任何配置项，诊断会把「rtp2httpd 配置文件」标为问题项，而不是默认按「系统路由表」判为正常。

常见播放地址形态：

```text
http://rtp2httpd-host:5140/rtp/239.x.x.x:port
```

如果频道带 FCC/FEC 参数，应用会在对应来源中保留这些信息。导出前的多来源健康检查会优先选择可读取媒体数据的源；单源频道不会额外探测。

## 回看与 HLS

直播与回看是两条独立链路：直播走组播、`rtp2httpd` 或本机 HLS 转封装；回看依赖运营商频道表中的时移地址和有效认证信息。回看 Token 通常绑定账号、机顶盒信息与 IPTV 地址，直播可用不代表回看可用。

- 开启回看后，动态订阅会给支持回看的频道写入稳定的本机 `/catchup/<频道ID>` 地址；应用在后台更新实际回看地址，播放器不必重新导入。
- 遇到 403、超时或零字节时，优先检查 IPTV 认证 IP、账号/机顶盒字段、门户 Token 与到 IPTV 网段的路由。
- HLS 转封装按需启动 FFmpeg，空闲后自动停止。

## 安全与操作边界

实验性认证助手会修改选定接口的 MAC、IPv4 或 IPTV 相关路由，并提供初始状态备份和恢复。使用前请：

- 断开机顶盒 IPTV 线，避免 MAC 冲突；
- 确保 Web 管理页面经另一张网卡访问；
- 导出接口备份，确认恢复路径；
- 只在明确的测试窗口内操作。

项目不会主动替换默认路由，但错误的接口或路由配置仍可能导致宿主机失联。

## API 入口

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| `POST` | `/api/stb_discovery/start` | 开始 STB 开机捕获。 |
| `POST` | `/api/stb_discovery/import` | 导入发现到的运营商频道。 |
| `POST` | `/api/channels/import-export` | 导入已导出的 M3U 或 `channels.json`。 |
| `POST` | `/api/iptv-auth/backup-import` | 恢复接口认证备份。 |
| `POST` | `/api/backup/disaster-export` | 导出包含凭据与原始 PCAP 的完整灾备 ZIP。 |
| `POST` | `/api/backup/disaster-import` | 校验并恢复完整灾备 ZIP。 |
| `POST` | `/api/export` | 导出频道文件。 |
| `GET` | `/api/subscription` | 读取订阅频道清单和固定订阅入口。 |
| `POST` | `/api/subscription/candidates` | 加入、移出或重置已订阅频道。 |
| `GET` | `/playlist-rtp2httpd.m3u` | rtp2httpd 最佳频道原始 RTP 订阅。 |
| `GET` | `/playlist-rtp2httpd-all.m3u` | rtp2httpd 全部实际线路订阅。 |
| `POST` | `/api/diagnose` | 执行播放链路诊断。 |
| `POST` | `/api/catchup/refresh` | 刷新回看地址。 |

## 镜像与标签

- 测试版使用 `x.y.z-test`：发布同名 Git tag 和 Docker tag，不更新 `latest`。
- 正式版使用 `x.y.z`：发布同名 Git tag、Docker tag 和 `latest`。
- 发布前执行 `python tools/check_release.py --tag vX.Y.Z-test`，确认应用、Compose、bake 和 Git 标签一致。
- 日常代码合入 `main`；测试发布也可使用 `codex/vX.Y.Z-test` 分支。工作流构建 `linux/amd64` 与 `linux/arm64`，并推送 GitHub Container Registry 和 Docker Hub。
- 仓库 Actions 需要配置镜像仓库凭据；只使用 GitHub Secrets，禁止把用户名、密码或访问令牌写入仓库。

## 版本演进

近期版本保留逐项记录；更早的连续小版本按主题合并，完整提交历史见 [GitHub Releases](https://github.com/roninriddle/IPTV-Sniffer-Web/releases) 和 [提交记录](https://github.com/roninriddle/IPTV-Sniffer-Web/commits/main)。

| 版本 | 更新摘要 |
| --- | --- |
| `v1.3.6-test`（测试版） | 合并 1.3.3 之后的恢复、调度、来源、媒体容量、诊断、解析器与发布改进；修复非 `10.*` DHCP 租约误判及初始 MAC 恢复点被覆盖问题。 |
| `v1.3.3` | 增加可删除历史 PCAP 及协议清单的管理功能；完整灾备纳入原始抓包与敏感凭据的可选迁移；所有原“输入指定文本确认”改为连续两次弹窗确认；新增 rtp2httpd 最佳频道与全部线路的原始 RTP 动态订阅。 |
| `v1.3.2` | 重构频道库为单一平铺视图：分类、订阅状态与 FCC / 回看 / 时移 / 4K 快捷筛选；直接显示 HD / 4K、能力与订阅状态；移除分组页面并收敛批量操作。 |
| `v1.3.1` | 修正订阅别名语义：`/playlist-all.m3u` 明确为主订阅兼容别名；订阅清单纳入全局备份、恢复与清除；回看入口统一为稳定 `/catchup/<频道ID>`；时移长度统一使用分钟字段并兼容旧数据。 |
| `v1.3.0–v1.2.0` | 建立从机顶盒抓包、频道发现、认证辅助、频道导入与备份恢复，到稳定动态订阅、直播 / FCC / 回看 / 时移、HLS、EPG、播放诊断的一体化工作流；覆盖联通、北京联通与电信频道表适配，支持原始 PCAP 归档和回归测试。 |
| `v0.9.96–v0.6` | 收敛为交换机镜像口发现流程，加入 IPTV 认证助手、播放诊断与统一 Web 工作台。 |

## 参考与致谢

- [江苏电信 IPTV 回看源技术分析](https://www.right.com.cn/forum/thread-8314608-1-1.html)
- [`supzhang/get_iptv_channels`](https://github.com/supzhang/get_iptv_channels)
- [`zzzz0317/beijing-unicom-iptv-playlist`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist)
- [`zzzz0317/beijing-unicom-iptv-playlist-sniffer`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist-sniffer)
- [江苏电信 IPTV 认证与频道获取实践](https://www.right.com.cn/forum/thread-8314231-1-1.html)
- [自动抓取 IPTV 单播地址，实现时移回看（一）](https://www.bandwh.com/net/2571.html)：镜像抓包、DHCP Option60 / STB 标识、IPTV 网口与策略路由。
- [自动抓取 IPTV 单播地址，实现时移回看（二）](https://www.bandwh.com/net/2637.html)：`rtp2httpd`、FCC、M3U 回看时间参数与客户端兼容性。
- [`suzukua/iptv-cd-telecom`](https://github.com/suzukua/iptv-cd-telecom)：直播、FCC、回看和 APTV 等播放器的 M3U 集成参考。
- [IPTV 单播 RTSP 路由与回看实践（NGA）](https://ngabbs.com/read.php?tid=41933257&rand=555)：单播回看可达性与 IPTV 专网路由排障参考。
- [`CGG888/SrcBox`](https://github.com/CGG888/SrcBox)
- [`epg.51zmt.top`](https://epg.51zmt.top:8001/)
- [`wanglindl/TVlogo`](https://github.com/wanglindl/TVlogo)
