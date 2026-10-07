# IPTV Sniffer Web

从机顶盒开机流量中发现频道，管理订阅、EPG 与回看，并提供固定的播放器订阅地址。适用于飞牛 NAS、Linux Docker 和交换机镜像口环境。

当前测试版：**1.3.8-test**；稳定版：**1.3.3**。代码统一维护在 `main`，1.3.3 之后的改进统一收录于本版。

## 快速开始

在 Linux 宿主机上创建持久化目录，启动当前测试版：

```bash
mkdir -p data output
docker run -d \
  --name iptv-sniffer-web \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -e TZ=Asia/Shanghai \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/output:/app/output" \
  roninriddle/iptv-sniffer-web:1.3.8-test
```

访问 `http://宿主机IP:8787`。需要稳定版时，将镜像标签改为 `1.3.3`；`latest` 仍指向稳定版，测试版不会覆盖它。镜像支持 `linux/amd64` 和 `linux/arm64`。

`data/` 保存频道、设置、认证材料与历史抓包；`output/` 保存导出文件。升级前请从网页导出备份，并保留这两个目录。源码构建可使用 `docker compose up -d --build`。

## 网络准备

```text
光猫 IPTV 口 → 交换机
  ├─ 机顶盒端口（镜像源）
  └─ Docker 宿主机网口（镜像目标）
```

将机顶盒端口流量镜像到宿主机抓包网口，容器使用 host 网络。飞牛容器的高级设置中，`NET_RAW` 用于抓包；只有使用实验性认证助手或调整接口路由时才需要 `NET_ADMIN`。

镜像口可以被动捕获流量，但通常不能主动向 IPTV 上游发送 IGMP/FCC 请求。实际播放还需要完成 IPTV 认证、能访问上游的设备与链路。请仅在你有权使用的网络和 IPTV 服务中部署。

## 发现频道并播放

1. 进入「运营商频道」，选择「实时抓包」并在开始后重启机顶盒；也可以选择「导入抓包」，上传爱快、OpenWrt 或 Wireshark 生成的 PCAP / PCAPNG。
2. 停止并分析，将发现的频道导入频道库。诊断面板可查看完整包数、解析 IP 和频道解析结果。
3. 在频道库勾选频道，加入「订阅中心」。同名多线路、FCC/FEC、回看、时移与来源信息随频道保存。
4. 在播放器中添加下表的固定订阅地址。运营商地址或回看 Token 更新后，无需重新导入订阅。
5. 播放异常时，使用「播放诊断」检查认证 IP、接口路由、IGMP、组播回流、FCC 和播放器首帧。

### IP 与 MAC 怎么填写

- 至少填写一项。已知 MAC 时，可留空 IP，并选择实际以太网接口。
- 按 MAC 捕获时，只有匹配目标的 DHCP ACK 才更新解析 IP；没有 ACK 时仍使用已填写的 IP。
- `any` 可用于按 IP 捕获，不支持按 MAC 过滤。SLL/SLL2 抓包无法统计 MAC 时，页面会显示无法判断。
- 解析到频道表只代表发现成功，实际播放仍取决于上游链路、认证和播放器支持。

### 从爱快导入抓包

- 优先在机顶盒所在 LAN / VLAN 抓包，可保留真实终端 IP 和 MAC；开始抓包后立即重启机顶盒，频道正常出现后再等几十秒即可停止。
- LAN 侧无法取得流量时再抓 WAN2。建议筛选 TCP、端口留空；WAN2 经过 NAT 时，预检显示的是 IPTV 线路侧客户端 IP，不一定是机顶盒 LAN 地址。
- 上传后先执行预检，页面会显示文件格式、链路层、VLAN / PPPoE、IPv4、TCP 流、候选客户端以及频道、FCC、回看特征。确认候选客户端后再分析，不会直接导入频道库。
- 支持经典 PCAP 与 PCAPNG，以及 Ethernet、VLAN / QinQ、PPPoE、Linux SLL / SLL2。文件上限 128 MiB，原始抓包会以仅所有者可读写权限保存在本地归档中。

### 固定订阅地址

以下路径均以 `http://宿主机IP:8787` 为前缀；如果配置了 `WEB_PORT`，请使用实际端口。

| 路径 | 用途 |
| --- | --- |
| `/playlist.m3u` | 推荐的主订阅，使用固定的 `/live/<频道ID>` 与 `/catchup/<频道ID>` 入口。 |
| `/playlist-all.m3u` | 主订阅的兼容别名，保留给已有播放器配置。 |
| `/playlist-hls.m3u` | 本机 HLS 直播入口，适用于需要 HLS 的播放器。 |
| `/playlist-rtp2httpd.m3u` | 每个频道的最佳原始 RTP 来源，供 rtp2httpd 订阅。 |
| `/playlist-rtp2httpd-all.m3u` | 频道库的全部原始线路，保留 FCC/FEC 参数。 |
| `/epg.xml` | 已配置的 XMLTV EPG。 |

直播固定入口通过 `307` 跳转到当前 rtp2httpd 来源，并禁止缓存响应。如果播放器仍缓存旧地址，请重新加载订阅或关闭其播放列表缓存。需要离线副本时，在「订阅中心 → 高级设置 / 静态导出」导出。

## rtp2httpd 与回看

rtp2httpd 默认端口为 `5140`，建议直接使用动态源列表：

```ini
external-m3u = http://iptv-sniffer-host:8787/playlist-rtp2httpd.m3u
external-m3u-update-interval = 300
```

全部线路使用 `/playlist-rtp2httpd-all.m3u`。这两个地址输出原始 RTP 来源，避免递归代理。常见播放地址为 `http://rtp2httpd-host:5140/rtp/239.x.x.x:port`。

诊断支持 INI 配置和 OpenWrt / ImmortalWrt 的 UCI `/etc/config/rtp2httpd`。将配置只读挂载进容器，在诊断页填写容器内路径。UCI 示例：

```uci
config instance
    option upstream_interface 'eth1'
    option upstream_interface_multicast 'eth1'
    option upstream_interface_fcc 'eth1'
    option external_m3u 'http://iptv-sniffer-host:8787/playlist-rtp2httpd.m3u'
    list listen '[::]:5140'
```

UCI 下划线键名等价于 INI 连字符键名；支持引号、行尾注释和 `list listen`。诊断读取唯一启用实例；多实例、外部配置文件或无法解析的配置会明确提示。

直播走组播、rtp2httpd 或本机 HLS；回看依赖运营商时移地址和有效认证信息。直播可用不代表回看可用。回看自动刷新会保存调度期限，重启后继续执行，失败按配置周期重试。HLS 按需启动 FFmpeg，空闲后停止。

遇到回看 403、超时或零字节，检查认证 IP、账号与机顶盒字段、门户 Token，以及到 IPTV 网段的路由。「媒体接收网口」控制本应用的直播、截图和主动组播检测；外部 rtp2httpd 仍使用自己的上游接口配置。

## 导入、备份与恢复

「导入频道 / 恢复备份」是统一入口，支持应用导出的 M3U、rtp2httpd 源文件、`channels.json` 和按模块备份。

- 普通 JSON 备份默认不包含密码、密钥与原始 PCAP；敏感模块需要主动选择。
- 更换容器或宿主机时，选择「全选（完整迁移）」导出 ZIP，包含设置、频道、认证材料、历史 PCAP、协议清单与 SHA-256 校验清单。敏感材料为明文，请存于可信位置。
- 只有选择历史 PCAP 时才生成 ZIP；未选时使用轻量 JSON。导出与 ZIP 恢复需要连续两次确认。
- ZIP 恢复先校验并暂存，拒绝额外路径、损坏文件和同名不同内容的 PCAP；相同内容会跳过。同步写入故障会回滚，但不保证断电时跨文件原子恢复。回滚失败时保留私有 `.restore-*/journal.json` 供人工恢复。
- 未选敏感模块时不会清空本机凭据；导入旧设置中的密码与密钥会归入敏感模块。已有同名接口的认证备份默认不覆盖。
- 恢复回看时，先恢复设置和运营商频道表，再刷新回看。备份不包含 Docker 镜像、应用日志、缓存、运行中的 DHCP 进程或 Cookie/JSESSIONID。

原始 PCAP 保存在 `data/stb-captures/`，重启或网页重置不会删除。频道发现页可以下载或经两次确认删除抓包及协议清单。PCAP 可能包含认证报文。

新版 `channels.json` 使用 schema v2，保留同名多线路；支持导入旧格式，向旧版迁移请使用 M3U。导入频道仅接受 IPv4 组播来源。灾备 ZIP 上限为 10,000 个文件、解压后 2 GiB；超过 256 项的包需用新版恢复。

迁移后仍需配置 host 网络、所需权限与专用 IPTV 网口，避免 NetworkManager 接管该网口，并恢复认证和路由。

## 认证助手与运行边界

实验性认证会修改指定接口的 MAC、IPv4 和 IPTV 路由。操作前请导出接口备份、断开机顶盒 IPTV 线避免 MAC 冲突，并通过另一张网卡访问管理页面。项目不会主动替换默认路由，但错误配置仍可能影响宿主机连通性。

认证接受运营商分配的可用 IPv4，不限定 `10.*`。初始恢复点不会被状态读取覆盖；历史快照被覆盖时，仅在有认证记录和可用的操作前快照时尝试恢复。MAC 命令失败或恢复后地址不匹配，会明确报错。

管理端口需由部署环境限制访问。IPTV 私网目标仍可访问，应用没有完整的目标地址访问控制列表。日志出口脱敏并轮转，每份 5 MiB，保留 3 份旧文件；历史日志和 PCAP 不自动改写。

| 项目 | 当前限制或行为 |
| --- | --- |
| 媒体任务 | 最多同时 4 个，直播最多 2、回看最多 2、截图最多 1、诊断最多 1；同时受 Waitress 线程数限制，满载返回 429，可在诊断页取消。 |
| 截图缓存 | 30 秒、32 项、16 MiB，检查 JPEG 边界并避免重复生成。 |
| PCAP | 支持经典 PCAP（大小端、微秒与纳秒）和 PCAPNG；可解析 Ethernet、VLAN / QinQ、PPPoE、Linux SLL / SLL2。上限 128 MiB，单包 1 MiB，TCP 重组 32 MiB / 262144 段 / 4096 流。 |
| 抓包归档 | 超过 16 MiB 暂停实时重复解析；约每 3 秒检查 128 MiB 停抓阈值，可能短暂超限。归档达 1 GiB 拒绝新抓包，不自动删除已有文件。 |
| 下载 | EPG / M3U 下载 16 MiB、gzip 展开 64 MiB；仅支持 HTTP(S)，重定向也检查协议。 |
| EPG 与静态导出 | 每分钟检查主源，刷新周期 12 小时；静态导出使用独立批次，24 小时过期、最多 100 批。 |
| 回看 | 支持 RTSP / HTTP(S)，FFmpeg 限制为网络输入；RTSP 按会话期限保活。RTP 缺口与迟到计数不等同于网络丢包率，不做乱序重排。 |

协议适配范围见[合成样本矩阵](tests/fixtures/protocols/README.md)。真实运营商长期播放、复杂多租约、FCC、RTSP 和各播放器兼容性仍需现场验收。

## 开发与发布

仓库仅维护 `main` 分支，通过版本标签发布镜像。应用、Compose、bake 与 Git 标签必须一致：

```bash
python -m pip install --require-hashes -r requirements-dev.lock
python -m pytest -q
node --test tests/settings-queue.test.cjs
python tools/check_release.py --tag v1.3.8-test
```

推送版本标签后，GitHub Actions 对同一提交运行 Linux/macOS 回归、amd64/arm64 构建和运行检查，生成 SBOM 并扫描可修复的 HIGH/CRITICAL 漏洞，通过后发布至 Docker Hub 和 GHCR。运行依赖带哈希锁定，基础镜像固定 digest。发布凭据使用 GitHub Secrets `DOCKERHUB_USERNAME` 和 `DOCKERHUB_TOKEN`。

测试标签 `vX.Y.Z-test` 对应镜像 `X.Y.Z-test`；正式标签 `vX.Y.Z` 同时更新版本镜像与 `latest`。结果以 [Actions](https://github.com/roninriddle/IPTV-Sniffer-Web/actions) 和实际镜像清单为准。

## 版本记录

| 版本 | 更新摘要 |
| --- | --- |
| **1.3.8-test** | 第一阶段外部抓包导入：爱快 / OpenWrt / Wireshark 页面向导、PCAP / PCAPNG 上传预检、VLAN / QinQ / PPPoE 归一化、抓包侧 IPTV 客户端自动识别，并复用频道、FCC、回看和认证分析链路。 |
| **1.3.7-test** | 汇总稳定版之后的所有改进：MAC/IP 捕获与 DHCP 目标关联、非 `10.*` 租约识别、MAC 恢复校验、持久回看调度、稳定订阅与来源记录、备份暂存回滚、UCI 诊断、媒体配额、解析器与发布检查。本次修正捕获表单输入框对齐和移动端排版，重整 README，统一为 main 分支与单一当前测试版。 |
| **1.3.3（稳定版）** | 历史 PCAP 管理、包含原始抓包和敏感材料的可选灾备、两次确认、rtp2httpd 动态原始源订阅。 |
| 1.3.2 及以前 | 建立频道发现、认证辅助、订阅与多线路管理、回看/HLS、EPG 和播放诊断。详细变化保留在 [Git 提交历史](https://github.com/roninriddle/IPTV-Sniffer-Web/commits/main)。 |

## 参考与致谢

- [江苏电信 IPTV 回看源技术分析](https://www.right.com.cn/forum/thread-8314608-1-1.html)、[认证与频道获取实践](https://www.right.com.cn/forum/thread-8314231-1-1.html)
- [IPTV 单播与回看实践（一）](https://www.bandwh.com/net/2571.html)、[（二）](https://www.bandwh.com/net/2637.html)、[RTSP 路由排障](https://ngabbs.com/read.php?tid=41933257&rand=555)
- [`supzhang/get_iptv_channels`](https://github.com/supzhang/get_iptv_channels)、[`suzukua/iptv-cd-telecom`](https://github.com/suzukua/iptv-cd-telecom)、[`CGG888/SrcBox`](https://github.com/CGG888/SrcBox)
- [`beijing-unicom-iptv-playlist`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist)、[`beijing-unicom-iptv-playlist-sniffer`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist-sniffer)
- [`epg.51zmt.top`](https://epg.51zmt.top:8001/)、[`wanglindl/TVlogo`](https://github.com/wanglindl/TVlogo)
