# IPTV Sniffer Web v1.2.4

适用于 **飞牛 NAS / Linux Docker / 交换机镜像口运营商频道发现** 的 IPTV 频道发现、线路整理与 `rtp2httpd` 播放列表工作台。

参考与致谢：

- [江苏电信 IPTV 回看源在 TVBox 上进行播放（技术分析）](https://www.right.com.cn/forum/thread-8314608-1-1.html)
- [江苏电信 IPTV 回看地址探究（技术分析）](https://www.right.com.cn/forum/thread-8314231-1-1.html)
- [`supzhang/get_iptv_channels`](https://github.com/supzhang/get_iptv_channels)：CU IPTV EPG 认证与回看地址获取思路；
- [`zzzz0317/beijing-unicom-iptv-playlist`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist)：多源播放列表、代理地址转换与 M3U 生成；
- [`zzzz0317/beijing-unicom-iptv-playlist-sniffer`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist-sniffer)：机顶盒 `channelAcquire` 请求与 `UserToken` 嗅探；
- [`CGG888/SrcBox`](https://github.com/CGG888/SrcBox)：FCC 快速换台、UDP/RTP/IGMP 多协议流识别以及 XMLTV EPG 模糊匹配；
- [`epg.51zmt.top`](https://epg.51zmt.top:8001/)：老张的 EPG / 51zmt 数据；
- [`wanglindl/TVlogo`](https://github.com/wanglindl/TVlogo)：频道台标 M3U 资源。

## 核心特性

| 功能 | 说明 |
|---|---|
| 运营商频道发现 | 通过交换机镜像口捕获机顶盒开机流量，解析频道表、组播地址、FCC/FEC、DHCP 认证信息 |
| IPTV 认证助手 | 集中展示 MAC / Hostname / IPTV IP / 网关 / Option60 / UserToken / FCC 摘要；提供实验性一键认证与恢复；支持导出/导入接口初始状态备份；可检测并临时解除选定网口 egress BPF 组播拦截，并支持定时自动修复开关 |
| 频道线路组 | 同名频道自动归组，按播放可用性、FCC/FEC、包数和人工主源标记选择主源，保留备选线路 |
| 播放链路诊断 | 检测 rtp2httpd 可达性、配置、FCC、IGMP、组播回流和镜像口误判 |
| 五档导出 | `channels-best.m3u` / `channels-all.m3u` / `channels-fnos-hls.m3u`（浏览器 HLS）/ `channels-rtp2httpd-best.m3u` / `channels-rtp2httpd-all.m3u` |
| 飞牛影视 HLS 支持 | 按需 FFmpeg HLS 转封装，浏览器直接播放组播流；空闲 60 秒自动停止 |
| EPG & 台标 | XMLTV EPG + TVlogo 缓存匹配；可在频道线路标签勾选启用/禁用；支持一键重新匹配 |

## 快速开始

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
  roninriddle/iptv-sniffer-web:1.2.4
```

打开：

```text
http://宿主机IP:8787
```

本地构建：

```bash
mkdir -p data output
docker compose up -d --build
```

本地测试：

```bash
python -m pip install -r requirements-dev.txt
pytest -q
```

## 版本标签策略

- 测试版使用 `x.y.z-test`，例如 `1.2.1-test`；
- 测试版只推送 GitHub tag 与 Docker Hub 同名 tag，不推送 `latest`；
- 正式版使用 `x.y.z`，例如 `1.2.4`；
- 正式版发布时才同时推送 Docker Hub `x.y.z` 与 `latest`。

## 唯一推荐拓扑：交换机镜像口

```text
光猫 IPTV 口 → 交换机
  ├─ 机顶盒端口（被镜像源）
  └─ Docker 宿主机网口（镜像目标）
```

这种方式用于 **捕获机顶盒开机流量**：

- 可以捕获机顶盒开机流量；
- 可以解析频道表、组播地址、FCC/FEC、Option60 等认证信息；
- 可以生成频道线路和 rtp2httpd 源文件；
- 不能证明宿主机可以主动播放，因为镜像口不能主动向 IPTV 上游发送 IGMP/FCC 请求。

如果要让 rtp2httpd 主动播放，必须让某个设备完成 IPTV DHCP 认证并具备主动访问 IPTV 上游的能力。项目中的 **IPTV 认证助手** 用于辅助完成这一步。

## 完整使用流程

1. **搭建镜像拓扑**  
   在管理型交换机中把机顶盒端口设为镜像源，把 Docker 宿主机网口设为镜像目标。容器使用 `--network host`。抓包需要 `NET_RAW`，实验性 IPTV 认证和接口路由调整需要 `NET_ADMIN`。
   FNOS 中这两个权限在容器编辑页的「高级设置 → 功能」项目里勾选：`NET_RAW`、`NET_ADMIN`。

2. **运营商频道发现**  
   打开「运营商频道」，填写机顶盒 IP，选择镜像口，点击「开始捕获」，然后重启机顶盒。捕获完成后导入频道列表。

3. **查看 IPTV 认证信息**  
   打开「IPTV 认证」。抓包得到的 STB MAC、Hostname、IPTV IP、网关、Option60、UserToken、FCC 记录会集中显示在这里。

4. **频道使用与导出**  
   打开「频道线路」，确认主源和备选线路。导出：
   - `channels-best.m3u`：每个频道组只导出主源（需填写 rtp2httpd 地址）；
   - `channels-all.m3u`：导出全部线路（需填写 rtp2httpd 地址）；
   - `channels-fnos-hls.m3u`：飞牛影视 HLS（浏览器可直接播放，地址指向本机 HLS 转封装端点）；
   - `channels-rtp2httpd-best.m3u`：给 rtp2httpd `external-m3u` 使用的主源文件；
   - `channels-rtp2httpd-all.m3u`：给 rtp2httpd 使用的全部线路源文件。

5. **IPTV 认证（需要主动播放时）**  
   在「IPTV 认证」中填写接口、MAC、Hostname 等参数，点击「实验性一键认证」。执行前会备份初始 MAC、IPv4 和路由，并提供恢复按钮。FNOS 容器必须在「高级设置 → 功能」勾选 `NET_ADMIN` 和 `NET_RAW`。

6. **播放诊断**  
   打开「播放诊断」，填写 rtp2httpd 地址和一个频道地址。诊断会检查 rtp2httpd 是否可访问、是否匹配 M3U、FCC 是否超时、是否发出 IGMP、是否收到 239.x UDP。

## IPTV 认证助手说明

实验性一键认证要求：

```text
network_mode: host
cap_add: NET_ADMIN, NET_RAW
容器以 root 运行
```

在 FNOS 图形界面中编辑容器时，进入「高级设置 → 功能」，勾选：

- `NET_RAW`：允许 `tcpdump` 抓包和原始网络访问；
- `NET_ADMIN`：允许实验性认证助手修改选定网口的 MAC、IPv4、路由并执行 DHCP 认证。

强提醒：

- 执行前断开机顶盒 IPTV 线，避免 STB MAC 冲突；
- 确认 Web 管理页面通过另一张网卡访问；
- 默认路由不会被项目主动替换，只会按页面选择写入 IPTV 相关路由。

## rtp2httpd 使用

`rtp2httpd` 默认端口为 `5140`。页面可以导出给 rtp2httpd 使用的源文件：

```ini
external-m3u = file:///vol1/@appshare/rtp2httpd/channels-rtp2httpd-best.m3u
external-m3u-update-interval = 0
```

导出最佳线路前会对同一频道组内的多条候选源做短拉流健康检查：通过 rtp2httpd 读取少量媒体字节，HTTP 200 且有数据的源优先；HTTP 503、超时或无数据的源会自动降级。单源频道不会额外检查。

常见播放地址形态：

```text
http://rtp2httpd-host:5140/rtp/239.x.x.x:port
```

如带 FCC/FEC，会追加：

```text
?fcc=FCC服务器IP:FCC服务器端口&fcc-type=telecom&fec=FEC端口
```

## 回看 / 时移工作流

本项目把直播和回看拆成两条链路，参考了致谢项目中“直播源 / timeshift 源分离”的做法：

- 直播源：频道播放仍走组播、`rtp2httpd` 或本机 HLS 转封装；
- 回看源：使用运营商频道表中的 `TimeShift`、`TimeShiftLength`、`TimeShiftURL` / `BacktimeURL` / `BackUrl` 等字段；
- 导出：只对带回看地址的频道写入 `catchup="default"`、`catchup-days` 和 `catchup-source`；
- 代理：默认 `catchup-source` 指向本机 `/hls/<key>/catchup?playseek=...`，由服务端用 FFmpeg 打开运营商 RTSP 回看地址并转成 HTTP MPEG-TS；
- 刷新：当回看返回 403、IPTV IP 变化、或 RTSP Token 过期时，在页面填写 IPTV 密码、UserID、STBID、DES/DES3 密钥并点击「刷新回看地址」；也可以开启「自动定时刷新回看地址」，由后台按小时周期重新登录 EPG 门户并更新 `operator_channels.json`。
- 门户 Token：STB 开机捕获会额外识别恩山帖子提到的 `CTCGetAuthInfo`、`/uploadAuthInfo` 响应头 `UserToken`、`X-Frame-SessionID`，捕获到的 `UserToken` 会写入现有 token 记录，用于认证摘要和诊断判断。
- 认证模式：支持自动 / 电信 CTC-HWCTC / 联通 CU-HWCTC。自动模式会在字段完整时优先使用 `supzhang/get_iptv_channels` 的 CTC-HWCTC 链路获取 `JSESSIONID` 与频道表，失败后回退到 CU-HWCTC。

几个容易混淆的点：

- `channels-best.m3u` / `channels-all.m3u` 是播放器入口，里面的直播 URL 可以是 `rtp2httpd` HTTP 地址；
- `channels-rtp2httpd-best.m3u` / `channels-rtp2httpd-all.m3u` 是给 `rtp2httpd external-m3u` 使用的源文件，里面保留 `rtp://` / `udp://` 组播源；
- 回看 RTSP Token 通常与账号、机顶盒信息、IPTV 侧 IP 绑定，能直播不代表回看 Token 一定有效；
- `catchup-source` 关闭时不会写入 HLS M3U；没有 `backtv_url` 的频道也不会写入回看属性；
- 导出的回看 M3U 入口是稳定的：播放器仍访问本机 `/hls/<key>/catchup`，无需因为 token 刷新而频繁替换播放列表；真正会变化的是服务端保存的 `backtv_url` token；
- Token 有效期不一定可见：如果门户 `JSESSIONID` 暴露 expires，页面会显示过期时间；如果只返回会话 Cookie 或不透明 RTSP token，页面会显示“未暴露明确有效期”，建议按 6-12 小时定时刷新；
- `/app/data` 必须持久化，否则频道表、认证摘要和刷新后的回看地址会随容器删除而丢失。

回看故障判断：

- HTTP 403：多半是 `backtv_url` Token 过期、IPTV 认证 IP 变化、门户 `UserToken` 未捕获，或 UserID/STBID/密码不匹配；
- 超时或 0 字节：先检查 IPTV 认证、`enp3s0` 是否有 10.x IPTV 地址、是否存在到 10.0.0.0/8 或回看服务器的路由；
- M3U 没有 `catchup-source`：确认页面已启用回看，且运营商频道表中该频道带 `TimeShift` 与 `backtv_url`；
- 播放器时间偏移：当前导出头会在启用回看时写入 `catchup-correction="8"`，让支持该字段的播放器按北京时间生成 `playseek`。

## API 摘要

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/interfaces` | 列出抓包接口 |
| POST | `/api/stb_discovery/start` | 启动 STB 开机捕获 |
| POST | `/api/stb_discovery/stop` | 停止捕获并分析 |
| POST | `/api/stb_discovery/import` | 导入运营商频道 |
| GET | `/api/stb-summary` | 获取 IPTV 认证摘要 |
| GET | `/api/iptv-auth/status` | 检查选定接口认证状态和权限 |
| POST | `/api/iptv-auth/apply` | 实验性一键认证 |
| POST | `/api/iptv-auth/restore` | 恢复选定接口初始设置 |
| GET | `/api/iptv-auth/backup-export` | 导出接口初始状态备份 JSON |
| POST | `/api/iptv-auth/backup-import` | 导入接口初始状态备份 JSON |
| GET | `/api/iptv-auth/egress-bpf/status` | 检测选定接口 TC/XDP/egress BPF 状态 |
| POST | `/api/iptv-auth/egress-bpf/clear` | 强确认后临时解除选定接口 egress BPF |
| GET | `/api/iptv-auth/egress-bpf/watch` | 查看 egress BPF 自动修复守护状态 |
| POST | `/api/iptv-auth/egress-bpf/watch` | 配置 egress BPF 自动修复开关与检测间隔 |
| POST | `/api/epg/refresh` | 刷新 EPG 与台标缓存 |
| POST | `/api/epg/rematch` | 强制重新匹配所有频道节目单 |
| POST | `/api/diagnose` | 播放链路诊断 |
| POST | `/api/export` | 导出频道文件 |
| GET | `/api/hls/m3u` | 生成飞牛影视 HLS M3U 文件 |
| POST | `/api/catchup/refresh` | 手动刷新运营商回看 backtv_url |
| GET | `/api/catchup/refresh/status` | 查看回看地址定时刷新状态 |
| GET | `/api/hls/status` | 查看当前 HLS 转流实例状态 |
| GET | `/hls/<key>/stream.m3u8` | HLS 播放列表（按需启动 FFmpeg） |
| GET | `/hls/<key>/<segment>.ts` | HLS 媒体分片 |

## 版本记录

- `v1.2.4`：修复 DHCP Option60 处理：抓包提取时改为存储原始十六进制（如 `dhcpcd-5.5.6` → `6468637063642d352e352e36`），避免 ASCII 字符串填入十六进制字段时因奇数位报错；`_normalize_hex` 同步支持 ASCII 文本直接输入并自动转十六进制；
- `v1.2.3`：修复 STB 开机捕获 `channelAcquire` 频道解析失败问题：当抓包漏掉 HTTP 响应前几个 TCP 包（含 headers 和 JSON 数组开头）时，重组流中无 `HTTP/` 标记、频道数组起始丢失，原解析器返回 0 个频道；新增三层 fallback：先剥离内嵌的 chunked 分块大小行（`\r\n2000\r\n`），再用括号计数逐对象提取完整 JSON 频道条目，可恢复除首个截断条目外的全部频道；
- `v1.2.2`：STB 开机捕获新增北京联通 / 海信 IP811N `channelAcquire` JSON 频道表解析，支持一次开机抓取完整频道列表（含 `channleInfoStruct` 拼写兼容）、组播地址、FCC/FEC、回看地址与 UserToken；若运营商频道表包含频道分组，将分组应用到频道列表与导出文件，并保留原始运营商分组；STB 捕获完成后保留最近一次 pcap，页面新增「导出抓包文件」用于一键下载排查；频道分类筛选改为按当前频道表动态生成，支持运营商自定义分组；
- `v1.2.1`：回看刷新新增认证 Profile：自动 / 电信 CTC-HWCTC / 联通 CU-HWCTC，自动模式改为优先尝试联通 CU-HWCTC，失败再回退电信 CTC-HWCTC；参考 `supzhang/get_iptv_channels` 增加 `EncryptToken → Authenticator → ValidAuthenticationHWCTC → JSESSIONID → getchannellistHWCTC` 链路；新增 STBType、STBVersion、UserAgent、AccessUserName、加密模式、padding 设置；STB 开机抓包自动提取并填充这些字段（含 STBID）；新增回看地址自动定时刷新开关、刷新状态与 token 有效期可见性提示；导出的回看 M3U 保持稳定入口，由后端刷新内部 `backtv_url`；修复频道无 `backtv_url` 且无自定义模板时仍写入 `catchup="default"` 但缺 `catchup-source` 的问题（会让播放器误以为支持回看）；修复回看认证字段表单溢出与单选按钮过大的布局问题；「保存导出设置」按钮移除，相关设置改为编辑后自动保存（文本类防抖、开关/下拉立即保存）；本地配置备份新增「清除所有配置」按钮（二次确认 + 输入确认文本）；备份导出文件名增加时分秒，避免同日多次导出互相覆盖；STB 开机捕获状态提示优化（约 30 秒可捕获认证信息、约 60 秒可捕获频道信息，发现频道数与认证状态分行显示）；回看 / 时移功能标注「暂不可用」（EPG 门户加密细节尚未完全验证，回看刷新可能不稳定）；
- `v1.2.0`：新增「刷新回看地址」功能：重新登录运营商 EPG 门户（支持 CU IPTV DES3 认证），自动刷新 operator_channels.json 中各频道的 backtv_url Token；新增 IPTV 密码、用户ID、STBID、DES3 密钥、EPG 服务器地址输入字段，EPG 服务器地址可从已有回看地址自动提取；整理首页致谢；
- `v1.1.9`：回看功能改为默认关闭、勾选后才显示回看设置；导出时 catchup-source 改为走 Flask HTTP 代理（`/hls/<key>/catchup`）而非内嵌过期的 RTSP token，代理通过 ffmpeg 转封装实时回看流；代理失败时将 ffmpeg 错误写入应用日志便于诊断；
- `v1.1.8`：首页底部新增作者赞赏码；修复 catchup-source 格式选择框布局溢出问题（改用 display:block 替代 flex，彻底解决文字右侧溢出）；
- `v1.1.7`：首页底部新增作者赞赏码；
- `v1.1.6`：修复直播 M3U 回看地址双问号 bug（backtv_url 已含 `?` 参数，playseek 错误拼接第二个 `?` 导致无效 URL）；飞牛 HLS M3U 新增回看支持（EXTINF 行注入 `catchup`/`catchup-days`/`catchup-source` 属性，`#EXTM3U` 头增加 `catchup-correction="8"`）；新增 `/hls/<key>/catchup` Flask 代理端点，通过 ffmpeg 将 RTSP 回看流转为 MPEG-TS 流式传输给播放器；
- `v1.1.5`：修复 auth 备份恢复时若初始快照无 IPv4（捕获过早）会导致断网：自动补跑普通 udhcpc 恢复局域网 IP，导入此类备份时前端给出警告；所有导出文件（全量备份、per-interface auth 备份）内部新增 `_app_version` 和 `_exported_at` 字段；修复 catchup-days 换算 bug（任何非零 TimeShiftLength 均除以 1440，不再有阈值误判）；
- `v1.1.4`：修复回看服务器地址（抓包后自动填入）在 RTSP 协议下为空的问题；修复备份导出 settings 为 null 的问题（改用内存设置，始终含默认值）；修复 TimeShiftLength 单位（分钟→天，14400 分钟正确导出为 10 天）；catchup-source 格式改为三选一（APTV 默认 / 飞牛 NAS·HLS 自动生成 / 其他手动填写）；
- `v1.1.3`：顶部导航顺序调整为「发现 → 认证 → 线路 → 诊断」，与实际工作流对齐；回看/时移服务器地址改为独立输入框，抓包导入时自动检测并填入（从 BacktimeURL/BackUrl 字段或 HTTP 流量正则匹配）；catchup-source 模板留空时由回看服务器地址自动生成；新增「保存导出设置」按钮，方便持久化回看地址等配置；
- `v1.1.2`：IPTV 认证页合并为单页（去掉「状态与参数」/「一键认证」两个 tab，实验性认证移至状态下方、组播拦截检测上方）；导出前线路健康检查改为默认关闭并新增勾选框（认证后再开启才有意义）；同时并发执行健康检查探测（由串行改为并行，80 频道从约 20 秒降至 1–2 秒）；新增回看服务器需认证的提示；首页工作流说明更新为「抓包 → 认证 → 导出」；
- `v1.1.1`：修复备份不含认证摘要（STB MAC / Hostname / IP / Option60）问题；捕获后自动将 auth_info 持久化到 stb_token 文件，备份导入后即可正确显示；
- `v1.1.0`：修复备份导入后 OperatorChannelStore 缓存不失效导致已保存频道表计数不更新；备份导入成功后立即刷新频道表计数、IPTV 认证摘要；页面初始化时加载频道表计数；catchup-source 模板改为后端默认值预填；
- `v1.0.9`：EPG/台标设置并入导出标签页；频道列表新增列头点击排序；捕获状态提示调整（已发现频道数与认证信息移至末尾）；认证备份导入后自动刷新状态；catchup-source 模板输入框宽度修复，placeholder 改为 APTV 标准格式；
- `v1.0.8`：发现页新增「本地配置备份」，支持一键导出/导入全部数据（频道列表、认证信息、FCC 记录、设置、快照、STB Token 等）；
- `v1.0.7`：频道主源评分逻辑重构，按播放可用性、FCC/FEC、包数和人工标记综合排序；CCTV4 欧洲/美洲变体频道独立归组；修复 BPF 确认文字（确认解除/确认恢复）；清除认证表单默认凭据；路由策略选项文字缩短；日志按钮状态正确反映开关状态；首页新增 GitHub 仓库链接；
- `v1.0.6`：IPTV 认证页新增组播拦截检测；可识别选定接口 XDP/clsact/egress BPF 与 drop 计数；强确认后仅临时解除该接口 egress BPF，并保存检测快照；新增默认关闭的自动修复守护开关，可按间隔检测并自动解除疑似拦截，用于修复 FCC 成功但组播切换无回流的问题；导出前新增多线路源健康检查，自动避开 HTTP 503、超时或无数据的坏源；
- `v1.0.2`：修复刷新台标按钮实际未调用 /api/logo/refresh；修复频道线路 EPG 徽章永远显示"未加载"（settings 端点不含 epg_status）；补全 epgStatusBox 状态文本；
- `v1.0.1`：EPG 与台标移至频道线路标签，可勾选启用/禁用，各保留一个来源；移除安全助手脚本生成模块；移除飞牛影视 rtp 直连 M3U 按钮；修复 udhcpc option125 malformed hex 报错；捕获流量时实时显示已发现频道数与认证状态；刷新状态自动覆盖备份；
- `v1.0.0`：飞牛影视 HLS 转封装支持（按需 FFmpeg，空闲自动停止）；飞牛影视 rtp 直连 M3U；EPG 数字边界误匹配修复；IPTV 认证备份导出/导入；重新匹配节目单按钮；iptv_private 路由模式设为默认推荐；
- `v0.9.96`：简化部署向导为交换机镜像口频道发现单一路径；删除 R4S / OpenWrt / iStoreOS 相关内容；认证摘要移动到 IPTV 认证页；补充 FNOS「高级设置 → 功能」中 `NET_ADMIN` / `NET_RAW` 权限说明；
- `v0.9.94`：新增 IPTV 认证助手；支持脚本生成、实验性一键认证、接口级备份与恢复；使用说明简化为交换机镜像口频道发现单一路径；认证摘要移动到 IPTV 认证页；
- `v0.9.93`：播放诊断分层输出；支持读取 rtp2httpd 配置文件；频道线路分组视图增强主源、备线、FCC/FEC 与最近状态；
- `v0.9.8`：STB 开机捕获同步解析 DHCP 认证信息、FCC、频道表；
- `v0.6`：基于 `beijing-unicom-iptv-playlist` 与 `beijing-unicom-iptv-playlist-sniffer` 思路重构为统一 Web 工作台。
