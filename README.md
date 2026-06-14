# IPTV Sniffer Web v1.0.9

适用于 **飞牛 NAS / Linux Docker / 交换机镜像口运营商频道发现** 的 IPTV 频道发现、线路整理与 `rtp2httpd` 播放列表工作台。

v0.6 起基于以下两个开源项目的思路重构而来，并整合为单一 Web 图形化页面：

- [`zzzz0317/beijing-unicom-iptv-playlist`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist)：参考多源播放列表、代理地址转换与 M3U 生成思路；
- [`zzzz0317/beijing-unicom-iptv-playlist-sniffer`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist-sniffer)：参考机顶盒 `channelAcquire` 请求与 `UserToken` 嗅探方式。

特别感谢以上项目作者的公开实现与整理工作。

另参考并致谢：

- [`CGG888/SrcBox`](https://github.com/CGG888/SrcBox)：参考 FCC 快速换台、UDP/RTP/IGMP 多协议流识别以及 XMLTV EPG 模糊匹配的工程实现思路；
- [`epg.51zmt.top`](https://epg.51zmt.top:8001/)：老张的 EPG / 51zmt 数据；
- [`wanglindl/TVlogo`](https://github.com/wanglindl/TVlogo)：频道台标 M3U 资源；
- [`epg.112114.xyz`](https://epg.112114.xyz/)：EPG 数据参考。

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
  roninriddle/iptv-sniffer-web:latest
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
| GET | `/api/hls/status` | 查看当前 HLS 转流实例状态 |
| GET | `/hls/<key>/stream.m3u8` | HLS 播放列表（按需启动 FFmpeg） |
| GET | `/hls/<key>/<segment>.ts` | HLS 媒体分片 |

## 版本记录

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
