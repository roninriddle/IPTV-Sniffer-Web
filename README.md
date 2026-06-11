# IPTV Sniffer Web v0.9.96

适用于 **飞牛 NAS / Linux Docker / 交换机镜像口嗅探** 的 IPTV 组播嗅探、运营商频道发现、频道线路整理与 `rtp2httpd` 播放列表工作台。

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
| IPTV 认证助手 | 集中展示 MAC / Hostname / IPTV IP / 网关 / Option60 / UserToken / FCC 摘要；生成认证脚本；提供实验性一键认证与恢复 |
| 频道线路组 | 同名频道自动归组，按 4K > 1080p > 720p > SD > 未识别自动选主源，保留备选线路 |
| 播放链路诊断 | 检测 rtp2httpd 可达性、配置、FCC、IGMP、组播回流和镜像口误判 |
| 四档导出 | `channels-best.m3u` / `channels-all.m3u` / `channels-rtp2httpd-best.m3u` / `channels-rtp2httpd-all.m3u` |
| EPG & 台标 | XMLTV EPG + TVlogo 缓存匹配，定时刷新并写入导出文件 |

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

这种方式用于 **只嗅探**：

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
   - `channels-best.m3u`：每个频道组只导出主源；
   - `channels-all.m3u`：导出全部线路；
   - `channels-rtp2httpd-best.m3u`：给 rtp2httpd `external-m3u` 使用的主源文件；
   - `channels-rtp2httpd-all.m3u`：给 rtp2httpd 使用的全部线路源文件。

5. **IPTV 认证（需要主动播放时）**  
   在「IPTV 认证」中先生成脚本，建议先手动执行 `dhclient` 脚本验证。实验性一键认证只会操作选定接口，执行前会备份初始 MAC、IPv4 和路由，并提供恢复按钮。FNOS 容器必须在「高级设置 → 功能」勾选 `NET_ADMIN` 和 `NET_RAW`。

6. **播放诊断**  
   打开「播放诊断」，填写 rtp2httpd 地址和一个频道地址。诊断会检查 rtp2httpd 是否可访问、是否匹配 M3U、FCC 是否超时、是否发出 IGMP、是否收到 239.x UDP。

7. **定时 EPG**  
   打开「定时 EPG」，设置每天或每小时刷新已经导入的 M3U/EPG 来源。

## IPTV 认证助手说明

认证助手分两层：

| 层级 | 说明 |
|---|---|
| 安全助手 | 只生成 `dhclient` / `udhcpc` 脚本，由你复制后手动执行 |
| 实验性一键认证 | 容器内执行 `udhcpc`，只更改选定接口；执行前备份；恢复按钮按初始备份回滚 |

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
- 默认路由不会被项目主动替换，只会按页面选择写入 IPTV 相关路由；
- 如果认证失败，优先使用页面生成的宿主机 `dhclient` 脚本验证。

## rtp2httpd 使用

`rtp2httpd` 默认端口为 `5140`。页面可以导出给 rtp2httpd 使用的源文件：

```ini
external-m3u = file:///vol1/@appshare/rtp2httpd/channels-rtp2httpd-best.m3u
external-m3u-update-interval = 0
```

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
| POST | `/api/iptv-auth/scripts` | 生成认证脚本 |
| POST | `/api/iptv-auth/apply` | 实验性一键认证 |
| POST | `/api/iptv-auth/restore` | 恢复选定接口初始设置 |
| POST | `/api/diagnose` | 播放链路诊断 |
| POST | `/api/export` | 导出频道文件 |

## 版本记录

- `v0.9.96`：简化部署向导为交换机镜像口嗅探单一路径；删除 R4S / OpenWrt / iStoreOS 相关内容；认证摘要移动到 IPTV 认证页；补充 FNOS「高级设置 → 功能」中 `NET_ADMIN` / `NET_RAW` 权限说明；
- `v0.9.94`：新增 IPTV 认证助手；支持脚本生成、实验性一键认证、接口级备份与恢复；使用说明简化为交换机镜像口嗅探单一路径；认证摘要移动到 IPTV 认证页；
- `v0.9.93`：播放诊断分层输出；支持读取 rtp2httpd 配置文件；频道线路分组视图增强主源、备线、FCC/FEC 与最近状态；
- `v0.9.8`：STB 开机捕获同步解析 DHCP 认证信息、FCC、频道表；
- `v0.6`：基于 `beijing-unicom-iptv-playlist` 与 `beijing-unicom-iptv-playlist-sniffer` 思路重构为统一 Web 工作台。
