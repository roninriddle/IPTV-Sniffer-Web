# 协议适配器样本矩阵

全部样本人工合成；192.0.2.0/24 为文档地址，无真实账号、Token 或设备 PCAP。地区名仅用于元数据分类回归，不能证明该地区所有平台兼容，也不配置 VLAN。

| 文件 | 协议／解析器 v1 | 字段与适用范围 |
|---|---|---|
| ctc-setconfig.html | CTC/CU/js SetConfig HTML | ChannelID、组播、频道序号／名称、分组、FCC/FEC、回看；已有回归另覆盖南京栏目、GBK、gzip |
| channel-acquire.json | ChannelAcquire JSON | channelInfoStruct/channleInfoStruct、组播查询参数、时移；字段形状参考北京联通类响应 |
| vsp.json | VSP channelDetails JSON | channelNO、ID、physicalChannels/btvCR；仅解析存在的字段，不推断 FCC／回看 |

测试将这些正文包装为合成 HTTP 响应，验证适配器选择、标准化字段及 provenance。既有 PCAP 构造测试另覆盖 TCP 重组、VLAN、Linux cooked capture 和多客户端 DHCP 选择。

`provenance.sources` 记录归档 PCAP 文件名、TCP 四元组、响应索引、正文 SHA-256、协议、解析器及版本；`fields` 将标准化输出字段映射到来源索引。这是解析结果来源，并非每字段的原始字节偏移；自动分类可能来自解析器推断。手工导入没有 PCAP 的数据不伪造来源。
