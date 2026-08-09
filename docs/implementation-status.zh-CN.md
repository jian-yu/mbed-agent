# mbed-agent 实现状态

本文档描述当前代码实际提供的能力，不代表长期目标。`mbed-agent capabilities`
返回的 `configuration` 字段是运行时判定的单一事实源；本表用于解释能力边界和
平台差异。

## 配置能力

| 配置域 | 当前状态 | 当前范围 |
|---|---|---|
| firewall | `writable_confirmed` | OpenWrt fw3/fw4；通用 Linux Agent-owned nftables/iptables；zone、forwarding、filter、set、NAT、MAC/IP/端口、顺序和启停 |
| network | OpenWrt `writable_confirmed`；通用 Linux `writable_runtime` | OpenWrt 接口、Bridge/VLAN、路由、policy rule，以及部分 DNS/DHCP 字段；通用 Linux Agent-owned 运行态地址、路由、policy rule |
| dns | `read_only` | 诊断可用；可写字段必须通过已支持的 network 对象进入 ChangeSet |
| dhcp | `read_only` | 诊断可用；OpenWrt 仅支持 network planner 暴露的 DHCP server/host 子集 |
| wireless | `read_only` | 被动 radio/interface 诊断，不执行扫描或无线配置写入 |
| service | `unsupported` | 没有 typed service planner |
| qos | `read_only` | qdisc 诊断，不写 SQM/tc |
| wireguard | `unsupported` | 没有 typed WireGuard planner |
| system_network | `unsupported` | 没有 NetworkManager/systemd-networkd 等持久后端 |

所有 writable 变更都必须经过 fresh inventory、typed plan、风险计算、管理员提权、
一次性审批、原生校验、confirmed commit、verify 和 rollback。未知或第三方对象保持
只读。

## Channel 和 Provider

- MQTT 5、TLS/mTLS、QoS1、去重、bounded outbox、自动重连已实现。
- 微信 ClawBot 支持官方二维码绑定、凭据原子落盘、长轮询和有界文本回复。
- 企业微信智能机器人支持官方 WSS 绑定、心跳、文本回调和自动重连。
- Channel 当前主要支持文本；媒体、按钮、签名 envelope 和证书热轮换仍未完成。
- LLM 当前为单个 OpenAI-compatible Provider；多 Provider 原生适配、logical model
  路由、配额和健康度属于后续阶段。

## 存储和运行态约束

- SQLite、WAL、日志、artifact 和 rollback 均位于 `/tmp/mbed-agent`。
- 配置和业务配置事务是允许写入持久介质的唯一类别。
- SQLite 主库已有 `max_page_count` 和 bounded record/payload；WAL checkpoint 水位、
  Session/Turn/Observation 以及哈希审计链仍在工程化收口阶段。
