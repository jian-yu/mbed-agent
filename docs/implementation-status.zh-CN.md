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
- SQLite 主库已有 `max_page_count`、bounded record/payload、WAL checkpoint 水位和
  启动/运行态维护；Session/Turn/Observation 元数据、日志轮转和 artifact 清理均受
  配额约束，业务正文与敏感值不写入 SQLite。

## 交付与可靠性验收

- `openwrt/targets.tsv` 覆盖 OpenWrt 21.02 fw3、22.03/23.05/24.10 fw4 的
  x86/64、armvirt、armsr 及 mediatek/ramips 代表目标，并校验 Rust musl target
  与防火墙后端的一致性；24.10.8 还包含真实验证设备使用的
  `bcm27xx/bcm2711` aarch64 目标。
- `scripts/build-openwrt-sdk-package.sh` 使用官方 release SDK 和同目录
  `sha256sums`，在固定 `/tmp` 缓存中重建目标包；`.github/workflows/openwrt-sdk.yml`
  提供手动、可复现的 x86/64 矩阵构建。
- `scripts/prepare-release-artifacts.sh` 聚合版本化 binary、Cargo 依赖图、Rust
  toolchain provenance、manifest 和 checksums；`.github/workflows/release-candidate.yml`
  提供手动 RC 产物工作流。依赖图到 SPDX/CycloneDX 的转换由发布侧服务完成，设备
  侧不引入额外生成器。
- `scripts/run-openwrt-qemu-smoke.sh`、`scripts/run-linux-namespace-smoke.sh` 和
  `scripts/check-persistent-write-set.sh` 分别提供 OpenWrt 启动、通用 Linux 能力、
  运行态 Flash 写入快照的有界验收入口。仓库不携带固件镜像，真实 fw3 事务、
  namespace 内核能力和 72 小时 Channel 稳定性仍是 v0.2.0 RC 的外部验收门槛。
- `scripts/run-openwrt-device-readonly-smoke.sh` 已在 OpenWrt 24.10.8
  bcm27xx/bcm2711 真机重复通过：aarch64 daemon、ping/status/capabilities、13 个
  被动诊断和 firewall/network inventory 均成功，`/etc/config` 前后哈希一致。
- `scripts/run-openwrt-device-firewall-rollback-smoke.sh` 已支持并在 fw3/fw4 真机验证：
  CLI 管理员密码提权、R3 typed plan、一次性审批、staging、原生 `fw3 -q print`/`fw4 check`、apply/reload、
  5 秒独立 helper 超时回滚和 `rolled_back` 审计状态均成功；回滚后的整个
  `/etc/config` 聚合 SHA-256 与写入前完全一致，所有运行态资料已从 `/tmp` 清理。
- `scripts/run-openwrt-device-network-rollback-smoke.sh` 已在 OpenWrt 21.02
  真机通过：禁用 Agent-owned 路由完成 network UCI staging、netifd reload、R3
  confirmed-commit 超时回滚、ChangeSet 状态同步和精确持久配置恢复。
