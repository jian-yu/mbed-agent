# ADR 0059: Generic Linux Agent-owned policy rules

## 状态

已实现首个普通 Linux policy rule 可写切片。

## 决策

在 generic Linux 上，Agent 可以通过现有 typed ChangeSet 生命周期管理 IPv4/IPv6
policy rule，但不接管发行版、NetworkManager、systemd-networkd 或厂商 supervisor
的规则。Agent-owned 规则使用保留的 ephemeral preference 范围 `32000..=32063`；
范围外规则只读。路由继续使用 numeric protocol `186` 标记 ownership。

`ip -j rule show` 是唯一库存来源。可表达的 source/destination CIDR、input/output
interface、fwmark/mask、lookup table、blackhole、unreachable 和 prohibit 进入 typed
inventory；未知 selector、`goto`、suppress、UID、端口等无法闭合表达的规则被忽略，
但若出现在 Agent 保留范围则 fail closed，避免误接管。

创建、更新、删除和 policy priority move 都经过 fresh inventory、digest、动态风险、
device-admin、一次性 approval、固定 `ip -batch`、独立反向 batch、live verify 和
confirmed-commit。canonical state 与 route 共用同一个 boot-bound `/tmp` SQLite 记录；
孤儿、漂移、跨 boot 或保留范围内未知规则都会阻止计划与执行。任何运行态写入仍不
落 Flash，重启后不恢复。

## 安全边界

- 命令 runner 只新增固定的 `ip -j rule show`，不接受 caller-provided argv 或 shell。
- policy rule action 与 table 组合由 `agent-core` typed validator 约束；地址族、fwmark
  mask、priority 和 selector 都有界校验。
- reserved preference 冲突按 native drift 处理，不尝试删除或改写未知规则。
- rollback 与确认复用现有 first-decision-wins、独立 helper、超时和 durable outcome。
