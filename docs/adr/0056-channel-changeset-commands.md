# ADR 0056: Channel ChangeSet commands

## 状态

已实现首个跨 Channel typed ChangeSet 切片。

## 决策

MQTT、微信 ClawBot 和企业微信智能机器人复用 daemon 已有的 firewall/network
ChangeSet planner，而不是新增 shell 或平台专用命令。Channel 请求可以表达：

- `firewall_inventory` / `network_inventory`
- `firewall_plan` / `network_plan`（JSON 字符串承载 typed mutation 数组）
- `change_get`、`change_approve`、`change_apply`、`change_confirm`、`change_reject`

微信和企业微信文本入口提供同名 `/firewall-*`、`/network-*`、`/change-*` 命令；
MQTT 使用同样的版本化 JSON envelope。所有输入仍经过本地 typed planner、fresh
inventory、ownership/digest、风险分级和资源边界。

ChangeSet 的 actor 取自 Channel 已验证的 `actor_id`。计划创建不自动提升权限；
approve/confirm 需要该 actor 当前 boot-bound 的 `device-admin` capability，
approval token 只使用一次，apply/confirm 继续走现有 rollback 和 confirmed-commit。
一个 actor 不能读取或操作其他 actor 的 ChangeSet。

## 安全边界

Channel 输入不会被拼接成 shell，未知 JSON 字段和未知 mutation 由 typed protocol
拒绝。计划和响应继续使用有界 `/tmp` SQLite；运行态不写 Flash。approval token 仅
作为短期敏感字段传输；ChangeSet 状态库只保存 digest/状态，平台实际配置写入仍受原有
ownership、风险和回滚约束。若 MQTT 为可靠重试而暂存 bounded response，它仍只进入
易失 `/tmp`，不会写入 Flash。
