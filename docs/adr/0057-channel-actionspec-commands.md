# ADR 0057: Channel ActionSpec commands

## 状态

已实现。

## 决策

用户和厂商的声明式 ActionSpec 通过统一 Channel 命令面暴露：

- `action_list`：列出当前平台可用 action；
- `action_run`：只执行 manifest 声明为 `read_only` 的 action；
- `action_plan`：把受信任的 change template 展开为 firewall/network typed ChangeSet；
- `action_reload`：重新扫描 manifest，仅允许当前 actor 的 `device-admin` capability。

微信/企业微信文本入口使用 `/action-*`，MQTT 使用版本化 JSON。输入只作为 bounded
JSON 交给 ActionRegistry；执行沿用固定 executable/argv、空环境、文件 owner、超时、
并发和输出上限，绝不进行 shell 拼接。变更 action 不直接写平台，而是复用现有
inventory、digest、approval、rollback 和 confirmed-commit 流程。
