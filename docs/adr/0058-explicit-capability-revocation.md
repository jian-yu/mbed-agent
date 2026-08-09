# ADR 0058: Explicit device-admin capability revocation

## 状态

已实现。

## 决策

设备管理员 capability 仍只存在 daemon 内存中，但每个已认证 actor 都可以
显式撤销自己的 capability。所有 Channel 的文本入口支持 `/deauth`，本地同一
可执行文件提供 `mbed-agent auth deauth`；两者都解析为协议层的 `Deauth` 命令，
不会进入 LLM、SQLite 或 Flash。

daemon 通过 `AuthManager::deauth(actor_id)` 删除该 actor 的 boot-bound capability。
撤销按 actor 隔离：不会影响其他 Channel、其他账号或配置中的管理员 verifier。
后续同一 actor 仍可重新执行 `/elevate` 或 `auth elevate`，继续受到密码校验、
失败限速、TTL 和当前 boot 约束。

## 安全边界

- Channel actor ID 必须来自现有适配器的身份边界；命令不接受目标 actor 参数，
  因此不能借撤权接口影响其他用户。
- 撤权成功响应只返回被撤销的 actor ID，不返回密码、hash 或 capability 内容。
- 撤权不写 Flash，也不写易失 SQLite；daemon 重启时 capability 本来就全部失效。
- `/deauthx` 等近似文本不会被误识别为控制命令，而是保留为普通 prompt。
