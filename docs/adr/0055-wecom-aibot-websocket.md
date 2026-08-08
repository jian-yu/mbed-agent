# ADR 0055: 企业微信智能机器人 WSS Channel

## 状态

已实现首个有界文本切片。

## 决策

企业微信 Channel 使用设备直连的智能机器人长连接协议，不经过项目云端
Relay。配置保存 Bot ID、Secret 和 host-only `wss://` endpoint；Secret 只在
root-only 配置文件中持久化，运行时状态和消息去重只落 `/tmp` SQLite。

协议边界参考 WecomTeam 的 Rust/Node SDK 实现：
<https://github.com/WecomTeam/aibot-node-sdk>。

- 连接后发送 `aibot_subscribe`，body 为 `bot_id` 和 `secret`。
- 认证成功后发送 `ping` 心跳；连接异常使用有界指数退避。
- `aibot_msg_callback` 只接受 bounded text，事件、媒体和未知类型忽略。
- 回应使用 `aibot_respond_msg` 的 `stream` body，`finish=true`；ACK 超时仅记
  录并清理 pending，连接健康由心跳 ACK 决定。
- 重复消息通过 `/tmp` SQLite 原子 claim 丢弃；daemon 重启后不恢复消息状态。
- 连续认证失败进入 `needs_rebind`，不会无限重试错误凭据。

CLI 使用：

```sh
printf '%s\n' "$WECOM_BOT_SECRET" |
  mbed-agent channel bind-wecom --bot-id BOT_ID --account default
```

官方智能机器人长连接模式不提供设备侧二维码登录，因此不伪造二维码流程；
需要二维码的产品形态必须由未来独立的官方授权适配器实现。

## 资源与安全界限

默认 websocket frame 32 KiB、入站队列 4、并发回复 4、回复 16 KiB，心跳
30 秒，ACK 5 秒。WSS URL 禁止路径、查询、片段和 userinfo；Secret 不进入
日志、SQLite、LLM 上下文或命令行参数。所有收到的文本仍经过统一
`ChannelRequest` 解码和本地 policy/device-admin 约束。
