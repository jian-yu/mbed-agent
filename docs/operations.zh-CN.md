# 运维与回滚

## 启动检查

daemon 启动时依次检查配置权限、`/tmp` 路径和容量、SQLite 完整性、平台 firewall
backend、ActionSpec 信任目录，然后启动已配置且已绑定的 Channel。

## 变更流程

```text
inventory → plan → approve → stage → native validate → arm rollback
→ activate → verify → confirm
```

任何阶段失败都应进入 rollback。确认窗口内 daemon 退出、设备管理链路中断或业务
探针失败时，由同一二进制的独立 rollback-helper 恢复本次启动内的快照。

真实 OpenWrt fw3/fw4 设备可使用仓库中的受控回滚验收。该脚本会实际写入并 reload 防火墙，必须
显式授权；测试规则使用不可路由地址、虚构 MAC 和 TCP/9，确认窗口为 5 秒，最终要求
ChangeSet 为 `rolled_back`、原生校验成功且整个 `/etc/config` 哈希精确恢复：

```sh
MBED_AGENT_ALLOW_DEVICE_WRITES=YES \
  scripts/run-openwrt-device-firewall-rollback-smoke.sh \
  root@DEVICE target/aarch64-unknown-linux-musl/release/mbed-agent
```

## 存储压力

优先清理可再生 artifact、已发送 Channel 响应和已完成历史；不得清理未确认变更的
rollback 资料。进入 Emergency 时仅保留 status、认证、confirm、reject 和 rollback。

## Channel 故障

凭据有效时断线自动退避重连；官方 token/secret 失效时进入 `NeedsRebind`。重新绑定
只通过 CLI 官方流程执行，绑定凭据原子写入配置文件，运行态 cursor、去重和重试数据
留在 `/tmp` SQLite。
