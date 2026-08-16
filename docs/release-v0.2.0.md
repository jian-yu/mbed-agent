# v0.2.0 发布边界

配套变更记录见仓库根目录的 `CHANGELOG.md`。

当前代码仍保持 `0.1.0`，本文件定义下一次正式版本的发布门槛；完成所有门槛前不
创建 `v0.2.0` tag，也不把 RC 产物标记为正式版。

## 版本范围

v0.2.0 的核心不是新增高风险配置域，而是把已有 OpenWrt 21+、通用 Linux
firewall/network、MQTT、微信 ClawBot、企业微信文本 Channel 和多 LLM fallback
路由做成可验证交付基线：

- capability 矩阵与实际 dispatcher 一致；
- SQLite/WAL、日志、artifact、rollback 不突破 `/tmp` 配额；
- OpenWrt target/capability 矩阵与实际 dispatcher 一致；SDK 打包流程作为独立的可选交付工具维护；
- fw3/fw4、nftables/iptables 的变更事务具备集成测试证据；
- daemon idle RSS、release binary 大小和非配置持久化写入有门禁；
- 变更、回滚、Channel 重连和重复消息行为有可追溯结果。

## RC 门槛

1. `cargo fmt --check`、`cargo clippy -D warnings`、workspace tests 全部通过。
2. `openwrt/targets.tsv` 校验通过；本版本不要求官方 SDK `.ipk` 构建或设备安装。
3. OpenWrt 21.02 fw3 和 22.03+ fw4 至少各完成一次 QEMU 或真实设备事务测试。
4. 通用 Linux nftables 和 iptables/ip6tables 至少各完成一次完整 daemon 事务测试；
   原生 namespace smoke 作为底层控制面前置证据。
5. 运行态 Flash 写入快照只允许配置和批准的业务配置变化。
6. 使用 `scripts/prepare-release-artifacts.sh` 生成 release binary、checksum、
   Cargo 依赖图（SBOM 输入）和构建元数据；组织级发布服务再将依赖图转换为要求的
   SPDX/CycloneDX SBOM。
7. 完成 72 小时 Channel 重连/重复消息/低水位测试后，才把 RC 提升为正式版。

## 当前真机证据

- 2026-08-15 在 OpenWrt 24.10.8 `bcm27xx/bcm2711` 上完成静态 aarch64 musl
  binary、daemon、ping/status/capabilities、全部 13 个被动诊断以及
  firewall/network inventory smoke。
- 两次 smoke 均确认 `/etc/config` 前后聚合 SHA-256 一致，且测试使用的进程、
  SQLite/WAL、socket、日志、binary 和配置副本均从 `/tmp` 清理。
- fw3 和 fw4 防火墙写事务均已完成真实的 `device-admin` 提权、R3 plan、一次性
  审批、原生校验、apply/reload、5 秒 confirmed-commit 超时、独立 helper 回滚和
  ChangeSet `rolled_back` 状态同步；回滚后 `/etc/config` 聚合 SHA-256 精确恢复。
- OpenWrt network UCI 写事务也已在 21.02 真机完成同样的提权、审批、reload、
  超时回滚和精确恢复验收。
- `scripts/prepare-release-artifacts.sh`、checksum/manifest/SBOM 输入和
  `scripts/check-release-footprint.sh` 已在本地通过；此前 aarch64 musl 交叉二进制及
  当前验证产物均低于 8 MiB 门槛。原生 daemon idle RSS 实测 9,856 KiB，低于 64 MiB
  门槛。
- `scripts/run-linux-firewall-namespace-smoke.sh` 已在 Docker Alpine Linux
  特权 namespace 中通过 nftables 及 iptables/ip6tables 原生 check、apply、cleanup
  和前后快照一致性验证。
- 2026-08-16 在 Docker Alpine Linux 特权容器中，使用 ARM64 musl daemon 分别完成
  generic nftables 与 iptables/ip6tables 的完整 socket 事务：管理员提权、R3 plan、
  一次性 approval、原生 apply、5 秒 confirmed-commit 超时、独立 helper 回滚、
  SQLite canonical state 与 native snapshot 恢复均通过；iptables 包装器的标准
  `iptables-* -> xtables-nft-multi` 符号链接也已纳入兼容性验收。
- `scripts/check-persistent-write-set.sh` 现在会检查 regular file、目录、删除项和符号链接
  目标变化；`scripts/test-persistent-write-set.sh` 已覆盖允许/拒绝和删除场景。Channel
  协议及 SQLite 去重/重试的有界 preflight 可用
  `MBED_AGENT_CHANNEL_SOAK_ITERS=2000 sh scripts/run-channel-protocol-soak.sh` 重复执行。
- LLM 配置仍兼容原有单 profile `[llm]`，并可增加最多三个 `[[llm.fallbacks]]`；fallback
  在 daemon 启动时一次性校验，不把 API key、路由状态或失败响应写入 SQLite/Flash。
- 本轮代码的主机 release 产物为 7,963,392 bytes，idle RSS 为 10,320 KiB，均低于
  8 MiB/64 MiB 门槛；本机缺少 `aarch64-linux-musl-gcc`，ARM64 musl 重建仍需使用
  CI 的 Zig/cargo-zigbuild 路径。
- 既有基线 ARM64 musl 验证产物为 7,376,520 bytes（SHA-256
  `a92eb2bf94c8bdd47b0f3d809c098318762e5965663cc6f1d41a92f1300a54dd`），低于 8 MiB
  门槛；本轮 fallback 代码变更尚未重新生成该交叉产物，正式 RC 前必须重建并更新
  checksum/manifest。OpenWrt 21.02/fw3 的防火墙和网络事务已经完成逐文件 Flash 写集证据；
  fw4 代表设备的同等快照和 Channel soak 仍是 v0.2.0 的外部发布门槛；官方 SDK
  `.ipk` 构建与设备安装不属于本版本验收范围。
