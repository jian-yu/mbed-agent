# v0.2.0 发布边界

当前代码仍保持 `0.1.0`，本文件定义下一次正式版本的发布门槛；完成所有门槛前不
创建 `v0.2.0` tag，也不把 RC 产物标记为正式版。

## 版本范围

v0.2.0 的核心不是新增配置域，而是把已有 OpenWrt 21+、通用 Linux firewall/network、
MQTT、微信 ClawBot 和企业微信文本 Channel 做成可验证交付基线：

- capability 矩阵与实际 dispatcher 一致；
- SQLite/WAL、日志、artifact、rollback 不突破 `/tmp` 配额；
- OpenWrt SDK 产物能按 release/target/subtarget 重建并校验 checksum；
- fw3/fw4、nftables/iptables 的变更事务具备集成测试证据；
- daemon idle RSS、release binary 大小和非配置持久化写入有门禁；
- 变更、回滚、Channel 重连和重复消息行为有可追溯结果。

## RC 门槛

1. `cargo fmt --check`、`cargo clippy -D warnings`、workspace tests 全部通过。
2. `openwrt/targets.tsv` 校验通过，至少完成一组 x86/64 SDK package build。
3. OpenWrt 21.02 fw3 和 22.03+ fw4 至少各完成一次 QEMU 或真实设备事务测试。
4. 通用 Linux nftables 和 iptables 至少各完成一次 namespace/真实内核测试。
5. 运行态 Flash 写入快照只允许配置和批准的业务配置变化。
6. 使用 `scripts/prepare-release-artifacts.sh` 生成 release binary、checksum、
   Cargo 依赖图（SBOM 输入）和构建元数据；组织级发布服务再将依赖图转换为要求的
   SPDX/CycloneDX SBOM。
7. 完成 72 小时 Channel 重连/重复消息/低水位测试后，才把 RC 提升为正式版。
