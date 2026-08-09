# 集成测试入口

本目录记录需要真实内核、OpenWrt 固件或目标设备的测试，不把它们伪装成 host
unit test。

## 通用 Linux namespace

```sh
sh scripts/run-linux-namespace-smoke.sh
```

脚本会尝试创建隔离 network namespace、启用 loopback 并读取 JSON link 状态。
没有 `CAP_NET_ADMIN` 时默认报告 `SKIP`；CI 或设备回归可设置
`MBED_AGENT_NAMESPACE_SMOKE_REQUIRED=1` 将 skip 变为失败。

后续 namespace fixture 应增加 veth、nftables/iptables、dnsmasq、tc/netem，并把
Agent-owned route/firewall transaction 接到真实 daemon socket。

## OpenWrt QEMU

QEMU 测试需要外部提供与 `openwrt/targets.tsv` 对应的 firmware/SDK。每个固件至少
执行 procd 启动、CLI ping、capability 矩阵、fw3/fw4 inventory、ChangeSet apply/
verify/confirm、超时 rollback 和 daemon kill 后 rollback-helper 恢复。

提供 x86/64 固件后，可先执行有界启动 smoke：

```sh
MBED_AGENT_QEMU_READY_PATTERN='procd: - init complete' \
  sh scripts/run-openwrt-qemu-smoke.sh /path/to/openwrt.img
```

smoke 不自动修改固件，使用 QEMU snapshot 模式；ready pattern 必须由调用者根据
固件串口日志显式提供。通过后再由设备测试脚本执行 Agent 事务和 Flash 写入快照。

Flash 写入快照使用：

```sh
sh scripts/check-persistent-write-set.sh BEFORE AFTER \
  etc/config/mbed-agent etc/mbed-agent etc/config/network etc/config/firewall
```

当前仓库不提交固件镜像，避免把大文件或供应商密钥写入仓库；发布流水线应通过
checksum 固定的外部 artifact 注入。
