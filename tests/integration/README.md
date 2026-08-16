# 集成测试入口

本目录记录需要真实内核、OpenWrt 固件或目标设备的测试，不把它们伪装成 host
unit test。

脱敏后的真机发现和事务结果记录在 `device-evidence.md`；禁止记录私网/公网地址、
凭据、token、SSID 或客户标识。

已有 aarch64 musl binary 时，可从受信任测试主机执行完整只读真机 smoke：

```sh
sh scripts/run-openwrt-device-readonly-smoke.sh \
  root@router target/aarch64-unknown-linux-musl/release/mbed-agent
```

脚本拒绝覆盖设备上已有的 `/tmp/mbed-agent-device-test` 或 `/tmp/mbed-agent`，执行
ping/status/capabilities、全部只读诊断、firewall/network inventory，并比较
`/etc/config` 前后聚合哈希；成功、失败和信号退出都会清理本次创建的临时目录。

## 通用 Linux namespace

```sh
sh scripts/run-linux-namespace-smoke.sh
```

脚本会尝试创建隔离 network namespace、启用 loopback 并读取 JSON link 状态。
没有 `CAP_NET_ADMIN` 时默认报告 `SKIP`；CI 或设备回归可设置
`MBED_AGENT_NAMESPACE_SMOKE_REQUIRED=1` 将 skip 变为失败。

通用 Linux 防火墙原生控制面使用以下 Docker 入口验收。容器只读挂载仓库，特权只
作用于临时 network namespace，退出后容器自动删除：

```sh
docker run --rm --privileged --network bridge \
  -v "$PWD:/workspace:ro" alpine:3.20 sh -euxc '
    apk add --no-cache iproute2 util-linux nftables iptables
    MBED_AGENT_LINUX_FIREWALL_SMOKE_REQUIRED=1 \
    MBED_AGENT_LINUX_FIREWALL_SMOKE_REQUIRE_BOTH=1 \
    sh /workspace/scripts/run-linux-firewall-namespace-smoke.sh
  '
```

该 smoke 覆盖 nftables check/apply/cleanup、iptables/ip6tables 双栈 restore test、
Agent-owned chain hook 和前后 native snapshot 一致性；typed daemon transaction
仍由 `platform-linux` 测试和真实 Linux daemon socket 回归继续覆盖。

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
