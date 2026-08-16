# 平台兼容性

## OpenWrt

| 版本 | 防火墙 | 网络写入 | 状态 |
|---|---|---|---|
| 21.02+ | fw3/iptables（实际 backend 由运行时探测） | UCI typed 子集 | 支持 |
| 22.03+ | fw4/nftables（实际 backend 由服务脚本和命令探测） | UCI typed 子集 | 支持 |
| 23.05/24.10 | fw4/nftables | UCI typed 子集 | 目标回归矩阵 |
| 24.10.8 bcm27xx/bcm2711 | fw4/nftables | UCI typed 子集 | 真机发现、`fw4 check`、aarch64 daemon smoke、防火墙 R3 回滚事务已验证 |
| 低于 21 | 不支持写入 | 不支持写入 | 启动能力检查拒绝 |

OpenWrt 写入始终通过 UCI、fw3/fw4 和 netifd 原生控制面。PPPoE、Bond、VRF、
高级 IPv6 PD、完整 DSA bridge-vlan 和未建模的厂商字段不会被猜测写入。

## 通用 Linux

支持平台发现、systemd/OpenRC/BusyBox 服务包装，以及 nftables/iptables 防火墙。
网络写入仅限 Agent-owned 的运行态地址 profile、protocol 186 路由和保留优先级
policy rule；不会修改第三方网络管理器或未声明 ownership 的对象。

## 交付要求

正式发布前必须完成 OpenWrt SDK 的 target/subtarget/架构矩阵、QEMU fw3/fw4
事务测试、Linux network namespace 测试，并记录 binary 大小、RSS、CPU 和非配置
Flash 写入结果。
