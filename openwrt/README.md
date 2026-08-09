# OpenWrt 构建矩阵

`targets.tsv` 是当前支持和回归目标的唯一矩阵。它覆盖 OpenWrt 21.02 的
fw3，以及 22.03、23.05、24.10 的 fw4，并为每个版本列出 x86_64、ARMv7、
AArch64 和 MIPS 目标。

当前 feed package 采用“宿主机交叉编译二进制 + OpenWrt SDK 打包”的边界：

```sh
make -C /path/to/openwrt \
  package/mbed-agent/compile V=s \
  MBED_AGENT_BINARY=/path/to/target/release/mbed-agent
```

`MBED_AGENT_BINARY` 必须已经是对应 target/subtarget 的产物；路由器上不执行
Cargo、不下载依赖，也不运行构建工具。正式发布流水线需要为 `targets.tsv` 每一行
绑定固定 SDK URL、SHA256、Rust target 和产物 checksum，然后执行 package install
smoke、procd 启动和 CLI ping。

矩阵校验由 `scripts/validate-openwrt-matrix.sh` 执行，CI 会拒绝缺列、重复目标、
非法防火墙版本或缺少最低版本/架构覆盖的修改。
