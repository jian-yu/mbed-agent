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

## SDK package build

在已经完成对应 Rust/musl 交叉编译后，可使用以下入口下载官方固定 release 的
SDK，读取同目录 `sha256sums` 校验 SDK，调用 OpenWrt package Makefile，并把产物
和 SDK 摘要写入 `dist/openwrt/`：

```sh
sh scripts/build-openwrt-sdk-package.sh \
  23.05.5 x86 64 \
  target/x86_64-unknown-linux-musl/release/mbed-agent
```

脚本只接受 `targets.tsv` 中存在的 release/target/subtarget 组合；构建缓存固定在
`/tmp/mbed-agent-openwrt-sdk-build`，完成后默认删除。设置
`MBED_AGENT_KEEP_SDK=1` 可保留该明确目录用于排障。
脚本还会校验输入是匹配矩阵架构的 ELF；在 CI/cache 中可设置
`MBED_AGENT_SDK_ARCHIVE=/path/to/openwrt-sdk.tar.xz` 复用已下载的官方 SDK，仍会
使用 release 目录的 `sha256sums` 做校验。

## Release artifacts

正式或 RC 构建可用以下入口聚合 binary、依赖图、工具链信息、manifest 和 checksum：

```sh
sh scripts/prepare-release-artifacts.sh target/release/mbed-agent
```

输出目录默认为 `dist/release/`；`sbom.cargo.json` 是设备构建不依赖额外工具的原始
依赖清单，发布服务应在上传前转换为组织要求的 SPDX/CycloneDX SBOM。交叉构建时
可设置 `MBED_AGENT_METADATA_PLATFORM`，使 Cargo 依赖图只解析目标平台。
校验聚合产物时在输出目录执行 `sha256sum -c checksums.sha256`。
