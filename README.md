# VPS Netcheck

在 Linux VPS 本机诊断出网、DNS、HTTP/TLS、网络质量和 Telegram 入口。

仓库同时保留两个版本：

| 版本 | 入口 | 状态 |
| --- | --- | --- |
| v2.0.0-rc2 | [`vps-netcheck-v2.sh`](vps-netcheck-v2.sh) | 重构候选版，Python 3.8+，终端自动展示详细报告 |
| v1.5.0 | [`vps-netcheck.sh`](vps-netcheck.sh) | 历史 Bash 版本，原入口保留；存在已记录的误判和修复风险 |

**v2 已在 Linux 容器中通过 83 项自动化测试，包含真实终端、单文件菜单和终端报告；仍需 systemd、iptables、真实双栈和 SSH 回滚实机验收。**
详细范围见[验证记录](docs/verification.md)。

## 使用 v2

Debian/Ubuntu 可以像 v1 一样一行启动；这个启动入口会自动安装缺失依赖、下载并校验固定版本的 v2，然后在交互终端打开菜单：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/M3DaLou/inonescripts/codex/vps-netcheck-v2/v2.sh)
```

普通用户缺依赖时会通过 sudo 安装；已是 root 则直接安装。需要已存在 curl 来获取启动入口。
自动安装是 `v2.sh` 的行为，直接运行 `vps-netcheck-v2.sh` 仍不会自动安装。
无交互终端时使用默认检测；也可在同一行最后加 `--quick`、`--full`、`--telegram-only` 等参数。

### 直接在终端看结果

检测结束后自动展开完整报告：异常汇总、本机网卡/路由、公网 IP、DNS 答案、HTTP 状态与 TCP/TLS/TTFB 耗时、ICMP 丢包与延迟、TCP 成功/失败采样、MTR 每跳结果、测速等。只展示本轮执行的项目，不需要另外打开 JSON。

`report.txt` 保存同一份详细报告；`report.json` 继续保存原始结构化证据。报告末尾同时打印两种文件的路径。

交互菜单提供快速/完整体检、Telegram、指定目标、测速、指定网站、指定 DNS 和双栈检测。指定目标时可输入次数、端口与地址族；输错可重试，`q` 退出。

从仓库取得脚本后，在 Linux 上执行：

```bash
bash vps-netcheck-v2.sh --help
bash vps-netcheck-v2.sh --quick
bash vps-netcheck-v2.sh --family 0 --full --deadline 300
bash vps-netcheck-v2.sh --interactive
```

需要 Bash、Python 3.8+；HTTP 检测需要 curl 7.63+。
ip/ss、ping、mtr 按模块使用；指定 DNS 需要 dig。缺依赖会明确跳过，不自动安装。
普通检测不要求 root；系统修复需要 root 和对应系统能力。

```bash
# 指定目标，选择真实业务端口
bash vps-netcheck-v2.sh --quality-only 1.1.1.1,example.com --port 443 --count 20 --deadline 300

# 指定 DNS，失败不会静默回退系统 DNS
bash vps-netcheck-v2.sh --quick --dns 1.1.1.1,8.8.8.8 --url https://example.com:8443/

# 下载测速需要显式启用
bash vps-netcheck-v2.sh --speed --speed-mb 5 --max-download-mb 30

# 报告包含 JSON、文本及原始命令证据
bash vps-netcheck-v2.sh --quick --output ./reports
```

## 修复与回滚

先查看计划，再显式应用。不会因一次探测自动关闭 IPv6。

```bash
bash vps-netcheck-v2.sh --repair mtu --interface eth0 --value 1400
sudo bash vps-netcheck-v2.sh --repair mtu --interface eth0 --value 1400 --apply --rollback-after 120

# 用上一条命令打印的实际 RUN_ID，检查 SSH/业务后再提交
sudo bash vps-netcheck-v2.sh --commit RUN_ID
# 或立即回滚未提交事务
sudo bash vps-netcheck-v2.sh --rollback RUN_ID
```

未提交的修复由独立 systemd 计时器回滚；该计时器不保证跨重启恢复，pending 阶段不要重启。
MTU/MSS 目前只修改运行时状态；托管的 resolv.conf 会拒绝直接覆盖。
完整边界、其他修复动作、退出码和第三方流媒体入口见[使用说明](docs/v2-guide.html)。

## 仓库结构

```text
src/netcheck.py          v2 检测和 CLI
src/netcheck_repair.py   显式修复、前态保存、提交与回滚
src/netcheck_report.py   终端与文本文件共用的详细报告
tests/                  自动化测试与 v1 缺陷复现
build.py                生成单文件 Bash 及 SHA256SUMS
v2.sh                   自动准备依赖的一行启动入口
vps-netcheck-v2.sh       纳入 Git 的 v2 发布入口
vps-netcheck.sh          保留的 v1.5.0 入口
docs/                   使用说明、原版审查及验证记录
```

修改 `src/` 后重新构建，并把源码、生成的脚本和校验和一起提交。
不要直接修改生成文件 `vps-netcheck-v2.sh`。
`v2.sh` 固定了已发布负载的 commit 和 SHA-256；发布新负载后须同步更新这两个常量，避免启动入口仍指向旧版。

```bash
python3 -m unittest discover -s tests -v
python3 build.py
python3 build.py --check
bash -n vps-netcheck-v2.sh
sha256sum -c SHA256SUMS
git diff --check
```

`build.py --check` 只验证构建产物与源码一致，不写文件。
测试只使用临时目录和本机受控 HTTP 服务；系统修复命令使用 mock。
`.gitattributes` 固定脚本 LF 换行，避免 Windows checkout 破坏 Linux Bash 和校验和。
`.gitignore` 排除 Python 缓存、报告、临时工作目录与 ZIP 打包产物。

## 文档

- [v2 使用说明和已知限制](docs/v2-guide.html)
- [v1 全面审查：32 项问题与改进路线](docs/v1-audit.html)
- [v1 使用文档](docs/README-v1.md)
- [验证记录](docs/verification.md)
- [v1 的 15 项缺陷复现结果](docs/v1-reproductions.txt)

原版复现可运行 `bash tests/reproduce_v1.sh`，夹具写入已忽略的 `tests/test-work/`。
其中 REPRODUCED 表示原版缺陷被复现，不是新版测试通过数。
HTML 文档下载后可在浏览器打开。
