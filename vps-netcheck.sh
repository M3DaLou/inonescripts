#!/usr/bin/env bash
# vps-netcheck.sh — Debian VPS 出网一键体检
# 在节点本机运行，检查「这台机器访问外网」是否正常。
# 默认只体检、不改系统。修复 / 流媒体 / Telegram / 指定 DNS 都是可选参数。

set -uo pipefail

VERSION="1.4.0"
MODE="default"
CUSTOM_URLS=()
CUSTOM_FILE=""
NO_INSTALL=0
LOG=""
ASSUME_YES=0
UNLOCK=0
UNLOCK_ONLY=0
UNLOCK_REGION="auto"
UNLOCK_IP="4"
TELEGRAM=0
TELEGRAM_ONLY=0
DNS_SERVERS=()
FIX_PROMPT=0
FIX_IPV6=0
UNDO_IPV6=0
FIX_MTU=0
FIX_MTU_VAL=""
FIX_DNS=0
FIX_GAI=0
UNDO_GAI=0
FIX_MSS=0
UNDO_MSS=0
FIX_NTP=0
FIX_FLUSH_DNS=0
SKIP_CHECK=0
FORCE_INTERACTIVE=0
DEFAULT_IFACE=""
IPV6_BROKEN=0
MTU_SUGGEST=""
CLOCK_UNSYNCED=0
CF_LOC=""

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
DIM='\033[2m'
RST='\033[0m'

PASS_N=0
WARN_N=0
FAIL_N=0
FINDINGS=()

usage() {
  cat <<'EOF'
vps-netcheck.sh — Debian VPS 出网一键体检

用法:
  bash vps-netcheck.sh              # 终端里直接回车：进入交互菜单（推荐）
  bash vps-netcheck.sh [选项]       # 给脚本/自动化用，不进菜单

体检:
  --quick              快速模式：跳过测速、traceroute
  --full               完整模式：加上 traceroute
  --url URL            额外探测一个网址（可重复）
  --file FILE          从文件读取额外网址（一行一个）
  --dns IP[,IP...]     指定 DNS（只影响本脚本的解析/HTTPS/--unlock/--telegram，不改系统）
  --no-install         缺工具时不自动 apt 安装

流媒体解锁（可选，调用 lmc999/RegionRestrictionCheck）:
  --unlock             体检后再跑流媒体解锁
  --unlock-only        只跑流媒体，跳过网络体检
  --unlock-region N    区域编号，默认 auto（按 IP 归属猜）
  --unlock-ip 4|6|0    4=只 IPv4（默认） 6=只 IPv6  0=两者都测

Telegram（可选，测节点到 TG 机房/官网，用来排除「TG 服务器坏了」）:
  --telegram           体检后再测 Telegram
  --telegram-only      只测 Telegram，跳过网络体检

可选修复（默认不执行；改系统前会问一声，--yes 才跳过确认）:
  --fix                体检结束后，对发现的问题逐项询问是否修复
  --fix-ipv6           持久关闭 IPv6（写 sysctl.d，重启仍生效）
  --undo-ipv6          撤销本脚本写过的「关闭 IPv6」
  --fix-mtu [N]        把默认网卡 MTU 改为 N（默认 1400）并开机保持
  --fix-dns            把系统 DNS 改成 --dns 指定的地址（影响整机，慎用）
  --fix-ipv4-pref      出站优先 IPv4（改 gai.conf，不关 IPv6）
  --undo-ipv4-pref     撤销「出站优先 IPv4」
  --fix-mss            加上 TCP MSS 钳位（配合偏低的 MTU）
  --undo-mss           撤销 MSS 钳位
  --fix-ntp            打开 NTP，同步系统时钟
  --flush-dns          刷新本机 DNS 缓存
  --yes                修复类操作不再询问

其它:
  --interactive          强制进入交互菜单
  --list-unlock-regions  列出流媒体区域编号后退出
  -h, --help             显示帮助

建议用 root 跑。结果写到 /tmp/vps-netcheck-时间戳.log
EOF
}

print_unlock_regions() {
  cat <<'EOF'
  a / auto  按这台机器 IP 归属自动选（推荐）
  0         只测跨国平台（Netflix、Disney+、YouTube、ChatGPT 等，较快）
  1         跨国 + 台湾
  2         跨国 + 香港
  3         跨国 + 日本
  4         跨国 + 北美
  5         跨国 + 南美
  6         跨国 + 欧洲
  7         跨国 + 大洋洲
  8         跨国 + 韩国
  9         跨国 + 东南亚
  10        跨国 + 印度
  11        跨国 + 非洲
  66        全部平台（最全，也最慢）
  88        Instagram 音乐
  99        体育直播
EOF
}

list_unlock_regions() {
  echo "流媒体区域编号（与 lmc999/RegionRestrictionCheck 一致）："
  print_unlock_regions
}

valid_unlock_region() {
  local r="$1"
  [[ "$r" == "auto" || "$r" == "a" ]] && return 0
  echo "$r" | grep -Eq '^[0-9]$|^1[0-1]$|^99$|^88$|^66$'
}

need_arg() {
  if [[ $# -lt 2 || -z "${2:-}" || "$2" == --* ]]; then
    echo "参数 $1 后面需要一个值"
    exit 1
  fi
}

ORIG_ARGC=$#
while [[ $# -gt 0 ]]; do
  case "$1" in
    --interactive|-i) FORCE_INTERACTIVE=1; shift ;;
    --quick) MODE="quick"; shift ;;
    --full) MODE="full"; shift ;;
    --url) need_arg "$@"; CUSTOM_URLS+=("$2"); shift 2 ;;
    --file) need_arg "$@"; CUSTOM_FILE="$2"; shift 2 ;;
    --dns)
      need_arg "$@"
      IFS=',' read -r -a DNS_SERVERS <<< "$2"
      shift 2
      ;;
    --unlock) UNLOCK=1; shift ;;
    --unlock-only) UNLOCK=1; UNLOCK_ONLY=1; shift ;;
    --unlock-region) need_arg "$@"; UNLOCK_REGION="$2"; shift 2 ;;
    --unlock-ip) need_arg "$@"; UNLOCK_IP="$2"; shift 2 ;;
    --telegram) TELEGRAM=1; shift ;;
    --telegram-only) TELEGRAM=1; TELEGRAM_ONLY=1; shift ;;
    --fix) FIX_PROMPT=1; shift ;;
    --fix-ipv6) FIX_IPV6=1; shift ;;
    --undo-ipv6) UNDO_IPV6=1; shift ;;
    --fix-mtu)
      FIX_MTU=1
      if [[ "${2:-}" =~ ^[0-9]+$ ]]; then
        FIX_MTU_VAL="$2"
        shift 2
      else
        shift
      fi
      ;;
    --fix-dns) FIX_DNS=1; shift ;;
    --fix-ipv4-pref) FIX_GAI=1; shift ;;
    --undo-ipv4-pref) UNDO_GAI=1; shift ;;
    --fix-mss) FIX_MSS=1; shift ;;
    --undo-mss) UNDO_MSS=1; shift ;;
    --fix-ntp) FIX_NTP=1; shift ;;
    --flush-dns) FIX_FLUSH_DNS=1; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    --no-install) NO_INSTALL=1; shift ;;
    --list-unlock-regions) list_unlock_regions; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1"; usage; exit 1 ;;
  esac
done

if [[ $FIX_DNS -eq 1 && ${#DNS_SERVERS[@]} -eq 0 ]]; then
  echo "--fix-dns 必须同时指定 --dns 1.1.1.1,8.8.8.8"
  exit 1
fi
if [[ "$UNLOCK_IP" != "4" && "$UNLOCK_IP" != "6" && "$UNLOCK_IP" != "0" ]]; then
  echo "--unlock-ip 只能是 4、6 或 0"
  exit 1
fi

prompt_val() {
  local p="$1" d="${2:-}"
  local a=""
  if [[ -n "$d" ]]; then
    read -r -p "$p [$d]: " a || true
    printf '%s' "${a:-$d}"
  else
    read -r -p "$p: " a || true
    printf '%s' "$a"
  fi
}

ask_unlock_options() {
  echo
  echo "测哪些流媒体区域？（与 https://github.com/lmc999/RegionRestrictionCheck 相同）"
  print_unlock_regions
  echo
  local region
  while true; do
    region=$(prompt_val "输入编号" "auto")
    [[ "$region" == "a" ]] && region="auto"
    if valid_unlock_region "$region"; then
      UNLOCK_REGION="$region"
      break
    fi
    echo "  编号不对，请按上面的列表重输。"
  done

  echo
  echo "测 IPv4 还是 IPv6？"
  echo "  4) 只测 IPv4（推荐，半残 IPv6 的机器请选这个）"
  echo "  6) 只测 IPv6"
  echo "  0) IPv4 + IPv6 都测"
  local ip
  while true; do
    ip=$(prompt_val "输入 4 / 6 / 0" "4")
    if [[ "$ip" == "4" || "$ip" == "6" || "$ip" == "0" ]]; then
      UNLOCK_IP="$ip"
      break
    fi
    echo "  只能填 4、6 或 0。"
  done
}

ask_dns_optional() {
  echo
  echo "要指定 DNS 吗？只影响这一轮检测，不会改系统。"
  echo "直接回车 = 用机器现在的 DNS。例: 1.1.1.1  或  1.1.1.1,8.8.8.8"
  local dns
  dns=$(prompt_val "DNS" "")
  if [[ -n "$dns" ]]; then
    IFS=',' read -r -a DNS_SERVERS <<< "$dns"
  fi
}

ask_extra_url() {
  echo
  echo "有特别卡的网站要加测吗？直接回车跳过。"
  local u
  u=$(prompt_val "网址，如 https://www.netflix.com" "")
  if [[ -n "$u" ]]; then
    CUSTOM_URLS+=("$u")
  fi
}

ask_telegram_optional() {
  echo
  echo "要加测 Telegram 吗？看这台机器到 TG 机房的延迟，以及官网/安装包下载速度。"
  echo "用来排除「是不是 TG 服务器自己慢」。直接回车 = 不测。"
  local yn
  yn=$(prompt_val "加测 Telegram" "N")
  [[ "$yn" == "y" || "$yn" == "Y" ]] && TELEGRAM=1
}

ask_depth() {
  echo
  echo "体检要做到哪一步？"
  echo "  1) 快速（约 40 秒，跳过测速和路由）"
  echo "  2) 默认（推荐，约 1–2 分钟）"
  echo "  3) 完整（再加上 traceroute）"
  local d
  while true; do
    d=$(prompt_val "输入 1 / 2 / 3" "2")
    case "$d" in
      1) MODE="quick"; break ;;
      2) MODE="default"; break ;;
      3) MODE="full"; break ;;
      *) echo "  请输入 1、2 或 3。" ;;
    esac
  done
}

run_interactive() {
  printf '\n'
  printf '%b\n' "${BLD}VPS 出网体检 v${VERSION}${RST}"
  echo "测的是「这台机器自己访问外网」。改系统的操作都会再问你一次。"
  echo
  echo "你要做什么？"
  echo "  1) 网络体检（推荐）"
  echo "  2) 网络体检 + 流媒体解锁"
  echo "  3) 只测流媒体解锁"
  echo "  4) 只测 Telegram（到 TG 机房延迟 + 官网下载）"
  echo "  5) 修复（关 IPv6 / 改 MTU / 改 DNS）"
  echo "  6) 看命令行帮助"
  echo "  q) 退出"
  echo

  local act yn
  while true; do
    act=$(prompt_val "输入序号" "1")
    case "$act" in
      1|2|3|4|5|6|q|Q) break ;;
      *) echo "  请输入 1–6 或 q。" ;;
    esac
  done

  case "$act" in
    q|Q) echo "已取消。"; exit 0 ;;
    6) usage; exit 0 ;;
    1)
      ask_depth
      ask_extra_url
      ask_telegram_optional
      ask_dns_optional
      yn=$(prompt_val "体检结束后，若发现问题是否询问修复" "Y")
      [[ "$yn" == "y" || "$yn" == "Y" ]] && FIX_PROMPT=1
      ;;
    2)
      UNLOCK=1
      ask_depth
      ask_unlock_options
      ask_extra_url
      ask_telegram_optional
      ask_dns_optional
      yn=$(prompt_val "体检结束后，若发现问题是否询问修复" "Y")
      [[ "$yn" == "y" || "$yn" == "Y" ]] && FIX_PROMPT=1
      ;;
    3)
      UNLOCK=1
      UNLOCK_ONLY=1
      ask_unlock_options
      ask_dns_optional
      ;;
    4)
      TELEGRAM=1
      TELEGRAM_ONLY=1
      ask_dns_optional
      ;;
    5)
      echo
      echo "要做哪项修复？"
      echo "  1)  先体检，再按结果询问（最稳）"
      echo "  2)  持久关闭 IPv6"
      echo "  3)  撤销「关闭 IPv6」"
      echo "  4)  出站优先 IPv4（不关 IPv6，半残 IPv6 推荐这个）"
      echo "  5)  撤销「出站优先 IPv4」"
      echo "  6)  把默认网卡 MTU 改为 1400（并开机保持）"
      echo "  7)  加上 TCP MSS 钳位（配合 MTU）"
      echo "  8)  撤销 MSS 钳位"
      echo "  9)  修改系统 DNS（影响整机，慎用）"
      echo "  10) 刷新本机 DNS 缓存"
      echo "  11) 同步系统时钟（NTP）"
      local fx
      while true; do
        fx=$(prompt_val "输入序号" "1")
        case "$fx" in
          1)
            FIX_PROMPT=1
            ask_depth
            break
            ;;
          2) FIX_IPV6=1; SKIP_CHECK=1; break ;;
          3) UNDO_IPV6=1; SKIP_CHECK=1; break ;;
          4) FIX_GAI=1; SKIP_CHECK=1; break ;;
          5) UNDO_GAI=1; SKIP_CHECK=1; break ;;
          6)
            FIX_MTU=1
            FIX_MTU_VAL=$(prompt_val "MTU 数值" "1400")
            SKIP_CHECK=1
            break
            ;;
          7) FIX_MSS=1; SKIP_CHECK=1; break ;;
          8) UNDO_MSS=1; SKIP_CHECK=1; break ;;
          9)
            FIX_DNS=1
            SKIP_CHECK=1
            local dns
            dns=$(prompt_val "系统 DNS，例 1.1.1.1,8.8.8.8" "1.1.1.1,8.8.8.8")
            IFS=',' read -r -a DNS_SERVERS <<< "$dns"
            break
            ;;
          10) FIX_FLUSH_DNS=1; SKIP_CHECK=1; break ;;
          11) FIX_NTP=1; SKIP_CHECK=1; break ;;
          *) echo "  请输入 1–11。" ;;
        esac
      done
      ;;
  esac

  echo
  echo "好，开始……"
  echo
}

if [[ $FORCE_INTERACTIVE -eq 1 ]]; then
  if [[ ! -t 0 ]]; then
    echo "当前不是交互终端，无法显示菜单。请直接 SSH 上去跑，或改用命令行参数。"
    exit 1
  fi
  run_interactive
elif [[ $ORIG_ARGC -eq 0 && -t 0 && -t 1 ]]; then
  run_interactive
fi

ts() { date '+%F %T'; }
hr() { printf '\n%s\n' "----------------------------------------"; }

log() {
  local line="$1"
  printf '%s\n' "$line"
  [[ -n "$LOG" ]] && printf '%s\n' "$line" >> "$LOG"
}

# 去掉颜色后再写入日志
logc() {
  local line="$1"
  printf '%b\n' "$line"
  if [[ -n "$LOG" ]]; then
    printf '%b\n' "$line" | sed -r 's/\x1B\[[0-9;]*[mK]//g' >> "$LOG"
  fi
}

section() {
  hr
  logc "${BLD}${CYN}[$1]${RST} $2"
}

ok()   { PASS_N=$((PASS_N + 1)); logc "  ${GRN}[OK]${RST}   $1"; }
warn() { WARN_N=$((WARN_N + 1)); logc "  ${YEL}[WARN]${RST} $1"; FINDINGS+=("WARN: $1"); }
fail() { FAIL_N=$((FAIL_N + 1)); logc "  ${RED}[FAIL]${RST} $1"; FINDINGS+=("FAIL: $1"); }
info() { logc "  ${DIM}$1${RST}"; }

have() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    fail "$1 需要 root"
    return 1
  fi
  return 0
}

confirm() {
  local msg="$1"
  if [[ $ASSUME_YES -eq 1 ]]; then
    info "已指定 --yes，执行: $msg"
    return 0
  fi
  if [[ ! -t 0 ]]; then
    warn "非交互终端，跳过: $msg（加上 --yes 才会执行）"
    return 1
  fi
  local ans=""
  read -r -p "  $msg [y/N] " ans || true
  [[ "$ans" == "y" || "$ans" == "Y" ]]
}

detect_wan_iface() {
  ip route 2>/dev/null | awk '/^default/{print $5; exit}'
}

awk_gt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 > b + 0) }'; }
awk_ge() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 >= b + 0) }'; }
fmt_s()  { awk -v n="$1" 'BEGIN { printf "%.3f", n + 0 }'; }
fmt_ms() { awk -v n="$1" 'BEGIN { printf "%.0f", (n + 0) * 1000 }'; }

need_root_install() {
  local pkgs=("$@")
  local missing=()
  local p
  for p in "${pkgs[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
  done
  [[ ${#missing[@]} -eq 0 ]] && return 0
  if [[ $NO_INSTALL -eq 1 ]]; then
    warn "缺少软件包: ${missing[*]}（已指定 --no-install，跳过安装）"
    return 1
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    warn "缺少软件包: ${missing[*]}。请用 root 重跑，或先执行: apt-get install -y ${missing[*]}"
    return 1
  fi
  info "正在安装: ${missing[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" >/dev/null 2>&1 || {
    warn "自动安装失败: ${missing[*]}"
    return 1
  }
  ok "已安装: ${missing[*]}"
}

# ---------- 依赖 ----------
ensure_deps() {
  section "0" "检查依赖"
  local pkgs=()
  have curl || pkgs+=(curl)
  have ping || pkgs+=(iputils-ping)
  have dig || pkgs+=(dnsutils)
  have ip || pkgs+=(iproute2)
  have openssl || pkgs+=(openssl)
  [[ "$MODE" == "full" ]] && { have traceroute || pkgs+=(traceroute); }
  dpkg -s ca-certificates >/dev/null 2>&1 || pkgs+=(ca-certificates)

  if [[ ${#pkgs[@]} -gt 0 ]]; then
    need_root_install "${pkgs[@]}" || true
  fi

  have curl || { fail "没有 curl，后续 HTTPS 探测无法进行"; return 1; }
  have ping || warn "没有 ping，将跳过 ICMP / MTU"
  have dig || warn "没有 dig，DNS 对比会变弱（可用 nslookup 兜底）"
  ok "基础工具可用"
}

# ---------- 本机概况 ----------
check_system() {
  section "1" "本机概况"
  local os="unknown" kern load mem disk idle
  [[ -f /etc/os-release ]] && os=$(. /etc/os-release; echo "${PRETTY_NAME:-$ID}")
  kern=$(uname -r)
  load=$(awk '{print $1","$2","$3}' /proc/loadavg)
  mem=$(free -h | awk '/Mem:/{print $3"/"$2}')
  disk=$(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')
  info "主机: $(hostname)  |  系统: $os  |  内核: $kern"
  info "负载: $load  |  内存: $mem  |  根分区: $disk"
  info "时间: $(date '+%F %T %z')  |  时区: $(cat /etc/timezone 2>/dev/null || echo unknown)"

  local cores
  cores=$(nproc 2>/dev/null || echo 1)
  local l1
  l1=$(awk '{print $1}' /proc/loadavg)
  if awk_gt "$l1" "$(awk -v c="$cores" 'BEGIN{print c * 2}')"; then
    warn "1 分钟负载 $l1（${cores} 核），机器本身很忙，体感卡不一定是网络"
  else
    ok "系统负载正常（$l1 / ${cores} 核）"
  fi

  local used_pct
  used_pct=$(df / | awk 'NR==2{gsub(/%/,"",$5); print $5}')
  if [[ -n "$used_pct" ]] && awk_ge "$used_pct" 95; then
    warn "根分区已用 ${used_pct}%，磁盘满可能导致各种奇怪故障"
  fi
}

check_clock() {
  section "2" "系统时间（时间不准会导致 HTTPS/TLS 失败）"
  if have timedatectl; then
    timedatectl | sed 's/^/  /' | while IFS= read -r line; do info "${line#  }"; done
    if timedatectl | grep -q 'System clock synchronized: yes'; then
      ok "时钟已同步"
    else
      CLOCK_UNSYNCED=1
      warn "时钟可能未同步。TLS 证书校验会失败，表现为「部分 HTTPS 网站打不开」"
    fi
  else
    info "当前时间: $(date -Is)"
    ok "已记录本机时间（无 timedatectl，无法判断是否同步）"
  fi
}

# ---------- 网络身份 ----------
PUBLIC_V4=""
PUBLIC_V6=""
HAS_LOCAL_V6=0

fetch_url() {
  curl -fsS --max-time 8 --connect-timeout 5 "$@" 2>/dev/null || true
}

check_identity() {
  section "3" "网卡 / 路由 / 公网身份"
  DEFAULT_IFACE=$(detect_wan_iface)
  [[ -n "$DEFAULT_IFACE" ]] && info "默认出网网卡: $DEFAULT_IFACE"
  if have ip; then
    ip -br addr | while IFS= read -r line; do info "$line"; done
    info "默认路由:"
    ip route | awk '/default/{print}' | while IFS= read -r line; do info "  $line"; done
  else
    ifconfig 2>/dev/null | head -n 40 | while IFS= read -r line; do info "$line"; done
  fi

  if ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
    HAS_LOCAL_V6=1
    info "本机有全局 IPv6 地址"
  else
    info "本机没有全局 IPv6 地址"
  fi

  local cf sb ipinfo
  cf=$(fetch_url https://www.cloudflare.com/cdn-cgi/trace)
  sb=$(fetch_url https://api.ip.sb/geoip)
  ipinfo=$(fetch_url https://ipinfo.io/json)

  if [[ -n "$cf" ]]; then
    PUBLIC_V4=$(printf '%s\n' "$cf" | awk -F= '/^ip=/{print $2}')
    CF_LOC=$(printf '%s\n' "$cf" | awk -F= '/^loc=/{print $2}')
    info "Cloudflare trace:"
    printf '%s\n' "$cf" | awk -F= '/^(ip|loc|colo|http|tls|warp)=/{print}' | while IFS= read -r line; do info "  $line"; done
  fi

  if [[ -z "$PUBLIC_V4" ]]; then
    PUBLIC_V4=$(fetch_url -4 https://ifconfig.me/ip)
  fi
  PUBLIC_V6=$(fetch_url -6 https://ifconfig.me/ip)
  [[ -z "$PUBLIC_V6" ]] && PUBLIC_V6=$(fetch_url -6 https://api64.ipify.org)

  if [[ -n "$PUBLIC_V4" ]]; then
    ok "公网 IPv4: $PUBLIC_V4"
  else
    fail "拿不到公网 IPv4（出网或探测源都失败）"
  fi

  if [[ -n "$PUBLIC_V6" ]]; then
    ok "公网 IPv6: $PUBLIC_V6"
  elif [[ $HAS_LOCAL_V6 -eq 1 ]]; then
    warn "本机有 IPv6 地址，但访问不了外网 IPv6（典型「IPv6 半残」，部分网站会卡住）"
  else
    info "无公网 IPv6（只有 IPv4 也可以，后面会再验证）"
  fi

  if [[ -n "$ipinfo" ]]; then
    info "ipinfo: $(printf '%s' "$ipinfo" | tr '\n' ' ' | head -c 400)"
  elif [[ -n "$sb" ]]; then
    info "ip.sb: $(printf '%s' "$sb" | tr '\n' ' ' | head -c 400)"
  fi
}

# ---------- DNS ----------
dns_lookup() {
  local name="$1" server="${2:-}"
  if have dig; then
    if [[ -n "$server" ]]; then
      dig +time=3 +tries=1 +short A "$name" "@$server" 2>/dev/null | awk 'NF && $1 !~ /^;/' | head -n 3 | tr '\n' ' '
    else
      dig +time=3 +tries=1 +short A "$name" 2>/dev/null | awk 'NF && $1 !~ /^;/' | head -n 3 | tr '\n' ' '
    fi
  elif have nslookup; then
    if [[ -n "$server" ]]; then
      nslookup "$name" "$server" 2>/dev/null | awk '/^Address: / && $2 !~ /#/{print $2}' | head -n 3 | tr '\n' ' '
    else
      nslookup "$name" 2>/dev/null | awk '/^Address: / && $2 !~ /#/{print $2}' | head -n 3 | tr '\n' ' '
    fi
  fi
}

dns_time_ms() {
  local name="$1" server="${2:-}"
  if have dig; then
    if [[ -n "$server" ]]; then
      dig +time=3 +tries=1 "$name" "@$server" 2>/dev/null | awk '/Query time:/{print $4; exit}'
    else
      dig +time=3 +tries=1 "$name" 2>/dev/null | awk '/Query time:/{print $4; exit}'
    fi
  fi
}

is_bad_ip() {
  local ip="$1"
  case "$ip" in
    127.*|0.*|10.*|192.168.*|169.254.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
  esac
  return 1
}

check_dns() {
  section "4" "DNS 解析"
  if [[ -f /etc/resolv.conf ]]; then
    info "/etc/resolv.conf:"
    grep -vE '^\s*#' /etc/resolv.conf | sed '/^$/d' | while IFS= read -r line; do info "  $line"; done
  fi
  if have resolvectl; then
    info "resolvectl:"
    resolvectl status 2>/dev/null | awk '/DNS Servers|Current DNS|DNS Domain/{print}' | while IFS= read -r line; do info "  $line"; done
  fi

  if [[ ${#DNS_SERVERS[@]} -gt 0 ]]; then
    info "本轮指定 DNS: ${DNS_SERVERS[*]}（只用于本脚本查询，未改 /etc/resolv.conf）"
  fi

  local domains=(www.google.com www.github.com www.cloudflare.com www.baidu.com chatgpt.com)
  local resolvers=("" "1.1.1.1" "8.8.8.8" "9.9.9.9")
  local labels=("系统DNS" "1.1.1.1" "8.8.8.8" "9.9.9.9")
  local extra
  for extra in "${DNS_SERVERS[@]+"${DNS_SERVERS[@]}"}"; do
    local already=0 r
    for r in "${resolvers[@]}"; do
      [[ "$r" == "$extra" ]] && already=1
    done
    if [[ $already -eq 0 ]]; then
      resolvers+=("$extra")
      labels+=("指定 $extra")
    fi
  done
  local d r i ans tms sys_empty=0 sys_hijack=0 sys_slow=0

  printf "  %-22s" "域名"
  for i in "${!labels[@]}"; do printf " %-28s" "${labels[$i]}"; done
  printf "\n"

  for d in "${domains[@]}"; do
    printf "  %-22s" "$d"
    [[ -n "$LOG" ]] && printf "  %-22s" "$d" >> "$LOG"
    for i in "${!resolvers[@]}"; do
      r="${resolvers[$i]}"
      ans=$(dns_lookup "$d" "$r")
      ans=${ans:-FAIL}
      tms=$(dns_time_ms "$d" "$r")
      local cell="$ans"
      [[ -n "$tms" ]] && cell="$ans ${tms}ms"
      printf " %-28s" "$(echo "$cell" | cut -c1-28)"
      [[ -n "$LOG" ]] && printf " %-28s" "$(echo "$cell" | cut -c1-28)" >> "$LOG"

      if [[ $i -eq 0 ]]; then
        if [[ "$ans" == "FAIL" || -z "${ans// }" ]]; then
          sys_empty=1
        else
          local first
          first=$(echo "$ans" | awk '{print $1}')
          if is_bad_ip "$first"; then
            sys_hijack=1
          fi
        fi
        if [[ -n "$tms" ]] && awk_gt "$tms" 300; then
          sys_slow=1
        fi
      fi
    done
    printf "\n"
    [[ -n "$LOG" ]] && printf "\n" >> "$LOG"
  done

  if [[ $sys_hijack -eq 1 ]]; then
    fail "系统 DNS 返回了内网/回环地址，很像被劫持。先改成 1.1.1.1 或 8.8.8.8 再测网站"
  elif [[ $sys_empty -eq 1 ]]; then
    fail "系统 DNS 有域名解析失败。网站会表现为「打不开 / 很慢再超时」"
  else
    ok "系统 DNS 能解析常见域名"
  fi
  if [[ $sys_slow -eq 1 ]]; then
    warn "系统 DNS 查询超过 300ms。部分网站会先卡在「转圈」，建议改用 1.1.1.1 / 8.8.8.8"
  fi

  # UDP 53 被墙时， dig 默认 UDP 会失败，TCP 可能成功
  if have dig; then
    local udp tcp
    udp=$(dig +time=2 +tries=1 +short A www.google.com @1.1.1.1 2>/dev/null | head -n 1)
    tcp=$(dig +tcp +time=2 +tries=1 +short A www.google.com @1.1.1.1 2>/dev/null | head -n 1)
    if [[ -z "$udp" && -n "$tcp" ]]; then
      warn "DNS UDP/53 可能不通，只有 TCP 能解析。部分程序会解析失败"
    elif [[ -n "$udp" ]]; then
      ok "DNS UDP/53 正常"
    fi
  fi
}

# ---------- ICMP ----------
ping_stats() {
  local target="$1" count="${2:-8}"
  ping -c "$count" -W 2 -n "$target" 2>/dev/null | awk '
    /packet loss/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /%/) {
          loss = $i
          gsub(/[^0-9.]/, "", loss)
        }
      }
    }
    /rtt min/ || /round-trip/ {
      split($4, a, "/")
      min=a[1]; avg=a[2]; max=a[3]; mdev=a[4]
    }
    END {
      if (loss == "") loss="100"
      if (avg == "") avg="-"
      printf "%s %s %s %s %s", loss, min, avg, max, mdev
    }'
}

check_icmp() {
  section "5" "ICMP 连通与丢包（ping）"
  if ! have ping; then
    warn "无 ping 命令，跳过"
    return
  fi

  local targets=(1.1.1.1 8.8.8.8 9.9.9.9 223.5.5.5)
  local t stats loss avg
  local any_ok=0 high_loss=0 high_lat=0

  printf "  %-16s %-8s %-10s %-10s %-10s\n" "目标" "丢包" "avg" "max" "jitter"
  [[ -n "$LOG" ]] && printf "  %-16s %-8s %-10s %-10s %-10s\n" "目标" "丢包" "avg" "max" "jitter" >> "$LOG"

  for t in "${targets[@]}"; do
    stats=$(ping_stats "$t" 8)
    loss=$(echo "$stats" | awk '{print $1}')
    avg=$(echo "$stats" | awk '{print $3}')
    local max mdev
    max=$(echo "$stats" | awk '{print $4}')
    mdev=$(echo "$stats" | awk '{print $5}')
    printf "  %-16s %-8s %-10s %-10s %-10s\n" "$t" "${loss}%" "${avg}ms" "${max}ms" "${mdev}ms"
    [[ -n "$LOG" ]] && printf "  %-16s %-8s %-10s %-10s %-10s\n" "$t" "${loss}%" "${avg}ms" "${max}ms" "${mdev}ms" >> "$LOG"

    if [[ "$loss" != "100" ]]; then
      any_ok=1
      if awk_gt "$loss" 5; then
        high_loss=1
      fi
      if [[ "$t" == "1.1.1.1" || "$t" == "8.8.8.8" ]] && [[ "$avg" != "-" ]] && awk_gt "$avg" 200; then
        high_lat=1
      fi
    fi
  done

  if [[ $any_ok -eq 0 ]]; then
    warn "ICMP 全部失败。很多机房禁 ping，这不一定代表 TCP/HTTPS 不通，下面以 HTTPS 为准"
  else
    ok "ICMP 至少有一个目标可达"
  fi
  if [[ $high_loss -eq 1 ]]; then
    warn "出现 >5% 丢包。网页会表现为偶发卡顿、刷新才好"
  fi
  if [[ $high_lat -eq 1 ]]; then
    warn "到 1.1.1.1 / 8.8.8.8 平均延迟 >200ms，到国际骨干可能偏远或绕路"
  fi
}

# ---------- MTU ----------
check_mtu() {
  section "6" "MTU / 大包（部分网站打不开的常见原因）"
  if ! have ping; then
    warn "无 ping，跳过 MTU"
    return
  fi

  local sizes=(1472 1452 1400 1200)
  local s ok_size="" fail_big=0
  info "对 1.1.1.1 做 Don't Fragment 探测（1500 以太网对应 payload 1472）"
  for s in "${sizes[@]}"; do
    if ping -c 2 -W 2 -M do -s "$s" 1.1.1.1 >/dev/null 2>&1; then
      ok "payload $s 通过（约 MTU $((s + 28))）"
      ok_size="$s"
      break
    else
      info "payload $s 失败"
      fail_big=1
    fi
  done

  if [[ -z "$ok_size" ]]; then
    warn "几种 MTU 探测都失败（可能机房禁 ping）。不能据此判断 MTU"
    return
  fi
  if [[ "$ok_size" != "1472" && $fail_big -eq 1 ]]; then
    MTU_SUGGEST=1400
    warn "大包过不去，可用 MTU 大约 $((ok_size + 28))。部分 HTTPS 网站会 TLS 卡住或加载到一半失败。可把网卡 MTU 降到 1450 或 1400 再试"
  else
    ok "标准 1500 MTU 大包正常"
  fi
}

# ---------- IPv6 ----------
check_ipv6() {
  section "7" "IPv6（半残 IPv6 是「只有部分网站慢」的第一嫌疑）"
  if [[ $HAS_LOCAL_V6 -eq 0 && -z "$PUBLIC_V6" ]]; then
    info "未启用 IPv6，跳过。纯 IPv4 节点通常更省心"
    ok "无 IPv6，不存在 Happy Eyeballs 卡死问题"
    return
  fi

  local ping6_ok=0
  if have ping; then
    if ping -6 -c 3 -W 2 2606:4700:4700::1111 >/dev/null 2>&1; then
      ping6_ok=1
      ok "IPv6 ping 1.1.1.1 成功"
    else
      IPV6_BROKEN=1
      fail "本机有 IPv6，但 ping6 1.1.1.1 失败"
    fi
  fi

  local v4c v6c
  v4c=$(curl -4 -sS -o /dev/null -L --max-time 10 --connect-timeout 6 \
    -w '%{http_code} %{time_total}' https://www.cloudflare.com 2>/dev/null || echo "000 0")
  v6c=$(curl -6 -sS -o /dev/null -L --max-time 10 --connect-timeout 6 \
    -w '%{http_code} %{time_total}' https://www.cloudflare.com 2>/dev/null || echo "000 0")

  info "curl -4 cloudflare: $v4c"
  info "curl -6 cloudflare: $v6c"

  local v6code
  v6code=$(echo "$v6c" | awk '{print $1}')
  if [[ "$v6code" != "200" && "$v6code" != "301" && "$v6code" != "302" ]]; then
    IPV6_BROKEN=1
    fail "IPv6 HTTPS 失败。浏览器/curl 会先试 IPv6 再回退 IPv4，有 AAAA 记录的网站会先卡 几秒～十几秒"
    info "建议先出站优先 IPv4（不关 IPv6）：菜单选修复，或 bash $0 --fix-ipv4-pref"
  else
    ok "IPv6 HTTPS 正常"
    if [[ $ping6_ok -eq 0 ]]; then
      warn "IPv6 HTTPS 通但 ping6 失败（可能禁 ICMP），可忽略"
    fi
  fi
}

# ---------- 出站端口 ----------
tcp_open() {
  local host="$1" port="$2"
  timeout 4 bash -c "echo >/dev/tcp/$host/$port" >/dev/null 2>&1
}

check_ports() {
  section "8" "出站 TCP 端口"
  local pairs=("1.1.1.1:443" "1.1.1.1:80" "8.8.8.8:53" "9.9.9.9:853" "github.com:443")
  local p host port
  for p in "${pairs[@]}"; do
    host="${p%%:*}"
    port="${p##*:}"
    if tcp_open "$host" "$port"; then
      ok "TCP $p 通"
    else
      warn "TCP $p 不通（$port 被运营商/机房拦，或对端不听这个口）"
    fi
  done
}

# ---------- HTTPS 批量探测 ----------
DEFAULT_URLS=(
  https://www.cloudflare.com
  https://1.1.1.1
  https://www.google.com
  https://www.youtube.com
  https://github.com
  https://www.microsoft.com
  https://aws.amazon.com
  https://www.apple.com
  https://www.wikipedia.org
  https://www.reddit.com
  https://x.com
  https://www.facebook.com
  https://discord.com
  https://openai.com
  https://chatgpt.com
  https://www.netflix.com
  https://www.amazon.com
  https://www.bbc.com
  https://www.baidu.com
  https://www.qq.com
  https://www.bilibili.com
)

probe_one() {
  local url="$1" outfile="$2"
  local extra=() host ip
  if [[ ${#DNS_SERVERS[@]} -gt 0 ]] && have dig; then
    host=$(printf '%s' "$url" | sed -E 's#^[a-zA-Z]+://##' | cut -d/ -f1 | cut -d: -f1)
    if [[ -n "$host" && ! "$host" =~ ^[0-9.]+$ ]]; then
      ip=$(dig +time=3 +tries=1 +short A "$host" "@${DNS_SERVERS[0]}" 2>/dev/null | awk '/^[0-9.]+$/{print; exit}')
      if [[ -n "$ip" ]]; then
        extra+=(--resolve "${host}:443:${ip}" --resolve "${host}:80:${ip}")
      fi
    fi
  fi
  local line
  line=$(curl -sS -o /dev/null -L --max-time 12 --connect-timeout 8 \
    "${extra[@]+"${extra[@]}"}" \
    -w '%{http_code} %{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{remote_ip} %{size_download}' \
    "$url" 2>/dev/null) || line="000 0 0 0 0 0 - 0"
  printf '%s %s\n' "$url" "$line" > "$outfile"
}

check_https() {
  section "9" "分站点 HTTPS 探测（最能对上「部分网站不顺」）"
  info "指标: DNS / TCP / TLS / TTFB / 总计。单位毫秒。并行 5 路。"

  local urls=("${DEFAULT_URLS[@]}")
  local u
  for u in "${CUSTOM_URLS[@]+"${CUSTOM_URLS[@]}"}"; do
    urls+=("$u")
  done
  if [[ -n "$CUSTOM_FILE" ]]; then
    if [[ ! -f "$CUSTOM_FILE" ]]; then
      fail "找不到文件: $CUSTOM_FILE"
    else
      while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(echo "$line" | tr -d ' \t\r')"
        [[ -n "$line" ]] && urls+=("$line")
      done < "$CUSTOM_FILE"
    fi
  fi

  local tmpdir
  tmpdir=$(mktemp -d)
  local i=0 running=0
  for u in "${urls[@]}"; do
    i=$((i + 1))
    probe_one "$u" "$tmpdir/$i" &
    running=$((running + 1))
    if [[ $running -ge 5 ]]; then
      wait
      running=0
    fi
  done
  wait

  printf "  %-36s %5s %6s %6s %6s %6s %6s %-16s %s\n" \
    "URL" "HTTP" "DNS" "TCP" "TLS" "TTFB" "总计" "对端IP" "判断"
  [[ -n "$LOG" ]] && printf "  %-36s %5s %6s %6s %6s %6s %6s %-16s %s\n" \
    "URL" "HTTP" "DNS" "TCP" "TLS" "TTFB" "总计" "对端IP" "判断" >> "$LOG"

  local fail_sites=() slow_sites=() blocked_sites=() dns_slow_sites=() tls_slow_sites=()
  local n=0 code namelookup connect appconnect starttransfer total rip
  for ((n=1; n<=i; n++)); do
    [[ -f "$tmpdir/$n" ]] || continue
    local url http dns_ms tcp_ms tls_ms ttfb_ms tot_ms verdict
    read -r url http namelookup connect appconnect starttransfer total rip _sz < "$tmpdir/$n"
    dns_ms=$(fmt_ms "$namelookup")
    tcp_ms=$(awk -v a="$connect" -v b="$namelookup" 'BEGIN{v=(a-b)*1000; if(v<0)v=0; printf "%.0f", v}')
    tls_ms=$(awk -v a="$appconnect" -v b="$connect" 'BEGIN{v=(a-b)*1000; if(v<0)v=0; printf "%.0f", v}')
    ttfb_ms=$(fmt_ms "$starttransfer")
    tot_ms=$(fmt_ms "$total")
    [[ -z "$rip" || "$rip" == "0.0.0.0" ]] && rip="-"

    verdict="OK"
    if [[ "$http" == "000" ]]; then
      verdict="FAIL 连不上"
      fail_sites+=("$url")
    elif [[ "$http" == "403" || "$http" == "429" || "$http" == "451" || "$http" == "503" ]]; then
      verdict="WARN HTTP $http"
      blocked_sites+=("$url($http)")
    elif awk_gt "$total" 8; then
      verdict="FAIL 太慢"
      fail_sites+=("$url")
    elif awk_gt "$total" 3; then
      verdict="WARN 偏慢"
      slow_sites+=("$url ${tot_ms}ms")
    elif awk_gt "$namelookup" 0.8; then
      verdict="WARN DNS慢"
      dns_slow_sites+=("$url")
    elif awk_gt "$(awk -v a="$appconnect" -v b="$connect" 'BEGIN{print a-b}')" 1.2; then
      verdict="WARN TLS慢"
      tls_slow_sites+=("$url")
    fi

    local short="$url"
    [[ ${#short} -gt 36 ]] && short="${short:0:33}..."
    printf "  %-36s %5s %6s %6s %6s %6s %6s %-16s %s\n" \
      "$short" "$http" "$dns_ms" "$tcp_ms" "$tls_ms" "$ttfb_ms" "$tot_ms" "$rip" "$verdict"
    [[ -n "$LOG" ]] && printf "  %-36s %5s %6s %6s %6s %6s %6s %-16s %s\n" \
      "$short" "$http" "$dns_ms" "$tcp_ms" "$tls_ms" "$ttfb_ms" "$tot_ms" "$rip" "$verdict" >> "$LOG"
  done
  rm -rf "$tmpdir"

  local total_n=$i
  if [[ ${#fail_sites[@]} -eq 0 ]]; then
    ok "探测的 $total_n 个网站都能连上"
  elif [[ ${#fail_sites[@]} -ge $((total_n / 2)) ]]; then
    fail "超过一半网站连不上或极慢，更像整机出网/路由问题，不是「个别站」"
  else
    warn "这些网站失败或极慢: ${fail_sites[*]}"
  fi

  if [[ ${#blocked_sites[@]} -gt 0 ]]; then
    warn "这些网站返回 403/429/503，常见于机房 IP 被目标站拉黑或风控: ${blocked_sites[*]}"
  fi
  if [[ ${#slow_sites[@]} -gt 0 ]]; then
    warn "这些网站偏慢(>3s): ${slow_sites[*]}"
  fi
  if [[ ${#dns_slow_sites[@]} -gt 0 ]]; then
    warn "这些网站卡在 DNS: ${dns_slow_sites[*]}"
  fi
  if [[ ${#tls_slow_sites[@]} -gt 0 ]]; then
    warn "这些网站 TLS 握手慢: ${tls_slow_sites[*]}"
  fi
}

# ---------- 测速 ----------
speed_one() {
  local name="$1" url="$2"
  local out
  out=$(curl -4 -sS -L --max-time 25 --connect-timeout 8 -o /dev/null \
    -w '%{http_code} %{size_download} %{time_total} %{speed_download}' \
    "$url" 2>/dev/null) || out="000 0 0 0"
  local code size total spd mbps
  code=$(echo "$out" | awk '{print $1}')
  size=$(echo "$out" | awk '{print $2}')
  total=$(echo "$out" | awk '{print $3}')
  spd=$(echo "$out" | awk '{print $4}')
  mbps=$(awk -v s="$spd" 'BEGIN{printf "%.2f", (s+0)*8/1000/1000}')
  info "$name  HTTP $code  下载 ${size}B  耗时 ${total}s  ≈ ${mbps} Mbps"
  if [[ "$code" == "000" || "$size" == "0" ]]; then
    warn "$name 测速失败"
  elif awk_gt 1000 "$size"; then
    info "$name 只返回了 ${size}B，测速源无效，忽略"
  elif awk_gt 5 "$mbps"; then
    warn "$name 下载约 ${mbps} Mbps，偏慢（网页能开但视频/大站会卡）"
  else
    ok "$name 下载约 ${mbps} Mbps"
  fi
}

check_speed() {
  section "10" "下载测速（粗看带宽，不是专业测速）"
  speed_one "Cloudflare 10MB" "https://speed.cloudflare.com/__down?bytes=10000000"
  speed_one "Cachefly 10MB" "http://cachefly.cachefly.net/10mb.test"
}

# ---------- Telegram（可选）----------
# 官方 DC 入口 IP 会变：https://core.telegram.org/api/datacenter
# 这里用社区长期沿用的生产入口，用来排除「TG 机房连不上 / 被单独限速」
TG_CF_MBPS=""
TG_DL_MBPS=""
TG_LAST_MBPS=""
TG_DC_FAIL=0
TG_DC_SLOW=0

curl_resolve_args() {
  local url="$1"
  local host ip
  if [[ ${#DNS_SERVERS[@]} -eq 0 ]] || ! have dig; then
    return 0
  fi
  host=$(printf '%s' "$url" | sed -E 's#^[a-zA-Z]+://##' | cut -d/ -f1 | cut -d: -f1)
  if [[ -n "$host" && ! "$host" =~ ^[0-9.]+$ ]]; then
    ip=$(dig +time=3 +tries=1 +short A "$host" "@${DNS_SERVERS[0]}" 2>/dev/null | awk '/^[0-9.]+$/{print; exit}')
    if [[ -n "$ip" ]]; then
      printf -- '--resolve %s:443:%s --resolve %s:80:%s' "$host" "$ip" "$host" "$ip"
    fi
  fi
}

tg_speed_one() {
  local name="$1" url="$2"
  local extra=() resolve
  resolve=$(curl_resolve_args "$url")
  # shellcheck disable=SC2206
  [[ -n "$resolve" ]] && extra=($resolve)
  local out code size total spd mbps mbs
  out=$(curl -4 -sS -L --max-time 25 --connect-timeout 8 -o /dev/null \
    -w '%{http_code} %{size_download} %{time_total} %{speed_download}' \
    "${extra[@]}" "$url" 2>/dev/null) || out="000 0 0 0"
  code=$(echo "$out" | awk '{print $1}')
  size=$(echo "$out" | awk '{print $2}')
  total=$(echo "$out" | awk '{print $3}')
  spd=$(echo "$out" | awk '{print $4}')
  mbps=$(awk -v s="$spd" 'BEGIN{printf "%.2f", (s+0)*8/1000/1000}')
  mbs=$(awk -v s="$spd" 'BEGIN{printf "%.2f", (s+0)/1024/1024}')
  info "$name  HTTP $code  下了 ${size}B  耗时 ${total}s  ≈ ${mbps} Mbps（${mbs} MB/s）"
  if [[ "$code" == "000" || "$size" == "0" ]]; then
    warn "$name 下载失败"
    TG_LAST_MBPS="0"
  elif awk_gt 1000 "$size"; then
    info "$name 只返回了 ${size}B，测速源无效，忽略"
    TG_LAST_MBPS="0"
  else
    TG_LAST_MBPS="$mbps"
  fi
}

tg_tcp_ms() {
  local ip="$1"
  local start end ms
  start=$(date +%s%N 2>/dev/null || echo 0)
  if timeout 5 bash -c "exec 3<>/dev/tcp/${ip}/443 && exec 3>&-" 2>/dev/null; then
    end=$(date +%s%N 2>/dev/null || echo 0)
    if [[ "$start" == "0" || "$end" == "0" ]]; then
      echo "ok"
      return 0
    fi
    ms=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.0f", (e-s)/1000000}')
    echo "$ms"
    return 0
  fi
  echo "fail"
  return 1
}

tg_ping_line() {
  local ip="$1"
  local out
  if ! have ping; then
    echo "无 ping"
    return
  fi
  out=$(ping -c 4 -W 2 "$ip" 2>/dev/null) || true
  if echo "$out" | grep -q 'min/avg/max'; then
    echo "$out" | awk -F'=' '/min\/avg\/max/{gsub(/^ +/,"",$2); print "rtt"$2}'
  else
    echo "ICMP 不通（TG 机房常禁 ping，不算坏）"
  fi
}

check_telegram() {
  section "Telegram" "到 TG 机房延迟 + 官网/安装包下载（排除 TG 服务器问题）"
  info "测的是本机直连 Telegram，不是用户穿过节点的体感。"
  info "DC 入口 IP 会变；某个 IP 连不上，先看其它 DC 和官网下载再下结论。"

  local cf_mbps tg_mbps
  tg_speed_one "对照 Cloudflare 10MB" "https://speed.cloudflare.com/__down?bytes=10000000"
  cf_mbps="$TG_LAST_MBPS"
  tg_speed_one "Telegram 安装包" "https://telegram.org/dl/desktop/linux"
  tg_mbps="$TG_LAST_MBPS"
  TG_CF_MBPS="$cf_mbps"
  TG_DL_MBPS="$tg_mbps"

  local extra=() resolve
  resolve=$(curl_resolve_args "https://telegram.org/")
  # shellcheck disable=SC2206
  [[ -n "$resolve" ]] && extra=($resolve)
  local web
  web=$(curl -4 -sS -L --max-time 15 --connect-timeout 8 -o /dev/null \
    -w '%{http_code} %{time_namelookup} %{time_connect} %{time_appconnect} %{time_total}' \
    "${extra[@]}" "https://telegram.org/" 2>/dev/null) || web="000 0 0 0 0"
  info "telegram.org  HTTP $(echo "$web" | awk '{print $1}')  DNS $(echo "$web" | awk '{printf "%.0f", ($2+0)*1000}')ms  TCP $(echo "$web" | awk '{printf "%.0f", ($3+0)*1000}')ms  TLS $(echo "$web" | awk '{printf "%.0f", ($4+0)*1000}')ms  总 $(echo "$web" | awk '{printf "%.2f", $5+0}')s"
  if [[ "$(echo "$web" | awk '{print $1}')" == "000" ]]; then
    warn "telegram.org HTTPS 打不开"
  else
    ok "telegram.org HTTPS 能开"
  fi

  info "五个官方机房 TCP 443（日本节点重点看 DC5 新加坡）"
  local name ip ms
  TG_DC_FAIL=0
  TG_DC_SLOW=0
  while IFS='|' read -r name ip; do
    ms=$(tg_tcp_ms "$ip")
    if [[ "$ms" == "fail" ]]; then
      TG_DC_FAIL=$((TG_DC_FAIL + 1))
      fail "$name  $ip  TCP 443 连不上"
    elif [[ "$ms" == "ok" ]]; then
      ok "$name  $ip  TCP 443 通"
    elif awk_gt "$ms" 1500; then
      TG_DC_SLOW=$((TG_DC_SLOW + 1))
      warn "$name  $ip  TCP ${ms} ms（偏慢）"
    else
      ok "$name  $ip  TCP ${ms} ms"
    fi
    info "         $(tg_ping_line "$ip")"
  done <<'EOF'
DC1 迈阿密|149.154.175.50
DC2 阿姆斯特丹|149.154.167.51
DC3 迈阿密|149.154.175.100
DC4 阿姆斯特丹|149.154.167.91
DC5 新加坡|91.108.56.130
EOF

  hr
  logc "${BLD}Telegram 怎么看${RST}"
  if awk_gt "$cf_mbps" 0 && awk_gt 8 "$cf_mbps" && awk_gt "$tg_mbps" 0 && awk_gt 8 "$tg_mbps"; then
    warn "Cloudflare 和 Telegram 安装包都慢（约 ${cf_mbps} / ${tg_mbps} Mbps）→ 这条线整体慢，不是 TG 机房独有"
  elif awk_gt "$cf_mbps" 20 && awk_gt "$tg_mbps" 0 && awk_gt 8 "$tg_mbps"; then
    warn "Cloudflare 约 ${cf_mbps} Mbps，Telegram 只有 ${tg_mbps} Mbps → 到 TG 网段被限或绕路"
  elif awk_gt "$tg_mbps" 8; then
    ok "到 Telegram 的下载看起来正常（约 ${tg_mbps} Mbps）"
  fi
  if [[ $TG_DC_FAIL -ge 4 ]]; then
    fail "五个 DC 大多连不上，像是出站被拦或到 TG 网段全挂"
  elif [[ $TG_DC_FAIL -ge 1 && $TG_DC_FAIL -le 2 ]]; then
    warn "个别 DC 连不上（入口 IP 会变）。其它 DC 和官网下载正常就可以排除「TG 全球挂了」"
  fi
  info "• 五个 DC 都能连、下载却只有 1–2 MB/s → 连得上，带宽被挤瘦了"
  info "• 某个 DC 要好几秒/失败、其它很快 → 那一个机房或那条国际路由有问题"
  info "这测的是官网和机房入口，和 App 里某条视频的 CDN 会略有差别，但足以排除 TG 宕机。"
}

# ---------- traceroute ----------
check_route() {
  section "11" "路由追踪（看是否绕路/中途丢包）"
  if ! have traceroute; then
    warn "没有 traceroute，跳过。可: apt-get install -y traceroute"
    return
  fi
  local t
  for t in 1.1.1.1 8.8.8.8; do
    info "traceroute -n -q 1 -w 2 -m 14 $t"
    traceroute -n -q 1 -w 2 -m 14 "$t" 2>/dev/null | sed 's/^/  /' | while IFS= read -r line; do
      log "$line"
    done
  done
  info "若出现大段 * * * 或跳数突然出国再绕回，说明路由质量差"
}

# ---------- 本机连接表 ----------
check_conntrack() {
  section "12" "本机连接数（节点用户多时会把网卡/连接表打满）"
  if have ss; then
    ss -s 2>/dev/null | head -n 8 | while IFS= read -r line; do info "$line"; done
    local est
    est=$(ss -tan state established 2>/dev/null | tail -n +2 | wc -l)
    info "ESTABLISHED ≈ $est"
    if awk_gt "$est" 8000; then
      warn "已建立连接很多（$est）。用户多或被扫端口时，新连接会变慢"
    else
      ok "当前连接数不夸张"
    fi
  else
    info "无 ss，跳过"
  fi
}

# ---------- 流媒体解锁 ----------
UNLOCK_URL_PRIMARY="https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/check.sh"
UNLOCK_URL_FALLBACK="https://check.unlock.media"

guess_unlock_region() {
  case "${CF_LOC:-}" in
    TW) echo 1 ;;
    HK) echo 2 ;;
    JP) echo 3 ;;
    US|CA|MX) echo 4 ;;
    BR|AR|CL|CO) echo 5 ;;
    GB|DE|FR|NL|IT|ES|SE|PL) echo 6 ;;
    AU|NZ) echo 7 ;;
    KR) echo 8 ;;
    SG|TH|VN|MY|PH|ID) echo 9 ;;
    IN) echo 10 ;;
    ZA|NG|EG|KE) echo 11 ;;
    *) echo 0 ;;
  esac
}

run_unlock() {
  section "流媒体" "RegionRestrictionCheck（第三方，按需下载，不改系统）"
  if ! have curl; then
    fail "没有 curl，无法下载流媒体脚本"
    return 1
  fi
  [[ $NO_INSTALL -eq 0 ]] && need_root_install uuid-runtime >/dev/null 2>&1 || true

  local region="$UNLOCK_REGION"
  if [[ "$region" == "auto" ]]; then
    region=$(guess_unlock_region)
    info "自动选择区域 $region（IP 归属=${CF_LOC:-未知}）。可改: --unlock-region N"
  fi
  info "来源: https://github.com/lmc999/RegionRestrictionCheck"
  info "参数: -M $UNLOCK_IP  -R $region"

  local tmp shfile
  tmp=$(mktemp -d)
  shfile="$tmp/check.sh"
  if ! curl -fsSL --max-time 30 --connect-timeout 10 -o "$shfile" "$UNLOCK_URL_PRIMARY"; then
    warn "GitHub raw 下载失败，改试 check.unlock.media"
    if ! curl -fsSL --max-time 30 --connect-timeout 10 -o "$shfile" "$UNLOCK_URL_FALLBACK"; then
      fail "流媒体脚本下载失败"
      rm -rf "$tmp"
      return 1
    fi
  fi

  local resolv="$tmp/resolv.conf"
  if [[ ${#DNS_SERVERS[@]} -gt 0 ]]; then
    {
      echo "# vps-netcheck unlock-only DNS"
      local s
      for s in "${DNS_SERVERS[@]}"; do
        echo "nameserver $s"
      done
    } > "$resolv"
  fi

  local use_unshare=0
  if [[ ${#DNS_SERVERS[@]} -gt 0 ]] && have unshare && [[ "$(id -u)" -eq 0 ]]; then
    use_unshare=1
    info "流媒体检测使用指定 DNS（unshare 隔离，不影响系统 resolv.conf）: ${DNS_SERVERS[*]}"
  elif [[ ${#DNS_SERVERS[@]} -gt 0 ]]; then
    warn "无法隔离 DNS（需要 root + unshare），流媒体仍走系统 DNS"
  fi

  (
    cd "$tmp" || exit 1
    if [[ $use_unshare -eq 1 ]]; then
      unshare --mount bash -c "mount --bind '$resolv' /etc/resolv.conf && bash '$shfile' -M '$UNLOCK_IP' -R '$region'"
    else
      bash "$shfile" -M "$UNLOCK_IP" -R "$region"
    fi
  ) 2>&1 | while IFS= read -r line; do
    log "$line"
  done

  rm -rf "$tmp"
  ok "流媒体检测结束（结果已写入日志）"
}

# ---------- 可选修复 ----------
SYSCTL_IPV6_FILE="/etc/sysctl.d/99-vps-netcheck-disable-ipv6.conf"
MTU_UNIT_FILE="/etc/systemd/system/vps-netcheck-mtu.service"
MSS_UNIT_FILE="/etc/systemd/system/vps-netcheck-mss.service"
MSS_SCRIPT_FILE="/usr/local/sbin/vps-netcheck-apply-mss.sh"
GAI_FILE="/etc/gai.conf"
GAI_BAK_FILE="/etc/gai.conf.vps-netcheck.bak"
RESOLV_BAK_FILE="/etc/resolv.conf.vps-netcheck.bak"
GAI_BEGIN="# BEGIN vps-netcheck ipv4-pref"
GAI_END="# END vps-netcheck ipv4-pref"

apply_disable_ipv6() {
  section "修复" "持久关闭 IPv6"
  require_root "关闭 IPv6" || return 1
  info "会写 $SYSCTL_IPV6_FILE ，立刻生效且重启后仍关闭。"
  info "若有用户用 IPv6 地址连这台节点，他们会连不上。"
  confirm "确认持久关闭 IPv6？" || return 1

  cat > "$SYSCTL_IPV6_FILE" <<'EOF'
# written by vps-netcheck.sh ; remove this file and --undo-ipv6 to restore
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
  sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
  sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null
  local iface
  for iface in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    echo 1 > "$iface" 2>/dev/null || true
  done
  ok "IPv6 已关闭。撤销: bash $0 --undo-ipv6"
}

apply_undo_ipv6() {
  section "修复" "撤销关闭 IPv6"
  require_root "恢复 IPv6" || return 1
  confirm "确认恢复 IPv6？" || return 1
  rm -f "$SYSCTL_IPV6_FILE"
  sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null
  sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null
  local iface
  for iface in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    echo 0 > "$iface" 2>/dev/null || true
  done
  ok "已去掉关闭 IPv6 的配置。若地址没回来，重启一次网卡或机器"
}

apply_fix_mtu() {
  local val="${FIX_MTU_VAL:-${MTU_SUGGEST:-1400}}"
  local iface="${DEFAULT_IFACE:-$(detect_wan_iface)}"
  section "修复" "设置 MTU=$val"
  require_root "改 MTU" || return 1
  if [[ -z "$iface" ]]; then
    fail "找不到默认网卡"
    return 1
  fi
  info "网卡 $iface 当前: $(cat /sys/class/net/$iface/mtu 2>/dev/null || echo unknown)"
  confirm "把 $iface 的 MTU 改为 $val 并开机保持？" || return 1

  ip link set "$iface" mtu "$val" || { fail "ip link set 失败"; return 1; }

  cat > "$MTU_UNIT_FILE" <<EOF
[Unit]
Description=vps-netcheck persist MTU
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/sbin/ip link set $iface mtu $val
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  if have systemctl; then
    systemctl daemon-reload
    systemctl enable --now vps-netcheck-mtu.service >/dev/null 2>&1 || systemctl enable vps-netcheck-mtu.service >/dev/null 2>&1 || true
  fi
  ok "$iface MTU 已设为 $val。撤销: systemctl disable --now vps-netcheck-mtu.service && ip link set $iface mtu 1500"
}

apply_fix_dns() {
  section "修复" "修改系统 DNS"
  require_root "改 DNS" || return 1
  info "将把 /etc/resolv.conf 改成: ${DNS_SERVERS[*]}"
  info "这会影响整机（含节点程序）的域名解析，不只是体检。"
  confirm "确认修改系统 DNS？" || return 1

  if [[ -L /etc/resolv.conf ]]; then
    warn "/etc/resolv.conf 是符号链接（多半 systemd-resolved）。改它可能被覆盖。"
    if have resolvectl && [[ -n "${DEFAULT_IFACE:-}" ]]; then
      resolvectl dns "$DEFAULT_IFACE" "${DNS_SERVERS[@]}" || true
      ok "已用 resolvectl 给 $DEFAULT_IFACE 设置 DNS"
      return 0
    fi
  fi
  if [[ -f /etc/resolv.conf && ! -f "$RESOLV_BAK_FILE" ]]; then
    cp -a /etc/resolv.conf "$RESOLV_BAK_FILE"
    info "原文件已备份: $RESOLV_BAK_FILE"
  fi
  {
    echo "# written by vps-netcheck.sh"
    local s
    for s in "${DNS_SERVERS[@]}"; do
      echo "nameserver $s"
    done
  } > /etc/resolv.conf
  ok "系统 DNS 已更新。恢复: cp $RESOLV_BAK_FILE /etc/resolv.conf"
}

apply_prefer_ipv4() {
  section "修复" "出站优先 IPv4（不关 IPv6）"
  require_root "改 gai.conf" || return 1
  info "会在 $GAI_FILE 加上 precedence，程序解析域名时先走 IPv4。"
  info "用户仍可用 IPv6 连进来。比整机关 IPv6 更稳。"
  confirm "确认让出站优先 IPv4？" || return 1

  if [[ -f "$GAI_FILE" && ! -f "$GAI_BAK_FILE" ]]; then
    cp -a "$GAI_FILE" "$GAI_BAK_FILE"
    info "原文件已备份: $GAI_BAK_FILE"
  fi
  touch "$GAI_FILE"
  if grep -qF "$GAI_BEGIN" "$GAI_FILE"; then
    ok "已经加过出站优先 IPv4，无需再改"
    return 0
  fi
  cat >> "$GAI_FILE" <<EOF

$GAI_BEGIN
precedence ::ffff:0:0/96  100
$GAI_END
EOF
  ok "已设置出站优先 IPv4。撤销: bash $0 --undo-ipv4-pref"
}

apply_undo_ipv4_pref() {
  section "修复" "撤销出站优先 IPv4"
  require_root "改 gai.conf" || return 1
  confirm "确认去掉出站优先 IPv4？" || return 1
  if [[ ! -f "$GAI_FILE" ]] || ! grep -qF "$GAI_BEGIN" "$GAI_FILE"; then
    info "没有本脚本写过的 gai.conf 标记，无需撤销"
    return 0
  fi
  local tmp
  tmp=$(mktemp)
  awk -v b="$GAI_BEGIN" -v e="$GAI_END" '
    $0 == b { skip=1; next }
    $0 == e { skip=0; next }
    !skip { print }
  ' "$GAI_FILE" > "$tmp"
  cat "$tmp" > "$GAI_FILE"
  rm -f "$tmp"
  ok "已去掉出站优先 IPv4"
}

write_mss_script() {
  cat > "$MSS_SCRIPT_FILE" <<'EOF'
#!/bin/sh
# written by vps-netcheck.sh
add_rule() {
  cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || return 0
  for chain in OUTPUT FORWARD POSTROUTING; do
    $cmd -t mangle -C "$chain" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 && continue
    $cmd -t mangle -A "$chain" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || true
  done
}
add_rule iptables
add_rule ip6tables
EOF
  chmod 755 "$MSS_SCRIPT_FILE"
}

apply_mss() {
  section "修复" "TCP MSS 钳位"
  require_root "加 MSS 钳位" || return 1
  info "让 TCP 握手按路径 MTU 自动缩小，避免改了网卡 MTU 后仍有网站加载到一半。"
  confirm "确认加上 MSS 钳位并开机保持？" || return 1

  if ! have iptables; then
    need_root_install iptables || { fail "没有 iptables，无法加 MSS 钳位"; return 1; }
  fi
  write_mss_script
  "$MSS_SCRIPT_FILE" || true

  cat > "$MSS_UNIT_FILE" <<EOF
[Unit]
Description=vps-netcheck persist TCP MSS clamp
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$MSS_SCRIPT_FILE
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  if have systemctl; then
    systemctl daemon-reload
    systemctl enable --now vps-netcheck-mss.service >/dev/null 2>&1 || systemctl enable vps-netcheck-mss.service >/dev/null 2>&1 || true
  fi
  ok "MSS 钳位已加上。撤销: bash $0 --undo-mss"
}

apply_undo_mss() {
  section "修复" "撤销 MSS 钳位"
  require_root "撤 MSS 钳位" || return 1
  confirm "确认去掉 MSS 钳位？" || return 1
  local cmd chain
  for cmd in iptables ip6tables; do
    have "$cmd" || continue
    for chain in OUTPUT FORWARD POSTROUTING; do
      $cmd -t mangle -D "$chain" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || true
    done
  done
  if have systemctl; then
    systemctl disable --now vps-netcheck-mss.service >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "$MSS_UNIT_FILE" "$MSS_SCRIPT_FILE"
  ok "MSS 钳位已去掉"
}

apply_ntp() {
  section "修复" "同步系统时钟"
  require_root "开 NTP" || return 1
  confirm "确认打开 NTP 并立刻对时？" || return 1

  if have timedatectl; then
    timedatectl set-ntp true || true
  fi
  if have systemctl; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-timesyncd'; then
      systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true
    elif systemctl list-unit-files 2>/dev/null | grep -q '^chrony'; then
      systemctl enable --now chrony >/dev/null 2>&1 || true
    else
      need_root_install systemd-timesyncd || true
      systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true
    fi
  fi
  if have timedatectl && timedatectl | grep -q 'System clock synchronized: yes'; then
    ok "时钟已同步"
  else
    ok "已打开 NTP。若仍显示未同步，等半分钟再执行 timedatectl"
  fi
}

apply_flush_dns() {
  section "修复" "刷新本机 DNS 缓存"
  require_root "刷新 DNS 缓存" || return 1
  confirm "确认刷新本机 DNS 缓存？" || return 1
  local did=0
  if have resolvectl; then
    resolvectl flush-caches >/dev/null 2>&1 && did=1
  elif have systemd-resolve; then
    systemd-resolve --flush-caches >/dev/null 2>&1 && did=1
  fi
  if have nscd; then
    nscd -i hosts >/dev/null 2>&1 && did=1
  fi
  if [[ $did -eq 1 ]]; then
    ok "DNS 缓存已刷新"
  else
    info "本机没有 systemd-resolved / nscd 缓存，无需刷新（解析每次都问 nameserver）"
  fi
}

maybe_prompt_fixes() {
  [[ $FIX_PROMPT -eq 1 ]] || return 0
  section "修复" "按体检结果询问（直接回车=不改）"
  local old_yes=$ASSUME_YES
  if [[ $IPV6_BROKEN -eq 1 && $FIX_GAI -eq 0 ]]; then
    if confirm "检测到 IPv6 半残，是否让出站优先 IPv4（不关 IPv6，推荐）？"; then
      ASSUME_YES=1
      apply_prefer_ipv4
      ASSUME_YES=$old_yes
    fi
  fi
  if [[ $IPV6_BROKEN -eq 1 && $FIX_IPV6 -eq 0 ]]; then
    if confirm "或者直接持久关闭 IPv6？（用户若用 IPv6 连节点会断）"; then
      ASSUME_YES=1
      apply_disable_ipv6
      ASSUME_YES=$old_yes
    fi
  fi
  if [[ -n "$MTU_SUGGEST" && $FIX_MTU -eq 0 ]]; then
    if confirm "检测到大包不过，是否把默认网卡 MTU 改为 ${MTU_SUGGEST}？"; then
      FIX_MTU_VAL="${FIX_MTU_VAL:-$MTU_SUGGEST}"
      ASSUME_YES=1
      apply_fix_mtu
      ASSUME_YES=$old_yes
    fi
  fi
  if [[ -n "$MTU_SUGGEST" && $FIX_MSS -eq 0 ]]; then
    if confirm "是否同时加上 TCP MSS 钳位（改了 MTU 后更稳）？"; then
      ASSUME_YES=1
      apply_mss
      ASSUME_YES=$old_yes
    fi
  fi
  if [[ $CLOCK_UNSYNCED -eq 1 && $FIX_NTP -eq 0 ]]; then
    if confirm "时钟可能未同步，是否打开 NTP？"; then
      ASSUME_YES=1
      apply_ntp
      ASSUME_YES=$old_yes
    fi
  fi
  if [[ $FIX_FLUSH_DNS -eq 0 ]]; then
    if confirm "是否刷新本机 DNS 缓存？"; then
      ASSUME_YES=1
      apply_flush_dns
      ASSUME_YES=$old_yes
    fi
  fi
  if [[ ${#DNS_SERVERS[@]} -gt 0 && $FIX_DNS -eq 0 ]]; then
    info "本轮用了指定 DNS，但默认不会改系统 DNS。若要持久化请选菜单「修改系统 DNS」"
  fi
}

run_requested_fixes() {
  [[ $UNDO_IPV6 -eq 1 ]] && apply_undo_ipv6
  [[ $UNDO_GAI -eq 1 ]] && apply_undo_ipv4_pref
  [[ $UNDO_MSS -eq 1 ]] && apply_undo_mss
  [[ $FIX_IPV6 -eq 1 ]] && apply_disable_ipv6
  [[ $FIX_GAI -eq 1 ]] && apply_prefer_ipv4
  [[ $FIX_MTU -eq 1 ]] && apply_fix_mtu
  [[ $FIX_MSS -eq 1 ]] && apply_mss
  [[ $FIX_DNS -eq 1 ]] && apply_fix_dns
  [[ $FIX_NTP -eq 1 ]] && apply_ntp
  [[ $FIX_FLUSH_DNS -eq 1 ]] && apply_flush_dns
  maybe_prompt_fixes
}

# ---------- 总结 ----------
summarize() {
  section "总结" "解读（先看 FAIL，再看 WARN）"
  logc "  通过 ${GRN}${PASS_N}${RST}  |  警告 ${YEL}${WARN_N}${RST}  |  失败 ${RED}${FAIL_N}${RST}"
  if [[ ${#FINDINGS[@]} -eq 0 ]]; then
    ok "这轮没有抓到明显出网故障。若用户仍觉得卡，多半是：节点到用户的入口线路、节点负载、或目标站对机房 IP 风控。"
    info "下一步：把用户说卡的具体域名用 --url 再跑一遍；或在用户侧对比「直连 vs 走节点」。"
  else
    local f
    for f in "${FINDINGS[@]}"; do
      if [[ "$f" == FAIL:* ]]; then
        logc "  ${RED}•${RST} ${f#FAIL: }"
      else
        logc "  ${YEL}•${RST} ${f#WARN: }"
      fi
    done
  fi

  hr
  logc "${BLD}怎么对照「只有部分网站不顺」${RST}"
  info "1) IPv6 半残     → 有 AAAA 的站（Google/Facebook/GitHub）慢，纯 IPv4 的站正常"
  info "2) MTU 偏大     → 小站正常，大站/登录/视频加载到一半失败"
  info "3) DNS 慢/劫持  → 所有站先转圈，或个别站解析到奇怪 IP"
  info "4) 机房 IP 风控 → 只有某几家返回 403/人机验证，其它站很快"
  info "5) 到某网段绕路 → 表里只有某几个站 TCP/TLS 特别慢"
  info "6) 入口线路问题 → 本机体检全绿，但用户走代理仍卡（本脚本测不到）"
  info "7) Telegram 慢  → 菜单选「只测 Telegram」，对照 Cloudflare 和五个 DC"
  hr
  logc "完整日志: ${LOG}"
  logc "下次直接 bash $0 进入菜单。命令行例子: bash $0 --telegram-only"
}

# ---------- main ----------
main() {
  LOG="/tmp/vps-netcheck-$(date +%Y%m%d-%H%M%S).log"
  : > "$LOG"

  logc "${BLD}VPS 出网体检 v${VERSION}${RST}  模式=${MODE}  $(ts)"
  info "测的是「这台 VPS 自己访问外网」，不是用户穿过节点的体感。"
  info "改系统的操作都会再确认一次。"

  if [[ $SKIP_CHECK -eq 1 ]]; then
    DEFAULT_IFACE=$(detect_wan_iface)
    run_requested_fixes
    [[ -n "$LOG" ]] && logc "完整日志: ${LOG}"
    return 0
  fi

  if [[ $UNLOCK_ONLY -eq 1 ]]; then
    ensure_deps
    check_identity
    run_unlock
    run_requested_fixes
    logc "完整日志: ${LOG}"
    return 0
  fi

  if [[ $TELEGRAM_ONLY -eq 1 ]]; then
    ensure_deps
    check_identity
    check_telegram
    run_requested_fixes
    logc "完整日志: ${LOG}"
    return 0
  fi

  ensure_deps
  check_system
  check_clock
  check_identity
  check_dns
  check_icmp
  check_mtu
  check_ipv6
  check_ports
  check_https
  if [[ "$MODE" != "quick" ]]; then
    check_speed
  fi
  if [[ "$MODE" == "full" ]]; then
    check_route
  fi
  check_conntrack
  [[ $TELEGRAM -eq 1 ]] && check_telegram
  summarize
  [[ $UNLOCK -eq 1 ]] && run_unlock
  run_requested_fixes
}

main
