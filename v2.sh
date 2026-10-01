#!/usr/bin/env bash
# One-command Debian/Ubuntu bootstrap. The reviewed payload is pinned below.
set -euo pipefail

V2_COMMIT='067a55a88c0e8daf6bb7213b1e90dcf918654b1b'
V2_SHA256='ac7e9fe500ca14bdef864d1ff6b8e009987f27f280ab026eb0fdcc2738bddcfb'
V2_TEMP=''

v2_cleanup() {
  if [[ -n "$V2_TEMP" && -d "$V2_TEMP" ]]; then
    # Only files created by this process, then its empty private directory.
    rm -f -- "$V2_TEMP/vps-netcheck-v2.sh"
    rmdir -- "$V2_TEMP" 2>/dev/null || true
  fi
}

v2_dependencies() {
  local -a packages=() elevate=()
  local entry tool package
  for entry in python3:python3 curl:curl ip:iproute2 ss:iproute2 ping:iputils-ping dig:dnsutils mtr:mtr-tiny sha256sum:coreutils; do
    tool=${entry%%:*}
    package=${entry#*:}
    if ! command -v "$tool" >/dev/null 2>&1; then
      case " ${packages[*]-} " in
        *" $package "*) ;;
        *) packages+=("$package") ;;
      esac
    fi
  done
  if command -v dpkg-query >/dev/null 2>&1; then
    if [[ "$(dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null || true)" != 'install ok installed' ]]; then
      packages+=(ca-certificates)
    fi
  fi
  if [[ ${#packages[@]} -gt 0 ]]; then
    if ! command -v apt-get >/dev/null 2>&1; then
      printf '自动安装仅支持 Debian/Ubuntu；缺少：%s\n' "${packages[*]}" >&2
      return 2
    fi
    if [[ $EUID -ne 0 ]]; then
      if ! command -v sudo >/dev/null 2>&1; then
        printf '缺少依赖且没有 sudo，请用 root 运行这一行命令。\n' >&2
        return 2
      fi
      elevate=(sudo)
    fi
    printf '安装缺少的依赖：%s\n' "${packages[*]}"
    "${elevate[@]}" apt-get update || return 2
    "${elevate[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" || return 2
  fi
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else "需要 Python 3.8+；请升级系统 Python 后重试。")' || return 2
}

v2_main() {
  v2_dependencies || return $?
  umask 077
  V2_TEMP=$(mktemp -d -t vps-netcheck-bootstrap.XXXXXXXX) || return 2
  trap v2_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  local script="$V2_TEMP/vps-netcheck-v2.sh"
  local url="https://raw.githubusercontent.com/M3DaLou/inonescripts/$V2_COMMIT/vps-netcheck-v2.sh"
  printf '下载并校验 VPS Netcheck v2…\n'
  curl -q -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 90 --retry 2 "$url" -o "$script" || return 2
  if ! printf '%s  %s\n' "$V2_SHA256" "$script" | sha256sum -c -; then
    printf '脚本校验失败，未执行。\n' >&2
    return 2
  fi
  bash -n "$script" || return 2
  if [[ $# -eq 0 && -t 0 && -t 1 ]]; then
    set -- --interactive
  fi
  # Keep this shell alive for cleanup and propagate the diagnostic exit code.
  bash "$script" "$@"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  v2_main "$@"
fi
