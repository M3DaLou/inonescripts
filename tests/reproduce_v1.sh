#!/usr/bin/env bash
# Offline regression evidence. Never invokes the original main or real repairs.
set -uo pipefail
export PATH="/usr/bin:/bin:$PATH"
cd "$(dirname "$0")" || exit 1
mkdir -p test-work
source_file="$PWD/../vps-netcheck.sh"
cd test-work || exit 1
sed '$d' "$source_file" > definitions.sh
source ./definitions.sh --quick
LOG=""
total=0
passed=0
run_case() {
  total=$((total+1))
  if ( "$2" ); then
    printf 'REPRODUCED %02d %s\n' "$total" "$1"
    passed=$((passed+1))
  else
    printf 'NOT_REPRODUCED %02d %s\n' "$total" "$1"
  fi
}
t_ipv4() { is_ipv4_addr 999.999.999.999; }
t_ipv6() { is_ipv6_addr invalid:address; }
t_route() {
  ip() { printf 'default dev ppp0 scope link\n'; }
  [[ "$(detect_wan_iface)" == link ]]
}
t_mtr() {
  local parsed
  parsed=$(quality_parse_mtr ' 1.|-- 192.0.2.1 0.0% 20 1.0 1.0 1.0 1.0 0.0')
  [[ "$(awk '{print $6}' <<< "$parsed")" == 1 ]]
}
t_traceroute() {
  printf 'traceroute to 203.0.113.10 (203.0.113.10), 20 hops max\n 1 * * *\n' |
    grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|:[0-9a-fA-F]'
}
t_ipv6_flag() {
  HAS_LOCAL_V6=1; IPV6_BROKEN=0
  ping() { return 1; }
  curl() { printf '200 0.1'; }
  check_ipv6 > ipv6-result.txt
  [[ "$IPV6_BROKEN" == 1 ]] && grep -q 'IPv6 HTTPS 正常' ipv6-result.txt
}
t_ipv6_403() {
  HAS_LOCAL_V6=1; IPV6_BROKEN=0
  ping() { return 0; }
  curl() { printf '403 0.1'; }
  check_ipv6 > /dev/null
  [[ "$IPV6_BROKEN" == 1 ]]
}
t_https_error() {
  DNS_SERVERS=()
  curl() { printf '000 0.02 0.1 0 0 0.15 203.0.113.1 0'; return 60; }
  probe_one https://example.invalid probe-result.txt
  [[ "$(cat probe-result.txt)" == 'https://example.invalid 000 0 0 0 0 0 - 0' ]]
}
t_speed_500() {
  PASS_N=0
  curl() { printf '500 100000 0.1 1000000'; }
  speed_one mock https://example.invalid > /dev/null
  [[ "$PASS_N" == 1 ]]
}
t_fix_both() {
  FIX_PROMPT=1; ASSUME_YES=1; IPV6_BROKEN=1; FIX_GAI=0; FIX_IPV6=0
  FIX_FLUSH_DNS=1; CLOCK_UNSYNCED=0; MTU_SUGGEST=''
  calls=''
  apply_prefer_ipv4() { calls+=' prefer'; }
  apply_disable_ipv6() { calls+=' disable'; }
  maybe_prompt_fixes > /dev/null
  [[ "$calls" == ' prefer disable' ]]
}
t_mtu() {
  MTU_SUGGEST=''
  ping() { [[ " $* " == *' -s 1200 '* ]]; }
  check_mtu > /dev/null
  [[ "$MTU_SUGGEST" == 1400 ]]
}
t_tcp_samples() {
  quality_tcp_ms() {
    local count=0
    [[ -f tcp-counter.txt ]] && read -r count < tcp-counter.txt
    count=$((count+1)); printf '%s\n' "$count" > tcp-counter.txt
    if [[ "$count" == 1 ]]; then printf '10'; else printf 'fail'; fi
  }
  printf '0\n' > tcp-counter.txt
  [[ "$(quality_tcp_stats 203.0.113.1)" == '443 1 10 10 10' ]]
}
t_exit() {
  LOG='main-test.log'
  ensure_deps() { fail 'mock missing curl'; return 1; }
  check_system() { :; }; check_clock() { :; }; check_identity() { :; }
  check_dns() { :; }; check_icmp() { :; }; check_mtu() { :; }
  check_ipv6() { :; }; check_ports() { :; }; check_https() { :; }
  check_conntrack() { :; }; summarize() { :; }
  # Mock timestamp to keep the original main's log inside this test directory.
  date() { printf 'offline'; }
  # Run a function copy with only its fixed log path redirected into the workspace.
  eval "$(declare -f main | sed 's@/tmp/vps-netcheck-@./vps-netcheck-@g')"
  main > /dev/null
  local rc=$?
  [[ "$rc" == 0 && "$FAIL_N" -gt 0 ]]
}
t_region_validation() {
  ( source ./definitions.sh --unlock-only --unlock-region invalid-region; [[ "$UNLOCK_REGION" == invalid-region ]] )
}
t_dns_failure_fallback() {
  DNS_SERVERS=(192.0.2.53 198.51.100.53)
  dig() { return 1; }
  curl() { printf '%s\n' "$@" > curl-args.txt; printf '200 0 0 0 0 0 203.0.113.1 1'; }
  probe_one https://example.invalid dns-probe-result.txt
  ! grep -q -- --resolve curl-args.txt
}
run_case 'Invalid IPv4 accepted' t_ipv4
run_case 'Invalid IPv6 accepted' t_ipv6
run_case 'PPP default interface parsed as link' t_route
run_case 'MTR router response counted as destination reached' t_mtr
run_case 'Traceroute header alone counts as reached' t_traceroute
run_case 'IPv6 failure flag survives HTTPS success' t_ipv6_flag
run_case 'IPv6 HTTP 403 treated as broken networking' t_ipv6_403
run_case 'curl certificate error and timings discarded' t_https_error
run_case 'HTTP 500 page accepted as valid speed sample' t_speed_500
run_case 'Automatic fix applies both IPv4 preference and IPv6 disable' t_fix_both
run_case 'MTU recommendation exceeds largest passing size' t_mtu
run_case 'One successful TCP sample hides four failed attempts' t_tcp_samples
run_case 'Missing curl and FAIL still produce exit status zero' t_exit
run_case 'CLI unlock region bypasses validation' t_region_validation
run_case 'Custom DNS failure silently falls back to system resolution' t_dns_failure_fallback
printf '\nReproduced: %s/%s\n' "$passed" "$total"
[[ "$passed" == "$total" ]]
