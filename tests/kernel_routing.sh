#!/usr/bin/env bash
# Маршрутизация туннелей на настоящем ядре: правила клиентов, «если туннель
# упал» (unreachable под маршрутом), метка и правило «РФ напрямую», «куда идёт
# адрес» — настоящими ip, ipset и iptables в отдельном сетевом пространстве.
# Запуск: unshare -rn bash tests/kernel_routing.sh dist/awg2.sh КАТАЛОГ tunnels|rudirect
# (или через tests/test_kernel_routing.py — он сам пропустит, если netns нет).
# shellcheck disable=SC2034  # пути — для функций awg2, подключённых через eval
set -u
LIB="$1"; T="$2"; PART="${3:-tunnels}"
src=$(cat "$LIB"); src="${src%main \"\$@\"*}"
eval "$src"
STATE_DIR="$T/state"; mkdir -p "$STATE_DIR"
SERVER_CONF="$T/awg0.conf"; printf '[Interface]
Address = 10.23.45.1/24
ListenPort = 51820
' > "$SERVER_CONF"
WARP_PEERS="$T/warp.peers"; echo "10.23.45.2" > "$WARP_PEERS"
WARP_STATE="$T/warp.state"; touch "$WARP_STATE"; XRAY_STATE="$T/xray.state"; EXITS_STATE="$T/exits.state"; XRAY_PEERS="$T/xray.peers"
TUNFAIL_CONF="$T/tunnel-fail.conf"; TUNFAIL_LOG="$T/tunfail.log"; WGOBF_STATE="$T/wgobf"; VKBLOCK_CONF="$T/vk.conf"
RUDIRECT_DIR="$T/rud"; RUDIRECT_CONF="$RUDIRECT_DIR/rudirect.conf"; RUDIRECT_USER="$T/user"; RUDIRECT_LOG="$T/rud.log"
DIAG_FWD=/proc/sys/net/ipv4/ip_forward
ipt_add() { :; }; ipt_ins() { :; }; ipt_del() { :; }; ipt_del_grep() { :; }; ipt_del_tagged() { :; }
systemctl() { return 1; }
server_exists() { return 0; }; clients_tsv() { printf 'alice	pub	10.23.45.2/32			
bob	pub	10.23.45.3/32			
'; }
xray_ru_on() { return 1; }
pass=0 fail=0
ok() { if eval "$2"; then echo "  OK   $1"; pass=$((pass+1)); else echo "  FAIL $1"; fail=$((fail+1)); fi; }
rg() { ip -4 route get "$1" from "$2" iif awg0 ${3:+mark $3} 2>&1; }

ip link set lo up
ip tuntap add mode tun dev awg0; ip addr add 10.23.45.1/24 dev awg0; ip link set awg0 up
ip link add eth0 type veth peer name eth0p; ip addr add 203.0.113.10/24 dev eth0; ip link set eth0 up; ip link set eth0p up
ip route add default via 203.0.113.1 dev eth0
echo 1 > /proc/sys/net/ipv4/ip_forward
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 > "$f" 2>/dev/null; done
mkwarp() { ip tuntap add mode tun dev warp0; ip addr add 172.16.0.2/32 dev warp0; ip link set warp0 up; }

if [[ "$PART" == tunnels ]]; then
echo "── напрямую (по умолчанию) ──"
mkwarp; rt_up warp0 200 "$WARP_PEERS"
ok "клиент WARP — в warp0" '[[ "$(rg 1.1.1.1 10.23.45.2)" == *"dev warp0"* ]]'
ok "клиент без туннеля — eth0" '[[ "$(rg 1.1.1.1 10.23.45.3)" == *"dev eth0"* ]]'
ok "rt_table_live видит живой маршрут" 'rt_table_live 200'
ok "_tunfail_rule_tables читает таблицу из ip rule show" '[[ "$(_tunfail_rule_tables)" == 200 ]]'
ok "ip rule show: «lookup 200» в конце строки (на этом держатся проверки)" 'ip rule show | grep -qE "lookup 200$"'
ip link del warp0
ok "WARP упал (устройство пропало): маршрут ушёл сам — клиент идёт напрямую (eth0)" '[[ "$(rg 1.1.1.1 10.23.45.2)" == *"dev eth0"* ]]'
rt_down warp0 200
ok "rt_down в «напрямую» снимает правила" '! ip rule show | grep -q "lookup 200"'

echo "── РФ напрямую: метка и правило 90 ──"
mkwarp; rt_up warp0 200 "$WARP_PEERS"
_rud_ip_rule_on || ip rule add fwmark "$RUDIRECT_MARK" lookup main priority "$RUDIRECT_PRIO"
ok "правило 90 найдено проверкой _rud_ip_rule_on" '_rud_ip_rule_on'
ok "помеченный пакет клиента WARP — мимо туннеля (eth0)" '[[ "$(rg 77.88.8.8 10.23.45.2 0x52550000)" == *"dev eth0"* ]]'
ok "метка с чужими младшими битами (wg-quick 0xca6c) — тоже мимо туннеля" '[[ "$(rg 77.88.8.8 10.23.45.2 0x5255ca6c)" == *"dev eth0"* ]]'
ok "без метки — в туннель" '[[ "$(rg 77.88.8.8 10.23.45.2)" == *"dev warp0"* ]]'
ok "чужая метка — в туннель" '[[ "$(rg 77.88.8.8 10.23.45.2 0x00010000)" == *"dev warp0"* ]]'

echo "── блокировать ──"
echo "warp=block" > "$TUNFAIL_CONF"
rt_fail_route 200
ok "«недоступно» лежит под живым маршрутом — трафик по-прежнему в warp0" '[[ "$(rg 1.1.1.1 10.23.45.2)" == *"dev warp0"* ]]'
ok "ip route show: «unreachable default metric 4096» (на этом держится tunfail_held)" 'ip route show table 200 | grep -q "^unreachable default"'
ip link del warp0
r=$(rg 1.1.1.1 10.23.45.2)
ok "WARP упал сам (устройство пропало, rt_down ещё не было) — клиент без маршрута: $r" '[[ "$r" == *"No route to host"* || "$r" == *"nreachable"* ]]'
ok "…а сеть России у него — напрямую" '[[ "$(rg 77.88.8.8 10.23.45.2 0x52550000)" == *"dev eth0"* ]]'
ok "клиент без туннеля не задет" '[[ "$(rg 1.1.1.1 10.23.45.3)" == *"dev eth0"* ]]'
rt_down warp0 200
ok "rt_down в «блокировать»: правило осталось, таблица — «недоступно»" 'ip rule show | grep -q "lookup 200" && ! rt_table_live 200 && tunfail_held warp'
mkwarp; rt_up warp0 200 "$WARP_PEERS"
ok "WARP вернулся — клиент снова в warp0" '[[ "$(rg 1.1.1.1 10.23.45.2)" == *"dev warp0"* ]]'
ok "правило клиента одно (без дублей)" '(( $(ip rule show | grep -c "lookup 200") == 1 ))'
ip link del warp0; rt_down warp0 200
rm -f "$WARP_STATE"; rt_down warp0 200
ok "выключили руками (состояния нет) — отпущен напрямую" '! ip rule show | grep -q "lookup 200" && [[ "$(rg 1.1.1.1 10.23.45.2)" == *"dev eth0"* ]]'

echo "── сторож после перезагрузки ──"
touch "$WARP_STATE"; tunfail_guard_run >/dev/null
ok "WARP включён, не поднялся — сторож удержал клиента" '[[ "$(rg 1.1.1.1 10.23.45.2)" == *"No route"* ]]'
ip tuntap add mode tun dev tun0; ip addr add 198.18.0.1/30 dev tun0; ip link set tun0 up
rt_up tun0 100 -
ok "поднят tun2socks — удержание WARP снято, клиент в tun0" '! ip rule show | grep -q "lookup 200" && [[ "$(rg 1.1.1.1 10.23.45.2)" == *"dev tun0"* ]]'
tunfail_guard_run >/dev/null
ok "сторож при живом tun2socks WARP не держит" '! ip rule show | grep -q "lookup 200"'
else
mkwarp; rt_up warp0 200 "$WARP_PEERS"
mkdir -p "$RUDIRECT_DIR" "$RUDIRECT_USER"
for b in $(seq 0 255); do for c in 0 64 128 192; do echo "77.$b.$c.0/18"; done; done > "$RUDIRECT_DIR/ru.list"
echo "77.88.8.0/24" > "$RUDIRECT_USER/tunnel.list"; echo "5.255.255.5" > "$RUDIRECT_USER/direct.list"
_rud_set ON 1
echo "── РФ напрямую на настоящих ipset, iptables и ip rule ──"
rudirect_run apply; rc=$?; ok "apply: код 0" '(( rc == 0 ))'
ok "набор: сеть России, свой адрес, исключение nomatch" 'ipset test awg2-ru 77.1.1.1 2>/dev/null && ipset test awg2-ru 5.255.255.5 2>/dev/null && ! ipset test awg2-ru 77.88.8.8 2>/dev/null'
ok "правила: метка для awg0 и wgobf0, правило 90" 'rudirect_rules_ok && (( $(iptables-save -t mangle | grep -c awg2-rudirect) == 2 ))'
ok "сводка: $(rudirect_summary)" '[[ "$(rudirect_summary)" == "сетей РФ 1024, своих напрямую 1, через туннель 1" ]]'
rudirect_run apply >/dev/null
ok "повтор apply — без дублей правил" '(( $(iptables-save -t mangle | grep -c awg2-rudirect) == 2 && $(ip rule show | grep -c "fwmark 0x52550000") == 1 ))'
ok "счётчики читаются: $(rudirect_counters)" '[[ "$(rudirect_counters)" =~ ^[0-9]+\ [0-9]+$ ]]'
echo "── Куда идёт адрес (ядро) ──"
rudirect_on() { [[ "$(_rud_get ON)" == 1 ]]; }
out=$(diag_route alice 77.1.1.1); ok "сеть России — rudirect: $out" '[[ "$out" == *$'"'"'\trudirect\teth0\t'"'"'* ]]'
out=$(diag_route alice 77.88.8.8); ok "исключение — через WARP: $out" '[[ "$out" == *$'"'"'\twarp\twarp0\t'"'"'* ]]'
out=$(diag_route alice 1.1.1.1); ok "прочее — через WARP" '[[ "$out" == *$'"'"'\twarp\t'"'"'* ]]'
out=$(diag_route bob 1.1.1.1); ok "клиент без туннеля — direct: $out" '[[ "$out" == *$'"'"'\tdirect\teth0\t'"'"'* ]]'
echo "warp=block" > "$TUNFAIL_CONF"; rt_fail_route 200; ip link del warp0; rt_down warp0 200
out=$(diag_route alice 1.1.1.1); ok "WARP упал, «блокировать» — held: $out" '[[ "$out" == *$'"'"'\theld\t'"'"'* ]]'
out=$(diag_route alice 77.1.1.1); ok "…сеть России у удержанного — rudirect" '[[ "$out" == *$'"'"'\trudirect\t'"'"'* ]]'
echo 0 > /proc/sys/net/ipv4/ip_forward
out=$(diag_route alice 1.1.1.1); ok "пересылка выключена — none с подсказкой: $out" '[[ "$out" == *$'"'"'\tnone\t'"'"'*ip_forward* ]]'
echo 1 > /proc/sys/net/ipv4/ip_forward
_rud_set ON 0; rudirect_run off
ok "off: правила и набор сняты" '! ipset list -n awg2-ru &>/dev/null && ! iptables-save -t mangle | grep -q awg2-rudirect && ! ip rule show | grep -q fwmark'
fi
echo "проверок: $((pass+fail)), провалов: $fail"
(( fail == 0 ))
