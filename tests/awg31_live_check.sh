#!/bin/bash
# awg31_live_check.sh — проверка AmneziaWG 3.1 на реальном ядре.
#
# Рабочий awg0 не трогается: тест поднимает две пары интерфейсов в отдельных
# network namespace, соединённых veth, и гоняет через них трафик. Проверяются
# по очереди наборы параметров 3.0 (контроль) и 3.1 (RandomTrailers,
# DisableCookies) — если 3.1 не поедет, а 3.0 поедет, причина именно в 3.1.
#
# Запуск: sudo bash tests/awg31_live_check.sh
# Выход:  0 — обе версии дали рукопожатие и пинг, 1 — есть провал.
set -uo pipefail

NS_A=awg31a; NS_B=awg31b
IF_A=awgt-a;  IF_B=awgt-b
PORT_A=51999
LINK_A=10.199.31.1; LINK_B=10.199.31.2
TUN_A=10.66.31.1;   TUN_B=10.66.31.2
TMP=$(mktemp -d); FAIL=0

R='\033[38;5;203m'; G='\033[0;32m'; Y='\033[0;33m'; D='\033[0;90m'; N='\033[0m'
ok(){   echo -e "  ${G}√${N} $*"; }
err(){  echo -e "  ${R}×${N} $*"; FAIL=$((FAIL+1)); }
info(){ echo -e "  ${D}→ $*${N}"; }

cleanup() {
  ip netns del "$NS_A" 2>/dev/null
  ip netns del "$NS_B" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'echo; echo "прервано"; exit 130' INT TERM

[[ $EUID -eq 0 ]] || { echo "нужен root: sudo bash $0"; exit 1; }
for b in ip awg ping; do command -v "$b" >/dev/null || { echo "нет $b"; exit 1; }; done

echo "── компоненты ──"
awg_ver=$(awg --version 2>/dev/null | head -1)
mod_ver=$(cat /sys/module/amneziawg/version 2>/dev/null || echo "не загружен")
info "tools : $awg_ver"
info "модуль: $mod_ver"
grep -aq 'RandomTrailers' "$(command -v awg)" \
  && ok "awg знает ключ RandomTrailers" \
  || { err "awg не знает RandomTrailers — 3.1 не поддерживается"; exit 1; }

rnd(){ echo $(( $1 + RANDOM % ($2 - $1 + 1) )); }

# Параметры устройства. Обязаны совпадать у обеих сторон — иначе рукопожатие
# не состоится, что и есть предмет проверки.
gen_params() {   # $1 = 3.0 | 3.1
  # S1-S4 не ниже 12: при заданном HeaderProtectionKey ядро требует место под
  # nonce защиты заголовков (header_protection.h: NONCE_SIZE = 12), иначе
  # setconf возвращает EINVAL.
  cat <<PARAMS
Jc = $(rnd 4 8)
Jmin = $(rnd 40 80)
Jmax = $(rnd 200 400)
S1 = $(rnd 30 70)
S2 = $(rnd 30 70)
S3 = $(rnd 12 40)
S4 = $(rnd 12 40)
H1 = $(rnd 100000 300000)
H2 = $(rnd 400000 600000)
H3 = $(rnd 700000 900000)
H4 = $(rnd 1000000 1200000)
HeaderProtectionKey = $(awg genkey)
ContentPaddingAddition = $(rnd 8 24)-$(rnd 48 96)
RekeyAfterTime = 115-150
RekeyTimeout = 5
RejectAfterTime = 175-205
KeepaliveTimeout = 10-25
MaxHandshakeAttempts = 18
PARAMS
  [[ "$1" == "3.1" ]] && printf 'RandomTrailers = on\nDisableCookies = on\n'
}

run_case() {   # $1 = версия
  local ver="$1" params key_a key_b pub_a pub_b
  echo ""
  echo "── AWG $ver ──"
  params=$(gen_params "$ver")

  key_a=$(awg genkey); pub_a=$(echo "$key_a" | awg pubkey)
  key_b=$(awg genkey); pub_b=$(echo "$key_b" | awg pubkey)

  # Хвосты прошлого прогона (в том числе аварийного) убираем до создания,
  # иначе veth/netns уже заняты и тест падает не по делу
  ip netns del "$NS_A" 2>/dev/null; ip netns del "$NS_B" 2>/dev/null
  ip link del veth-a 2>/dev/null; ip link del veth-b 2>/dev/null
  sleep 0.2

  ip netns add "$NS_A" 2>/dev/null || true
  ip netns add "$NS_B" 2>/dev/null || true
  ip link add veth-a type veth peer name veth-b 2>/dev/null
  ip link set veth-a netns "$NS_A"; ip link set veth-b netns "$NS_B"
  ip -n "$NS_A" addr add "${LINK_A}/24" dev veth-a; ip -n "$NS_A" link set veth-a up
  ip -n "$NS_B" addr add "${LINK_B}/24" dev veth-b; ip -n "$NS_B" link set veth-b up
  ip -n "$NS_A" link set lo up; ip -n "$NS_B" link set lo up

  if ! ip netns exec "$NS_A" ip link add "$IF_A" type amneziawg 2>"$TMP/e"; then
    err "не создался интерфейс amneziawg: $(cat "$TMP/e")"; return 1
  fi
  ip netns exec "$NS_B" ip link add "$IF_B" type amneziawg 2>/dev/null

  { echo "[Interface]"; echo "PrivateKey = $key_a"; echo "ListenPort = $PORT_A"
    echo "$params"
    echo "[Peer]"; echo "PublicKey = $pub_b"; echo "AllowedIPs = ${TUN_B}/32"
  } > "$TMP/a.conf"
  { echo "[Interface]"; echo "PrivateKey = $key_b"
    echo "$params"
    echo "[Peer]"; echo "PublicKey = $pub_a"; echo "AllowedIPs = ${TUN_A}/32"
    echo "Endpoint = ${LINK_A}:${PORT_A}"; echo "PersistentKeepalive = 15-25"
  } > "$TMP/b.conf"

  if ! ip netns exec "$NS_A" awg setconf "$IF_A" "$TMP/a.conf" 2>"$TMP/e"; then
    err "setconf (сервер) отвергнут: $(tr '\n' ' ' < "$TMP/e")"; return 1
  fi
  if ! ip netns exec "$NS_B" awg setconf "$IF_B" "$TMP/b.conf" 2>"$TMP/e"; then
    err "setconf (клиент) отвергнут: $(tr '\n' ' ' < "$TMP/e")"; return 1
  fi
  ok "параметры $ver приняты ядром (setconf прошёл с обеих сторон)"

  if [[ "$ver" == "3.1" ]]; then
    local shown
    shown=$(ip netns exec "$NS_A" awg showconf "$IF_A" 2>/dev/null | grep -cE '^(RandomTrailers|DisableCookies) = ')
    [[ "$shown" -eq 2 ]] \
      && ok "showconf отдаёт RandomTrailers и DisableCookies — параметры реально в устройстве" \
      || err "showconf не показывает ключи 3.1 (нашлось $shown из 2)"
  fi

  ip -n "$NS_A" addr add "${TUN_A}/24" dev "$IF_A"; ip -n "$NS_A" link set "$IF_A" up
  ip -n "$NS_B" addr add "${TUN_B}/24" dev "$IF_B"; ip -n "$NS_B" link set "$IF_B" up

  if ip netns exec "$NS_B" ping -c 3 -W 3 -q "$TUN_A" >"$TMP/ping" 2>&1; then
    ok "пинг через туннель прошёл: $(grep -o '[0-9]* received' "$TMP/ping")"
  else
    err "пинг через туннель не прошёл"; sed 's/^/      /' "$TMP/ping"
  fi

  local hs
  hs=$(ip netns exec "$NS_B" awg show "$IF_B" latest-handshakes | awk '{print $2}')
  if [[ -n "$hs" && "$hs" != "0" ]]; then
    ok "рукопожатие состоялось ($(( $(date +%s) - hs )) с назад)"
  else
    err "рукопожатия нет"
  fi

  local rx tx
  read -r _ rx tx < <(ip netns exec "$NS_B" awg show "$IF_B" transfer)
  info "трафик клиента: rx=${rx:-0} B, tx=${tx:-0} B"

  ip netns del "$NS_A" 2>/dev/null; ip netns del "$NS_B" 2>/dev/null
  sleep 0.3
}

echo ""
echo "Рабочий awg0 не затрагивается: тест живёт в отдельных netns."
run_case "3.0"
run_case "3.1"

echo ""
if [[ $FAIL -eq 0 ]]; then
  echo -e "${G}Итог: AWG 3.0 и 3.1 работают на этом ядре.${N}"
else
  echo -e "${R}Итог: провалов — ${FAIL}.${N}"
fi
exit $(( FAIL > 0 ? 1 : 0 ))
