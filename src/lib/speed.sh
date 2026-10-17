# Скорость клиентов — одна цифра (Мбит/с) на оба направления.
#
# Скачивание (сервер → клиент): HTB на выходе awg0, у каждого клиента своя
# полоса по его адресу в VPN, внутри — fq_codel. Отдача (клиент → сервер):
# Linux выравнивает только исходящую очередь, поэтому вход awg0 по адресам
# ограниченных клиентов перенаправляется в ifb-интерфейс и режется там тем же
# HTB. Нет модуля ifb — отдача режется полисером на входе awg0 (грубее).
# Весь трафик клиента проходит через awg0, поэтому скорость действует при
# любом маршруте: напрямую, WARP, Xray, exit-ноды.
#
# Метки клиента в конфиге сервера:
#   # speed=N        постоянная скорость, Мбит/с;
#   # limit_slow=N   исчерпал лимит трафика — не блокировать, а замедлять до N;
#   # slowed_by=traffic  сейчас замедлен (ставит и снимает таймер лимитов).
# Таймер сроков (каждые 15 с) сверяет план с тем, что стоит в tc, и ставит
# заново после перезапуска awg0 или перезагрузки — хуков в конфиге сервера
# не нужно. Клиенты без ограничений идут через awg0 как раньше; пока
# ограничений нет ни у кого, tc на awg0 не трогается вовсе.

SPEED_IFB="${AWG_IF}-ifb"
SPEED_H="a2"             # свой handle корня: чужую очередь (поставленную руками) не трогаем
SPEED_MAX=10000          # Мбит/с
SPEED_ERR=""

# Корень awg0: ours — наша HTB; free — очередь по умолчанию (handle 0:);
# busy — чужая, её не трогаем.
_speed_root() {
  local q
  q=$(tc qdisc show dev "$AWG_IF" root 2>/dev/null | head -1)
  case "$q" in
    "qdisc htb $SPEED_H: "*) echo ours ;;
    "" | "qdisc "*" 0: "*) echo free ;;
    *) echo busy ;;
  esac
}

# Запас HTB: ~20 мс на скорости, не меньше 16 КБ — иначе на малых скоростях
# пакеты GSO (до 64 КБ) шли бы рывками.
_speed_burst() { local b=$(( $1 * 5 / 2 )); (( b < 16 )) && b=16; echo "${b}k"; }

# Команды tc -batch под план «адрес<TAB>Мбит/с»; $2 — ifb или police;
# $3 — очередь внутри полос (fq_codel, а в ядре без него — проще).
_speed_batch() {
  local plan="$1" mode="$2" leaf="$3" ip r k=1 id b proto m prio d devs=("$AWG_IF")
  [[ "$mode" == ifb ]] && devs+=("$SPEED_IFB")
  echo "qdisc add dev $AWG_IF root handle $SPEED_H: htb default 1"
  echo "class add dev $AWG_IF parent $SPEED_H: classid $SPEED_H:1 htb rate 10gbit quantum 60000"
  echo "qdisc add dev $AWG_IF parent $SPEED_H:1 $leaf"
  [[ "$mode" == down ]] || echo "qdisc add dev $AWG_IF handle ffff: ingress"
  if [[ "$mode" == ifb ]]; then
    echo "qdisc add dev $SPEED_IFB root handle $SPEED_H: htb default 1"
    echo "class add dev $SPEED_IFB parent $SPEED_H: classid $SPEED_H:1 htb rate 10gbit quantum 60000"
    echo "qdisc add dev $SPEED_IFB parent $SPEED_H:1 $leaf"
  fi
  while IFS=$'\t' read -r ip r; do
    [[ -n "$ip" && "$r" =~ ^[0-9]+$ ]] || continue
    k=$((k + 1)); id=$(printf '%x' "$k"); b=$(_speed_burst "$r")
    # У одного приоритета фильтров — один протокол: IPv4 и IPv6 — разные
    if [[ "$ip" == *:* ]]; then proto=ipv6 m=ip6 prio=2; else proto=ip m=ip prio=1; fi
    for d in "${devs[@]}"; do
      echo "class add dev $d parent $SPEED_H: classid $SPEED_H:$id htb rate ${r}mbit ceil ${r}mbit burst $b cburst $b quantum 1514"
      echo "qdisc add dev $d parent $SPEED_H:$id $leaf"
    done
    echo "filter add dev $AWG_IF parent $SPEED_H: protocol $proto prio $prio u32 match $m dst $ip flowid $SPEED_H:$id"
    if [[ "$mode" == ifb ]]; then
      echo "filter add dev $SPEED_IFB parent $SPEED_H: protocol $proto prio $prio u32 match $m src $ip flowid $SPEED_H:$id"
      echo "filter add dev $AWG_IF parent ffff: protocol $proto prio $prio u32 match $m src $ip action mirred egress redirect dev $SPEED_IFB"
    elif [[ "$mode" == police ]]; then
      echo "filter add dev $AWG_IF parent ffff: protocol $proto prio $prio u32 match $m src $ip police rate ${r}mbit burst $b drop flowid :1"
    fi
  done <<< "$plan"
}

# Снять наши правила: корень — только свой, вход и ifb — если ставили мы.
speed_clear() {
  local own="$EXPIRE_STATE_DIR/speed.own"
  [[ "$(_speed_root)" == ours ]] && tc qdisc del dev "$AWG_IF" root 2>/dev/null
  if [[ -f "$own" ]]; then
    tc qdisc del dev "$AWG_IF" ingress 2>/dev/null
    ip link show "$SPEED_IFB" &>/dev/null && ip link del "$SPEED_IFB" 2>/dev/null
  fi
  rm -f "$own" "$EXPIRE_STATE_DIR/speed" "$EXPIRE_STATE_DIR/speed.err" "$EXPIRE_STATE_DIR/speed.mode"
  return 0
}

# Снять поставленное наполовину (прошлая попытка сборки не прошла).
_speed_undo() {
  [[ "$(_speed_root)" == ours ]] && tc qdisc del dev "$AWG_IF" root 2>/dev/null
  tc qdisc del dev "$AWG_IF" ingress 2>/dev/null
  ip link show "$SPEED_IFB" &>/dev/null && tc qdisc del dev "$SPEED_IFB" root 2>/dev/null
  return 0
}

# Поставить правила по плану заново. Ошибка — в SPEED_ERR; в speed.mode —
# как режется отдача: ifb, police или down (никак: в ядре нет ни ifb, ни
# полисера — режется только скачивание).
_speed_build() {
  local plan="$1" own="$EXPIRE_STATE_DIR/speed.own" bat errf rc=1 leaf mode modes=(police down)
  mkdir -p "$EXPIRE_STATE_DIR"
  # Вход awg0 занят не нами (своя очередь ingress, поставленная руками) — не трогаем
  if [[ ! -f "$own" ]] && tc qdisc show dev "$AWG_IF" ingress 2>/dev/null | grep -q .; then
    SPEED_ERR="на $AWG_IF уже стоит своя очередь ingress (tc) — не трогаю"
    return 1
  fi
  : > "$own"
  _speed_undo
  # numifbs=0: модуль без лишних ifb0 и ifb1
  [[ -d /sys/module/ifb ]] || modprobe ifb numifbs=0 2>/dev/null || true
  if { ip link show "$SPEED_IFB" &>/dev/null || ip link add "$SPEED_IFB" type ifb 2>/dev/null; } \
     && ip link set "$SPEED_IFB" up 2>/dev/null; then
    modes=(ifb police down)
  fi
  bat=$(mktemp) && errf=$(mktemp) || return 1
  # Очередь в полосах: fq_codel есть в ядрах Ubuntu и Debian; нет — sfq,
  # затем простая. Не принят режим отдачи (нет act_mirred, act_police) — следующий.
  for mode in "${modes[@]}"; do
    for leaf in fq_codel "sfq perturb 10" "pfifo limit 1000"; do
      _speed_batch "$plan" "$mode" "$leaf" > "$bat"
      if tc -batch "$bat" 2>"$errf"; then rc=0; break 2; fi
      _speed_undo
      grep -q 'qdisc kind is unknown' "$errf" || break
    done
  done
  if (( rc )); then
    SPEED_ERR="tc: $(grep -v '^Command failed' "$errf" | head -2 | tr '\n' ' ')"
    SPEED_ERR="${SPEED_ERR% }"
  else
    printf '%s\n' "$mode" > "$EXPIRE_STATE_DIR/speed.mode"
    [[ "$mode" == ifb ]] || { ip link show "$SPEED_IFB" &>/dev/null && ip link del "$SPEED_IFB" 2>/dev/null; }
  fi
  rm -f "$bat" "$errf"
  return "$rc"
}

# Привести tc к плану. 0 — стоит как надо, или ограничений нет, или awg0 не поднят (таймер
# поставит, когда поднимется); 1 — не вышло (причина в SPEED_ERR).
speed_apply() {
  local plan st="$EXPIRE_STATE_DIR/speed" root
  SPEED_ERR=""
  [[ -f "$SERVER_CONF" ]] || return 0
  plan=$(py speed-plan "$SERVER_CONF" "$EXPIRE_SUSPEND_IP") || { SPEED_ERR="план скорости не прочитан"; return 1; }
  if [[ -z "$plan" ]]; then
    [[ -f "$st" || -f "$st.own" ]] && speed_clear
    return 0
  fi
  ip link show "$AWG_IF" &>/dev/null || return 0
  root=$(_speed_root)
  if [[ "$root" == busy ]]; then
    SPEED_ERR="на $AWG_IF уже стоит своя очередь tc — не трогаю"
    return 1
  fi
  [[ "$root" == ours && "$(cat "$st" 2>/dev/null)" == "$plan" ]] && return 0
  _speed_build "$plan" || return 1
  printf '%s\n' "$plan" > "$st"
}

# Проход таймера: ограничений нет и не было — один grep. Ошибка пишется в
# журнал сроков один раз, пока не сменится.
speed_check() {
  local st="$EXPIRE_STATE_DIR/speed" e
  [[ -f "$st" || -f "$st.own" ]] || grep -qE '^#[[:space:]]*(speed|slowed_by)=' "$SERVER_CONF" 2>/dev/null || return 0
  if speed_apply; then rm -f "$st.err"; return 0; fi
  e="${SPEED_ERR:-tc не принял правила}"
  if [[ "$(cat "$st.err" 2>/dev/null)" != "$e" ]]; then
    mkdir -p "$EXPIRE_STATE_DIR"
    printf '%s\n' "$e" > "$st.err"
    echo "$(date '+%F %T') speed: $e" >> "$EXPIRE_LOG"
  fi
  return 0
}

# Число Мбит/с из ввода («20», «20M», «20 Мбит»); off, 0, пусто — без ограничения.
_speed_num() {  # → число или пусто; 1 — не распознано
  local v="${1// /}"
  v="${v,,}"; v="${v%/s}"; v="${v%/с}"; v="${v%mbit}"; v="${v%мбит}"; v="${v%Мбит}"; v="${v%m}"; v="${v%м}"; v="${v%М}"
  case "$v" in off | 0 | "" | none | no) echo ""; return 0 ;; esac
  [[ "$v" =~ ^[0-9]{1,5}$ ]] || return 1
  v=$((10#$v))
  (( v >= 1 && v <= SPEED_MAX )) || return 1
  echo "$v"
}

client_speed_set() {  # имя Мбит/с|off
  local name="$1" v
  client_exists "$name" || { err "Клиента $name нет"; return 1; }
  v=$(_speed_num "$2") || { err "Скорость: целое число Мбит/с от 1 до $SPEED_MAX или off"; return 1; }
  py meta-set "$SERVER_CONF" "$name" speed "$v" || return 1
  expire_install
  if ! speed_apply; then
    err "Скорость записана, но не применилась: $SPEED_ERR"
    return 1
  fi
  if [[ -n "$v" ]]; then ok "Скорость $name: $v Мбит/с"; else ok "$name — без ограничения скорости"; fi
  [[ -n "$v" && "$(cat "$EXPIRE_STATE_DIR/speed.mode" 2>/dev/null)" == down ]] \
    && warn "Отдача (клиент → сервер) не ограничивается: в ядре нет ни ifb, ни полисера tc — режется только скачивание"
  return 0
}

# Что делать, когда лимит трафика исчерпан: block — блокировать (как было),
# число — замедлять до стольких Мбит/с. Применяется сразу.
client_limit_mode() {  # имя block|Мбит/с
  local name="$1" v
  client_exists "$name" || { err "Клиента $name нет"; return 1; }
  if [[ "$2" == block ]]; then v=""
  else
    v=$(_speed_num "$2") && [[ -n "$v" ]] || { err "При исчерпании: block или скорость в Мбит/с от 1 до $SPEED_MAX"; return 1; }
  fi
  py meta-set "$SERVER_CONF" "$name" limit_slow "$v" || return 1
  expire_install
  traffic_tick 1
  [[ -f "$EXPIRE_STATE_DIR/speed.err" ]] && warn "Скорость не применилась: $(cat "$EXPIRE_STATE_DIR/speed.err")"
  if [[ -n "$v" ]]; then ok "$name: исчерпал лимит — замедлять до $v Мбит/с"
  else ok "$name: исчерпал лимит — блокировать"; fi
}

# «20 Мбит/с», «🐢 1 Мбит/с — лимит исчерпан» для меню.
speed_fmt() {  # speed limit_slow slowed_by
  local sp="$1" slow="$2" by="$3"
  if [[ "$by" == traffic && -n "$slow" ]]; then
    if [[ -n "$sp" ]] && (( sp < slow )); then echo "$sp Мбит/с"; else echo "🐢 $slow Мбит/с — лимит исчерпан"; fi
  elif [[ -n "$sp" ]]; then echo "$sp Мбит/с"
  fi
}

_ask_speed() {  # → Мбит/с, «off» или пусто (отмена)
  local v
  echo -e "  ${D}Одна цифра на скачивание и отдачу, Мбит/с: 5, 10, 20, 50, 100; 0 — без ограничения${N}" >&2
  read -rp "  Скорость: " v
  [[ -n "$v" ]] || return 0
  v=$(_speed_num "$v") || { warn "Не понял скорость: целое число Мбит/с от 1 до $SPEED_MAX" >&2; return 0; }
  echo "${v:-off}"
}

_ask_limit_mode() {  # → block, Мбит/с или пусто (отмена)
  local c
  echo -e "  ${C}1)${N} Блокировать ${D}— как истёкший; в новом месяце разблокируется сам${N}" >&2
  echo -e "  ${C}2)${N} Замедлять до 1 Мбит/с" >&2
  echo -e "  ${C}3)${N} Замедлять до 2 Мбит/с" >&2
  echo -e "  ${C}4)${N} Замедлять до 5 Мбит/с" >&2
  read_choice c "${C}  Исчерпал лимит [1-4]: ${N}" 1 4 1
  case "$c" in 2) echo 1 ;; 3) echo 2 ;; 4) echo 5 ;; *) echo block ;; esac
}
