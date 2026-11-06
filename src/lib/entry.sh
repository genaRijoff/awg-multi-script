# Точки входа (каскад): клиент подключается не к этому серверу напрямую, а
# через сервер-вход — любой сервер, где UDP-порт проброшен сюда (каскад Тулзы,
# свой iptables, nginx stream). В конфиге такого клиента Endpoint — адрес
# входа; ключи, лимиты, скорость, сроки и выходы — как у всех, сервер разницы
# не видит. Хранение — py entry: список в шапке awg0.conf, вход клиента —
# метка его пира, поэтому всё попадает в любой бэкап вместе с клиентами.

entry_direct() { echo "$(endpoint_host):$(server_port)"; }

# Endpoint для конфига клиента: адрес его входа, без входа — сервер напрямую.
client_endpoint() {  # имя
  local a
  a=$(py entry "$SERVER_CONF" of "$1" 2>/dev/null)
  echo "${a:-$(entry_direct)}"
}

# Вход нового клиента: _O_ENTRY пусто — вход по умолчанию, direct — напрямую,
# иначе имя входа. Итог — в _ENTRY_NEW (имя, пусто — напрямую) и
# _ENTRY_NEW_ADDR (его адрес); помнится до смены списка или _O_ENTRY: пакет
# из 200 клиентов не спрашивает Python 400 раз.
_O_ENTRY="" _ENTRY_NEW="" _ENTRY_NEW_ADDR="" _ENTRY_NEW_KEY="-"
client_new_entry() {
  [[ "$_ENTRY_NEW_KEY" == "$_O_ENTRY" ]] && return 0
  _ENTRY_NEW="" _ENTRY_NEW_ADDR=""
  case "$_O_ENTRY" in
    "") _ENTRY_NEW=$(entry_default_get) ;;
    direct) ;;
    *) _ENTRY_NEW="$_O_ENTRY" ;;
  esac
  [[ -n "$_ENTRY_NEW" ]] && _ENTRY_NEW_ADDR=$(py entry "$SERVER_CONF" get "$_ENTRY_NEW" 2>/dev/null)
  [[ -n "$_ENTRY_NEW_ADDR" ]] || _ENTRY_NEW=""
  _ENTRY_NEW_KEY="$_O_ENTRY"
}
_entry_new_reset() { _ENTRY_NEW_KEY="-"; }

# py entry: вывод — в ENTRY_OUT, отказ — в err.
ENTRY_OUT=""
_entry_py() {
  _entry_new_reset
  ENTRY_OUT=$(py entry "$SERVER_CONF" "$@" 2>&1) && return 0
  err "${ENTRY_OUT##*$'\n'}"
  ENTRY_OUT=""
  return 1
}

# Строки «клиент<TAB>адрес» (пусто — напрямую) → Endpoint в их конфигах.
# У перенесённых из Amnezia файла нет — им адрес достанется при перевыпуске.
ENTRY_REWRITTEN=0
_entry_apply() {
  local n a f direct
  direct=$(entry_direct)
  ENTRY_REWRITTEN=0
  while IFS=$'\t' read -r n a; do
    [[ -n "$n" ]] || continue
    f=$(client_file "$n")
    [[ -f "$f" ]] && grep -q '^Endpoint = ' "$f" || continue
    sed -i "s|^Endpoint = .*|Endpoint = ${a:-$direct}|" "$f" && ENTRY_REWRITTEN=$((ENTRY_REWRITTEN + 1))
  done <<< "$1"
}

_entry_rewritten_note() {
  (( ENTRY_REWRITTEN )) || return 0
  info "Конфигов переписано: $ENTRY_REWRITTEN — этим клиентам нужен новый конфиг или QR"
}

# «имя» или пусто/direct — напрямую
_entry_arg() { [[ "${1:-}" == direct ]] && echo "" || echo "${1:-}"; }

entry_add() {  # имя хост:порт
  server_exists || { err "Сервер не создан"; return 1; }
  _entry_py add "${1:-}" "${2:-}" || return 1
  ok "Точка входа «$1»: $(py entry "$SERVER_CONF" get "$1")"
  log_info "точка входа добавлена: $1"
  entry_check "$1" soft || true
  info "Вход клиенту — в его карточке («Вход»); всем новым — «По умолчанию»"
}

entry_set() {  # имя хост:порт — новый адрес входа; конфиги его клиентов переписываются
  server_exists || { err "Сервер не создан"; return 1; }
  _entry_py set "${1:-}" "${2:-}" || return 1
  _entry_apply "$ENTRY_OUT"
  ok "Точка входа «$1»: $(py entry "$SERVER_CONF" get "$1")"
  log_info "точка входа изменена: $1"
  _entry_rewritten_note
  entry_check "$1" soft || true
}

entry_del() {  # имя — его клиенты переходят на «напрямую»
  server_exists || { err "Сервер не создан"; return 1; }
  _entry_py del "${1:-}" || return 1
  _entry_apply "$ENTRY_OUT"
  ok "Точка входа «$1» удалена"
  log_info "точка входа удалена: $1"
  [[ -n "$ENTRY_OUT" ]] && info "Её клиенты теперь подключаются напрямую: $(entry_direct)"
  _entry_rewritten_note
}

entry_default() {  # имя|direct — вход для новых клиентов
  local e
  server_exists || { err "Сервер не создан"; return 1; }
  e=$(_entry_arg "${1:-}")
  _entry_py default "$e" || return 1
  if [[ -n "$e" ]]; then ok "Новые клиенты — через вход «$e»"; else ok "Новые клиенты — напрямую"; fi
}

entry_default_get() { py entry "$SERVER_CONF" list 2>/dev/null | awk -F'\t' '$4 == 1 {print $1; exit}'; }

client_entry_set() {  # клиент имя|direct
  local e a
  server_exists || { err "Сервер не создан"; return 1; }
  e=$(_entry_arg "${2:-}")
  _entry_py assign "${1:-}" "$e" || return 1
  _entry_apply "$ENTRY_OUT"
  a=$(client_endpoint "$1")
  if [[ -n "$e" ]]; then ok "$1 → вход «$e» ($a)"; else ok "$1 → напрямую ($a)"; fi
  log_info "вход клиента: $1 → ${e:-напрямую}"
  (( ENTRY_REWRITTEN )) && info "Клиенту нужен новый конфиг или QR — в старом прежний Endpoint"
  return 0
}

entry_assign_all() {  # имя|direct — все клиенты
  local e
  server_exists || { err "Сервер не создан"; return 1; }
  e=$(_entry_arg "${1:-}")
  _entry_py assign-all "$e" || return 1
  _entry_apply "$ENTRY_OUT"
  if [[ -n "$e" ]]; then ok "Все клиенты — через вход «$e»"; else ok "Все клиенты — напрямую"; fi
  log_info "вход всех клиентов: ${e:-напрямую}"
  _entry_rewritten_note
}

# Доходит ли пакет через вход до этого сервера: шлём с сервера UDP с меткой
# на адрес входа и ловим его на своём порту AWG (правило raw со строкой
# метки). Простой проброс порта (DNAT) возвращает пакет сюда же.
# 0 — дошёл, 1 — нет, 2 — проверить нельзя (адрес не найден, нет модуля string).
ENTRY_PROBE_TAG="awg2-entry-check"
entry_probe() {  # хост:порт
  local host="${1%:*}" port="${1##*:}" ip mark i n rc=1
  if valid_ip "$host"; then ip="$host"
  else ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}'); fi
  [[ -n "$ip" ]] || return 2
  mark="$ENTRY_PROBE_TAG-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  ipt_del_grep raw "--comment \"?${ENTRY_PROBE_TAG}\"?( |$)"
  iptables -t raw -I PREROUTING 1 -p udp --dport "$(server_port)" -m string --algo bm --string "$mark" \
    -m comment --comment "$ENTRY_PROBE_TAG" -j ACCEPT 2>/dev/null || return 2
  for i in 1 2 3 4; do
    { printf '%s' "$mark" > "/dev/udp/$ip/$port"; } 2>/dev/null || true
    sleep 0.5
    n=$(iptables -t raw -L PREROUTING -v -x -n 2>/dev/null | awk -v t="$ENTRY_PROBE_TAG" 'index($0, t) {print $1; exit}')
    [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )) && { rc=0; break; }
  done
  ipt_del_grep raw "--comment \"?${ENTRY_PROBE_TAG}\"?( |$)"
  return "$rc"
}

entry_check() {  # имя [soft] — soft: провал проверки — предупреждение, не ошибка
  local a m rc=0
  server_exists || { err "Сервер не создан"; return 1; }
  a=$(py entry "$SERVER_CONF" get "${1:-}" 2>/dev/null)
  [[ -n "$a" ]] || { err "Точки входа «${1:-}» нет"; return 1; }
  info "Проверяю вход «$1»: пакет с сервера на $a должен вернуться на порт AWG"
  entry_probe "$a" || rc=$?
  case "$rc" in
    0) ok "Вход работает: пакеты через $a доходят до этого сервера" ;;
    1) m="Через $a пакеты до сервера не дошли — проверь проброс на сервере-входе: UDP ${a##*:} → $(public_ip_cached):$(server_port)"
       if [[ "${2:-}" == soft ]]; then warn "$m"; else err "$m"; fi
       info "Вход не простым пробросом (прокси, фильтр по адресам) проверку может не пройти и рабочим — тогда проверь клиентом" ;;
    *) warn "Проверить вход не удалось (адрес не найден или нет модуля iptables string) — проверь клиентом"
       rc=0 ;;
  esac
  return "$rc"
}

# ── Меню awg2 ─────────────────────────────────────────────
_entry_rows() { py entry "$SERVER_CONF" list 2>/dev/null; }

_entry_pick() {  # [direct — с «напрямую»] → имя в CHOSEN (пусто — напрямую)
  local rows=() i c n a k d off=0
  mapfile -t rows < <(_entry_rows)
  if [[ "${1:-}" == direct ]]; then
    off=1
    echo -e "  ${G}  1)${N} Напрямую ${D}— $(entry_direct)${N}"
  else
    (( ${#rows[@]} )) || { warn "Точек входа нет"; return 1; }
  fi
  for i in "${!rows[@]}"; do
    IFS=$'\t' read -r n a k d <<< "${rows[$i]}"
    printf "  ${G}%3d)${N} %s ${D}— %s, клиентов %s%s${N}\n" "$((i + 1 + off))" "$n" "$a" "$k" "$( (( d )) && echo ', по умолчанию')"
  done
  read_choice c "${C}  Номер (0 — отмена): ${N}" 0 "$(( ${#rows[@]} + off ))" 0
  (( c == 0 )) && return 1
  CHOSEN=""
  (( c > off )) && CHOSEN=$(cut -f1 <<< "${rows[$((c - 1 - off))]}")
  return 0
}

do_entries_menu() {
  server_exists || { err "Сервер не создан"; return 1; }
  local c n a k d def
  while true; do
    echo ""
    hdr "Точки входа (каскад)"
    echo -e "  ${D}Клиент подключается через сервер-вход, где UDP-порт проброшен на этот.${N}"
    echo -e "  ${D}В его конфиге Endpoint — адрес входа. Напрямую: $(entry_direct)${N}"
    while IFS=$'\t' read -r n a k d; do
      [[ -n "$n" ]] && echo -e "  ${W}•${N} $n ${D}— $a, клиентов $k$( (( d )) && echo ', по умолчанию')${N}"
    done < <(_entry_rows)
    def=$(entry_default_get)
    echo ""
    echo -e "  ${G}1)${N} Добавить"
    echo -e "  ${C}2)${N} Изменить адрес"
    echo -e "  ${C}3)${N} Проверить"
    echo -e "  ${C}4)${N} Вход для новых клиентов ${D}— ${def:-напрямую}${N}"
    echo -e "  ${C}5)${N} Перевести всех клиентов"
    echo -e "  ${R}6)${N} Удалить"
    echo -e "  ${W}0)${N} ← Назад"
    read_choice c "${C}  Выбор [0-6]: ${N}" 0 6 0
    case "$c" in
      1) read_line n "${C}  Название (например, Каскад NL): ${N}"
         [[ -n "$n" ]] || continue
         read_line a "${C}  Адрес входа хост:порт: ${N}"
         [[ -n "$a" ]] && { entry_add "$n" "${a// /}" || true; } ;;
      2) _entry_pick || continue
         n="$CHOSEN"
         read_line a "${C}  Новый адрес «$n» хост:порт: ${N}"
         [[ -n "$a" ]] && { entry_set "$n" "${a// /}" || true; } ;;
      3) _entry_pick && { entry_check "$CHOSEN" || true; } ;;
      4) _entry_pick direct && { entry_default "${CHOSEN:-direct}" || true; } ;;
      5) _entry_pick direct || continue
         ask_yes "  Переписать Endpoint во всех конфигах? [y/N]: " n && { entry_assign_all "${CHOSEN:-direct}" || true; } ;;
      6) _entry_pick || continue
         ask_yes "  Удалить «$CHOSEN»? Его клиенты перейдут на «напрямую» [y/N]: " n && { entry_del "$CHOSEN" || true; } ;;
      0) return 0 ;;
    esac
    pause
  done
}

do_client_entry() {
  server_exists || { err "Сервер не создан"; return 1; }
  local name
  [[ -n "$(_entry_rows)" ]] || { warn "Точек входа нет — добавь: Сервер → Endpoint → Точки входа"; return 1; }
  _pick_client || return 0
  name="${CHOSEN%%$'\t'*}"
  echo -e "  Сейчас: ${W}$(client_endpoint "$name")${N}"
  _entry_pick direct || return 0
  client_entry_set "$name" "${CHOSEN:-direct}" && share_config "$(client_file "$name")" qr
}
