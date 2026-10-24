# Перенос сервера из Amnezia (Docker): приложение AmneziaVPN ставит AWG в
# контейнер amnezia-awg2 (AWG 2.0/3.1) или amnezia-awg (старый). Из него
# берутся ключ сервера, порт, параметры, подсеть и пиры с PSK — awg0 Тулзы
# поднимается ровно таким же, и конфиги клиентов работают без перевыдачи.
#
# Контейнер не удаляется, а останавливается: «Вернуть Amnezia» запускает его
# снова. Всё, что пришло из контейнера, — недоверенные данные: разбор и
# проверка — в helper (amnezia-scan / amnezia-conf), в awg0.conf попадают
# только известные ключи с проверенными значениями.
#
# Приватных ключей клиентов на сервере нет — они только у самих клиентов.
# Перенесённые помечены «# amnezia=исходное имя»: конфиг и QR для них Тулза
# не покажет, а перевыпустит (новый ключ) по просьбе.

AMNEZIA_SRC="/opt/amnezia/awg"
AMNEZIA_STATE_DIR="$STATE_DIR/amnezia"
AMNEZIA_MAX=1048576               # больше мегабайта в конфиге Amnezia не бывает

# Имя контейнера Amnezia AWG: новый (amnezia-awg2) первым. Только эти имена —
# в docker уходит проверенная строка.
amnezia_container() {
  local n
  command -v docker &>/dev/null || return 1
  n=$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -xE 'amnezia-awg2?' | sort -r | head -1)
  [[ -n "$n" ]] && echo "$n"
}

amnezia_running() { [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == true ]]; }

amnezia_migrated() { [[ -f "$AMNEZIA_STATE_DIR/container" ]]; }

# Файл из контейнера (и из остановленного): docker cp отдаёт tar, из него —
# только содержимое в stdout, на диск tar ничего не распаковывает.
_amnezia_cat() {  # контейнер файл
  docker cp "$1:$AMNEZIA_SRC/$2" - 2>/dev/null | tar -xOf - 2>/dev/null | head -c "$AMNEZIA_MAX"
}

# Конфиг, таблица клиентов и внешний порт контейнера → каталог (700, файлы 600).
amnezia_fetch() {  # контейнер каталог
  local c="$1" d="$2" f got=""
  [[ "$c" =~ ^amnezia-awg2?$ ]] || return 1
  ( umask 077; mkdir -p "$d" ) || return 1
  chmod 700 "$d"
  for f in awg0.conf wg0.conf; do
    if ( umask 077; _amnezia_cat "$c" "$f" > "$d/$f" ) && [[ -s "$d/$f" ]]; then got=1; break; fi
    rm -f "$d/$f"
  done
  [[ -n "$got" ]] || { err "В контейнере $c нет конфига сервера ($AMNEZIA_SRC/awg0.conf)"; return 1; }
  ( umask 077; _amnezia_cat "$c" clientsTable > "$d/clientsTable" ) || true
  # Наружу порт может быть проброшен другим номером — клиенты знают внешний
  ( umask 077
    docker inspect -f '{{range $p, $b := .HostConfig.PortBindings}}{{$p}} {{range $b}}{{.HostPort}} {{end}}{{"\n"}}{{end}}' "$c" 2>/dev/null \
      | awk '$1 ~ /\/udp$/ && $2 ~ /^[0-9]+$/ {print $2; exit}' > "$d/host_port" )
  return 0
}

# Версия протокола по ключам конфига — для проверки модуля до переноса.
_amnezia_proto() {  # каталог
  local f
  for f in "$1/awg0.conf" "$1/wg0.conf"; do
    [[ -f "$f" ]] || continue
    if grep -qE '^[[:space:]]*(RandomTrailers|DisableCookies)[[:space:]]*=' "$f"; then echo 3.1
    elif grep -qE '^[[:space:]]*HeaderProtectionKey[[:space:]]*=' "$f"; then echo 3.0
    else echo 2.0; fi
    return 0
  done
  echo 2.0
}

# Что мешает переносу сейчас (по строке): server — свой сервер Тулзы уже
# есть; components — нет awg/awg-quick; proto — модуль не умеет версию.
amnezia_blockers() {  # [версия]
  server_exists && echo server
  { command -v awg && command -v awg-quick; } &>/dev/null || { echo components; return 0; }
  local rc=0
  if [[ "${1:-2.0}" == 3* ]]; then
    proto_supported "$1" || rc=$?
    (( rc == 1 )) && echo proto
  fi
  return 0
}

_amnezia_state_clear() {
  [[ "$AMNEZIA_STATE_DIR" == */amnezia && -d "$AMNEZIA_STATE_DIR" ]] && rm -rf "$AMNEZIA_STATE_DIR"
  return 0
}

# Контейнер — как был: автозапуск и запуск.
_amnezia_back() {  # контейнер политика
  docker update --restart="$2" "$1" >/dev/null 2>&1 || warn "Автозапуск контейнера $1 вернуть не удалось"
  docker start "$1" >/dev/null 2>&1 || { err "Контейнер $1 не запустился — docker start $1"; return 1; }
}

# awg0 поднят и слушает нужный порт.
_amnezia_up_ok() { iface_up && [[ "$(awg show "$AWG_IF" listen-port 2>/dev/null)" == "$1" ]]; }

amnezia_migrate() {
  local c d sum proto port net dev restart n b
  c=$(amnezia_container) || { err "Контейнер Amnezia (amnezia-awg2 / amnezia-awg) не найден"; return 1; }
  amnezia_migrated && { err "Перенос уже сделан. Вернуть Amnezia: Сервер → Перенос из Amnezia"; return 1; }
  d="$AMNEZIA_STATE_DIR/orig"
  info "Читаю конфиг из контейнера $c"
  amnezia_fetch "$c" "$d" || { _amnezia_state_clear; return 1; }
  proto=$(_amnezia_proto "$d")
  b=$(amnezia_blockers "$proto")
  case "$b" in
    *server*) err "Сервер Тулзы уже создан — перенос только на сервер без своего awg0 (Сервер → Сбросить сервер)"; _amnezia_state_clear; return 1 ;;
    *components*) err "Сначала установи компоненты: Сервер → Установить компоненты"; _amnezia_state_clear; return 1 ;;
    *proto*) err "Модуль ядра не умеет AWG $proto — обнови модуль (Сервер → Модуль ядра и утилиты)"; _amnezia_state_clear; return 1 ;;
  esac
  # Конфиг проверяется до остановки контейнера: с ошибками ничего не трогаем
  sum=$(py amnezia-conf "$d" iface) || { _amnezia_state_clear; return 1; }
  port=$(sed -n 's/^ListenPort = //p' <<< "$sum")
  net=$(py amnezia-conf "$d" net) && valid_cidr "$net" || { err "Подсеть сервера не определена"; _amnezia_state_clear; return 1; }
  n=$(py amnezia-conf "$d" peers | grep -c '^\[Peer\]' || true)
  dev=$(uplink_iface) || { err "Не найден интерфейс маршрута по умолчанию"; _amnezia_state_clear; return 1; }
  restart=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$c" 2>/dev/null)
  [[ "$restart" =~ ^(no|always|unless-stopped|on-failure)$ ]] || restart=always
  printf '%s\n' "$c" > "$AMNEZIA_STATE_DIR/container"
  printf '%s\n' "$restart" > "$AMNEZIA_STATE_DIR/restart"
  date +%s > "$AMNEZIA_STATE_DIR/migrated"
  chmod 600 "$AMNEZIA_STATE_DIR/container" "$AMNEZIA_STATE_DIR/restart" "$AMNEZIA_STATE_DIR/migrated"
  info "Останавливаю контейнер $c (не удаляю — его можно вернуть)"
  docker update --restart=no "$c" >/dev/null 2>&1 || warn "Автозапуск контейнера выключить не удалось"
  if ! docker stop -t 20 "$c" >/dev/null 2>&1; then
    err "Контейнер $c не остановился"
    _amnezia_back "$c" "$restart"; _amnezia_state_clear; return 1
  fi
  mkdir -p "$AWG_DIR" && chmod 700 "$AWG_DIR"
  if ! { printf '%s\n\n' "$sum"; _postup_lines "$net" "$dev"; py amnezia-conf "$d" peers; } | write_file "$SERVER_CONF" 600; then
    err "awg0.conf не записан"
    rm -f "$SERVER_CONF"; _amnezia_back "$c" "$restart"; _amnezia_state_clear; return 1
  fi
  info "Поднимаю awg0: AWG $proto, порт $port, клиентов: $n"
  # shellcheck disable=SC2034  # S_PORT читает server_start_new (UFW)
  S_PORT="$port"
  if ! server_start_new || ! _amnezia_up_ok "$port"; then
    err "awg0 не поднялся — возвращаю Amnezia"
    awg-quick down "$SERVER_CONF" &>/dev/null || ip link del "$AWG_IF" &>/dev/null || true
    systemctl disable awg-quick@awg0 &>/dev/null || true
    rm -f "$SERVER_CONF"
    _amnezia_back "$c" "$restart" && ok "Amnezia снова работает ($c)"
    _amnezia_state_clear
    return 1
  fi
  # Копия файлов контейнера (с ключом сервера) больше не нужна: ключ — в awg0.conf,
  # для возврата есть сам контейнер
  [[ "$d" == */amnezia/orig && -d "$d" ]] && rm -rf "$d"
  log_info "перенос из Amnezia: $c → awg0, AWG $proto, порт $port, клиентов $n"
  ok "Перенесено из Amnezia: клиентов $n, порт $port/udp, AWG $proto"
  info "Конфиги клиентов прежние — переподключаться не нужно"
  warn "Приложение AmneziaVPN больше не управляет этим сервером (как клиент работает как раньше)"
  info "Контейнер $c остановлен, не удалён: Сервер → Перенос из Amnezia → Вернуть Amnezia"
}

amnezia_revert() {
  local c restart
  amnezia_migrated || { err "Переноса из Amnezia не было"; return 1; }
  c=$(cat "$AMNEZIA_STATE_DIR/container"); restart=$(cat "$AMNEZIA_STATE_DIR/restart" 2>/dev/null)
  [[ "$c" =~ ^amnezia-awg2?$ ]] || { err "Состояние переноса повреждено"; return 1; }
  [[ "$restart" =~ ^(no|always|unless-stopped|on-failure)$ ]] || restart=always
  docker inspect "$c" &>/dev/null || { err "Контейнера $c больше нет — вернуть Amnezia нельзя"; return 1; }
  if server_exists; then
    # Клиенты, созданные в Тулзе после переноса, остаются в бэкапе
    backup_create >/dev/null 2>&1 && info "Бэкап сервера Тулзы — в $BACKUP_DIR"
    awg-quick down "$SERVER_CONF" &>/dev/null || ip link del "$AWG_IF" &>/dev/null || true
    systemctl disable awg-quick@awg0 &>/dev/null || true
    rm -f "$SERVER_CONF"
  fi
  _amnezia_back "$c" "$restart" || return 1
  _amnezia_state_clear
  log_info "перенос из Amnezia отменён: $c снова запущен"
  ok "Amnezia снова работает ($c)"
}

# Контейнер больше не нужен: удалить его (данные Amnezia в нём — тоже).
amnezia_remove() {
  local c
  amnezia_migrated || { err "Сначала перенос: удалять можно только перенесённый контейнер"; return 1; }
  c=$(cat "$AMNEZIA_STATE_DIR/container")
  [[ "$c" =~ ^amnezia-awg2?$ ]] || { err "Состояние переноса повреждено"; return 1; }
  iface_up || { err "awg0 не работает — контейнер не удаляю, пока Тулза не подняла сервер"; return 1; }
  if docker inspect "$c" &>/dev/null; then
    docker rm -f "$c" >/dev/null 2>&1 || { err "Контейнер $c не удалён"; return 1; }
  fi
  _amnezia_state_clear
  log_info "контейнер Amnezia удалён: $c"
  ok "Контейнер $c удалён"
}

# Сводка для меню, бота и панели. Ключей в ней нет.
amnezia_scan_json() {
  local c d running=0 b
  c=$(amnezia_container) || c=""
  [[ -n "$c" ]] && amnezia_running "$c" && running=1
  if [[ -z "$c" ]] || amnezia_migrated; then
    { _kv container "$c"; _kv running:b "$running"; _kv migrated:b "$(_b amnezia_migrated)"; } | py json-kv
    return 0
  fi
  mktmp d -d || return 1
  if ! amnezia_fetch "$c" "$d/x" >/dev/null 2>&1; then
    { _kv container "$c"; _kv running:b "$running"; _kv error "конфиг контейнера не прочитан"; } | py json-kv
    return 0
  fi
  b=$(amnezia_blockers "$(_amnezia_proto "$d/x")" | paste -sd, -)
  # AmneziaDNS — отдельный контейнер: переносом не трогается и работает дальше
  py amnezia-scan "$d/x" "$c" "$running" "$b" \
    "$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx amnezia-dns && echo dns)"
}

do_amnezia_menu() {
  local c j
  c=$(amnezia_container) || c=""
  hdr "Перенос из Amnezia (Docker)"
  if amnezia_migrated; then
    info "Перенос сделан: контейнер $(cat "$AMNEZIA_STATE_DIR/container") остановлен"
    echo -e "  ${C}1)${N} Вернуть Amnezia ${D}— awg0 Тулзы снимается, контейнер запускается${N}"
    echo -e "  ${C}2)${N} Удалить контейнер Amnezia"
    echo -e "  ${W}0)${N} ← Назад"
    read_choice j "${C}  Выбор [0-2]: ${N}" 0 2 0
    case "$j" in
      1) read_confirm "${R}  Сервер Тулзы будет снят (бэкап сохранится). Продолжить? (введи yes): ${N}" && amnezia_revert ;;
      2) read_confirm "${R}  Контейнер будет удалён навсегда. Продолжить? (введи yes): ${N}" && amnezia_remove ;;
    esac
    return 0
  fi
  [[ -n "$c" ]] || { info "Контейнер Amnezia (amnezia-awg2 / amnezia-awg) не найден"; return 0; }
  j=$(amnezia_scan_json) || return 1
  py amnezia-show <<< "$j"
  read_confirm "${Y}  Перенести? Контейнер будет остановлен (введи yes): ${N}" || return 0
  amnezia_migrate
}
