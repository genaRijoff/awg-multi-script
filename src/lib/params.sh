# Параметры обфускации AmneziaWG.
#
# Версия протокола — на весь сервер: параметры 3.x уровня устройства
# (WGDEVICE_A_* в модуле), клиент 2.0 к серверу 3.1 не подключится.
# Профиль задаёт ширину диапазонов:
#   lite («AmneziaVPN») — вокруг значений официального клиента: Jc=4,
#        Jmin=10, Jmax=50, S1=86, S2=48, S3=16, S4=12;
#   pro («Мощный») — полные рекомендованные диапазоны;
#   standard — устаревший, распознаётся у старых серверов.

# S1-S4 >= 12 при HeaderProtectionKey — требование ядра (netlink.c): первые
# 12 байт паддинга уходят nonce'ом защиты заголовков. Меньше — setconf
# отвечает «Invalid argument».
AWG_HP_MIN_S=12
# Базовые длины сообщений WireGuard: 148 (initiation), 92 (response),
# 64 (cookie). S прибавляется к ним, и два типа сообщений становятся одной
# длины при разнице S ровно 56, 84 или 28 — такие совпадения разводим.
AWG_S_DELTAS=(56 84 28)
AWG_S_GAP=10
AWG_S4_MAX=32     # потолок amneziawg-tools (config.c)
AWG_JC_MAX=128    # модуль больше не примет
# Внешний пакет = MTU + 16 (заголовок) + 16 (Poly1305) + S4 + паддинг 3.x
# + 28 (IPv4+UDP). 24 байта запаса — под хвост RandomTrailers и туннель по пути.
AWG_MTU_OVERHEAD=60
AWG_MTU_SAFETY=24

_rand_s() {  # профиль S1|S2|S3|S4
  case "$1:$2" in
    lite:S1) rand_range 80 92 ;;     lite:S2) rand_range 42 54 ;;
    lite:S3) rand_range 14 20 ;;     lite:S4) rand_range 12 18 ;;
    standard:S1|standard:S2) rand_range 30 80 ;;
    standard:S3) rand_range 15 32 ;; standard:S4) rand_range 10 20 ;;
    *:S1|*:S2) rand_range 15 150 ;;
    *:S3) rand_range 8 64 ;;         *:S4) rand_range 6 31 ;;
  esac
}

_too_close() { local d=$(( $1 - $2 )); (( (d < 0 ? -d : d) < AWG_S_GAP )); }

_s_collide() {  # есть ли совпадение длин при текущих S1-S3
  _too_close $(( S1 + AWG_S_DELTAS[0] )) "$S2" ||
  _too_close $(( S1 + AWG_S_DELTAS[1] )) "$S3" ||
  _too_close $(( S2 + AWG_S_DELTAS[2] )) "$S3"
}

_s_raise_min() {  # только для 3.x: S1-S4 не ниже AWG_HP_MIN_S
  local n
  for n in S1 S2 S3 S4; do
    (( ${!n} >= AWG_HP_MIN_S )) || printf -v "$n" '%s' "$(rand_range "$AWG_HP_MIN_S" $((AWG_HP_MIN_S + 12)))"
  done
}

# Пара «lo-hi» в диапазоне [min, max]: нижний конец в первой трети, верхний
# в последней, ширина не меньше 1000.
_h_pair() {
  local min="$1" max="$2" span lo hi
  span=$(( max - min ))
  lo=$(rand_range "$min" $(( min + span / 3 )))
  hi=$(rand_range $(( min + 2 * span / 3 )) "$max")
  (( hi - lo < 1000 )) && hi=$(( lo + 1000 ))
  echo "${lo}-${hi}"
}

# Параметры 3.x. Модуль значения не проверяет, поэтому диапазоны строятся
# вокруг протокольных констант WireGuard (REKEY_AFTER_TIME 120, REJECT_AFTER_TIME
# 180, KEEPALIVE_TIMEOUT 10, REKEY_TIMEOUT 5). Инвариант: RejectAfterTime
# строго больше RekeyAfterTime, иначе сессия умрёт раньше, чем переустановится.
_gen_awg3_lines() {
  local proto="$1" hp cpa_lo cpa_hi rat_lo rat_hi rjt_lo rjt_hi rkt_lo
  hp=$(awg genkey) || return 1
  cpa_lo=$(rand_range 8 24); cpa_hi=$(rand_range 48 96)
  rat_lo=$(rand_range 110 125); rat_hi=$(rand_range 140 160)
  rjt_lo=$(rand_range 175 190); rjt_hi=$(rand_range 200 215)
  (( rjt_lo <= rat_hi )) && rjt_lo=$(( rat_hi + 15 ))
  (( rjt_hi <= rjt_lo )) && rjt_hi=$(( rjt_lo + 20 ))
  # Повтор рукопожатия не константой 5 с (стабильная временная подпись), но и
  # не быстрее 5 с; при MaxHandshakeAttempts 16-20 отказ наступит за ~3 мин.
  rkt_lo=$(rand_range 5 6)
  printf 'HeaderProtectionKey = %s\n' "$hp"
  printf 'ContentPaddingAddition = %s-%s\n' "$cpa_lo" "$cpa_hi"
  printf 'RekeyAfterTime = %s-%s\n' "$rat_lo" "$rat_hi"
  printf 'RekeyTimeout = %s-%s\n' "$rkt_lo" $(( rkt_lo + $(rand_range 2 3) ))
  printf 'RejectAfterTime = %s-%s\n' "$rjt_lo" "$rjt_hi"
  printf 'KeepaliveTimeout = %s-%s\n' "$(rand_range 9 14)" "$(rand_range 20 30)"
  printf 'MaxHandshakeAttempts = %s\n' "$(rand_range 16 20)"
  # RandomTrailers обязан совпадать на обоих концах: с ним приёмник принимает
  # рукопожатие длиннее ожидаемого, без него — отбросит. DisableCookies
  # локален: сервер не отвечает cookie-пакетом под нагрузкой.
  if [[ "$proto" == 3.1 ]]; then
    printf 'RandomTrailers = on\nDisableCookies = on\n'
  fi
}

# gen_awg_params ПРОФИЛЬ ВЕРСИЯ → AWG_PARAMS (строки «Ключ = значение»).
# Может снизить глобальный MTU, если внешний пакет не влезает в 1500.
AWG_PARAMS="" AWG3_CPA_MAX=0
gen_awg_params() {
  local profile="$1" proto="$2" Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 tries=0 p3=""
  case "$profile" in
    lite)     Jc=$(rand_range 3 5);  Jmin=$(rand_range 8 12); Jmax=$(rand_range 70 90) ;;
    standard) Jc=$(rand_range 5 8);  Jmin=$(rand_range 8 16); Jmax=$(rand_range 70 100) ;;
    *)        Jc=$(rand_range 4 12); Jmin=$(rand_range 8 24); Jmax=$(rand_range 80 120) ;;
  esac
  S1=$(_rand_s "$profile" S1); S2=$(_rand_s "$profile" S2)
  S3=$(_rand_s "$profile" S3); S4=$(_rand_s "$profile" S4)
  [[ "$proto" == 3* ]] && _s_raise_min

  # Разведение длин: сперва перебор в рамках профиля, затем сдвиг вверх
  while _s_collide && (( tries++ < 20 )); do
    S2=$(_rand_s "$profile" S2); S3=$(_rand_s "$profile" S3)
    [[ "$proto" == 3* ]] && _s_raise_min
  done
  tries=0
  while _too_close $(( S1 + AWG_S_DELTAS[0] )) "$S2" && (( tries++ < 30 )); do S2=$(( S2 + AWG_S_GAP )); done
  tries=0
  while { _too_close $(( S1 + AWG_S_DELTAS[1] )) "$S3" || _too_close $(( S2 + AWG_S_DELTAS[2] )) "$S3"; } \
        && (( tries++ < 30 )); do S3=$(( S3 + AWG_S_GAP )); done
  (( S4 > AWG_S4_MAX )) && S4=$AWG_S4_MAX
  (( Jc > AWG_JC_MAX )) && Jc=$AWG_JC_MAX
  (( Jmin < Jmax )) || Jmax=$(( Jmin + 50 ))

  # H1-H4: на 3.x заголовок целиком под шифром (HeaderProtectionKey), и подмена
  # типа пакета ничего не скрывает — официальный клиент тоже оставляет 1-4.
  # На 2.0 заголовок открыт: 1-4 — прямой признак WireGuard, нужны диапазоны,
  # не пересекающиеся и не выше 2^31-1 (старый Windows-клиент выше не принимал).
  if [[ "$proto" == 3* ]]; then
    H1=1; H2=2; H3=3; H4=4
    p3=$(_gen_awg3_lines "$proto") || { err "awg genkey не сработал"; return 1; }
    AWG3_CPA_MAX=$(sed -n 's/^ContentPaddingAddition = [0-9]*-//p' <<< "$p3")
  else
    AWG3_CPA_MAX=0
    H1=$(_h_pair 5 536870911)
    H2=$(_h_pair 536870912 1073741823)
    H3=$(_h_pair 1073741824 1610612735)
    H4=$(_h_pair 1610612736 2147483647)
  fi

  AWG_PARAMS=$(printf 'Jc = %s\nJmin = %s\nJmax = %s\nS1 = %s\nS2 = %s\nS3 = %s\nS4 = %s\nH1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n%s' \
    "$Jc" "$Jmin" "$Jmax" "$S1" "$S2" "$S3" "$S4" "$H1" "$H2" "$H3" "$H4" "$p3")
  AWG_PARAMS="${AWG_PARAMS%$'\n'}"
  _check_mtu_headroom "$S4"
}

# Случайные значения для формы параметров (бот, панель, «кубик»): ничего не
# пишет и не применяет — дальше обычная проверка (params check) и запись.
# Диапазоны — генератора (lite — как AmneziaVPN, pro — от допустимого минимума
# до разумного верха), версия — текущая сервера. MTU сервера не трогается:
# набор, которому не хватает запаса до него, перебирается заново.
PARAMS_GEN=""
params_gen() {  # ПРОФИЛЬ → PARAMS_GEN («ключ<TAB>значение», без HeaderProtectionKey)
  local profile="$1" proto mtu s4 tries=0
  proto=$(server_proto); mtu=$(conf_iface_get MTU)
  while :; do
    # Пустой MTU — генератор не спрашивает про его снижение
    MTU="" gen_awg_params "$profile" "$proto" || return 1
    [[ "$mtu" =~ ^[0-9]+$ ]] || break
    s4=$(sed -n 's/^S4 = //p' <<< "$AWG_PARAMS")
    (( mtu + AWG_MTU_OVERHEAD + ${s4:-0} + AWG3_CPA_MAX <= 1500 - AWG_MTU_SAFETY )) && break
    (( ++tries < 20 )) || break
  done
  PARAMS_GEN=$(sed -n 's/^\([A-Za-z0-9]*\) = \(.*\)$/\1\t\2/p' <<< "$AWG_PARAMS" | grep -v '^HeaderProtectionKey' || true)
}

# MTU без запаса до пути в 1500 даёт не обрыв, а загадочную просадку скорости:
# крупные пакеты режутся, а PMTU discovery по UDP работает не везде.
_check_mtu_headroom() {
  local s4="$1" outer limit safe
  [[ "${MTU:-}" =~ ^[0-9]+$ ]] || return 0
  outer=$(( MTU + AWG_MTU_OVERHEAD + s4 + AWG3_CPA_MAX ))
  limit=$(( 1500 - AWG_MTU_SAFETY ))
  (( outer <= limit )) && return 0
  safe=$(( (limit - AWG_MTU_OVERHEAD - s4 - AWG3_CPA_MAX) / 10 * 10 ))
  (( safe > 1420 )) && safe=1420
  (( safe < 1280 )) && safe=1280
  warn "MTU $MTU не оставляет запаса: внешний пакет до $outer Б при пути 1500"
  if (( AUTO_MODE )) || ask_yes "  Снизить MTU до $safe? [Y/n]: " y; then
    MTU=$safe
    ok "MTU: $MTU"
  fi
}

# PersistentKeepalive клиента. На 3.x — диапазон вокруг 25 с (ядро выбирает
# значение на каждой отправке, константа — стабильная временная подпись),
# в официальных границах 22-30: выше 30 с роутеры забывают UDP-сессию.
keepalive_for() {
  if [[ "$1" == 3* ]]; then echo "$(rand_range 22 25)-$(rand_range 27 30)"
  else echo 25; fi
}

# Нарушения S >= 12 в конфиге с HeaderProtectionKey (для диагностики).
conf_hp_min_s_violations() {
  local k v bad=""
  grep -q '^HeaderProtectionKey' "$SERVER_CONF" 2>/dev/null || return 0
  for k in S1 S2 S3 S4; do
    v=$(conf_iface_get "$k")
    [[ "$v" =~ ^[0-9]+$ ]] && (( v < AWG_HP_MIN_S )) && bad+=" $k=$v"
  done
  echo "${bad# }"
}
