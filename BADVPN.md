# BadVPN: патчи поверх mihomo

Эта ветка (`bpn/<тег mihomo>`) — ядро mihomo для Android-клиента BadVPN. Это тег upstream [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) плюс небольшой набор патчей ниже. Больше ничего не меняется.

*English summary: MetaCubeX/mihomo tag + a small patch set for REALITY compatibility with current Xray-core (client version 26.3.27, empty fingerprint → chrome, optional `reality-opts.client-version`; X25519MLKEM768 is stripped unless `reality-opts.support-x25519mlkem768: true`, as upstream) and metacubex/utls `v1.9.0-mod-meta` (Firefox 148 / Safari 26.3). Branch `bpn/v1.19.31-xhttp-par` adds P5: XHTTP packet-up sends up to 8 upload requests in parallel (Xray-style pipelining) instead of one at a time. Not affiliated with MetaCubeX; please do not report issues from this build upstream.*

- Upstream: `MetaCubeX/mihomo`, тег **v1.19.32** (`88dcbf7f`). В нём новый TUN-стек `mips` (стек самого mihomo, теперь умолчание upstream) и `tun.congestion-controller` (cubic / reno / bbr / bbr3, только для `mips`).
- Ветка: `bpn/v1.19.32` = `bpn/v1.19.31` (`9b11ffbd`, P1–P5), перенесённая `git rebase --onto v1.19.32 v1.19.31` 02.10.2026. Коммиты патчей: `v1.19.32..bpn/v1.19.32`. Хеши в таблице ниже — исходные, с `bpn/v1.19.31`.
- При переносе: upstream поднял utls до v1.8.8 (Firefox 120 / Safari 16.0, как раньше), поэтому P2 остаётся — голова `v1.9.0-mod-meta` теперь `78c9290b` (`v0.0.0-20260930132604-78c9290bf587`, сверху та же правка HWCap, что в v1.8.8).
- Старые ветки `bpn/v1.19.31` и `bpn/v1.19.31-xhttp-par` не меняются.
- Список патчей совпадает с реестром приложения `docs/core-patches.md` (AGENTS.md §11). ID те же. При изменении правятся оба файла.

## Патчи

| # | Что меняет | Зачем | Файлы | Источник / автор / лицензия | С версии mihomo | Проверка | Когда убрать |
|---|---|---|---|---|---|---|---|
| **P1** | REALITY-клиент шлёт в session ID версию **26.3.27** вместо 1.8.2. В исходном коммите P1 ещё переставал вырезать X25519MLKEM768 (`support-x25519mlkem768` игнорировался) — **это отменено патчем P4**, вырезание снова как в upstream. Пустой `client-fingerprint` у REALITY → `chrome` (раньше была ошибка). Заодно в серверной части (listener REALITY) `max-time-difference` считается в миллисекундах, а не в микросекундах; приложение listener не использует | Совместимость с Xray ≥ 26.7.11 (умолчание `minClientVer` 26.3.27) и ≥ 26.9.8 (обязателен X25519MLKEM768 раньше X25519, [XTLS/REALITY 8cdf7bf](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8)). Upstream отказался: [#2967](https://github.com/MetaCubeX/mihomo/issues/2967), [#3132](https://github.com/MetaCubeX/mihomo/issues/3132), [#3193](https://github.com/MetaCubeX/mihomo/issues/3193), [PR #3070](https://github.com/MetaCubeX/mihomo/pull/3070) | `component/tls/reality.go`, `adapter/outbound/reality.go`, `transport/vmess/tls.go`, `listener/reality/reality.go` + тесты | cherry-pick `84cc2c17` ← [legiz-ru/Prizrak-Core `2197a3c`](https://github.com/legiz-ru/Prizrak-Core/commit/2197a3cac1e960987e3844a638a281509bb265ae), автор Jolymmiles (авторство в git сохранено), GPL-3.0 | v1.19.31 | `component/tls/reality_test.go`, `transport/vmess/tls_test.go`, `listener/reality/reality_test.go`; interop с настоящим Xray: `TestVLESSRealityXrayInterop`, `TestBPNRealityXrayMatrix` (см. ниже) | Когда upstream mihomo сам начнёт слать актуальную версию. Или когда у BadVPN не останется REALITY-нод |
| **P2** | `github.com/metacubex/utls` v1.8.7 → голова ветки `v1.9.0-mod-meta` (`v0.0.0-20260924074610-04010625d68b`). Отпечатки: `firefox` Firefox 120 → **148**, `safari` Safari 16.0 → **26.3**, оба с X25519MLKEM768. `chrome` (133), `edge` (85), `ios` (14), `android` (OkHttp 11) не менялись. Кода mihomo правка не требует | Свежие отпечатки, те же, что у Xray ≥ 26.3.27. Без них `firefox` на Xray ≥ 26.9.8 не проходит даже с `support-x25519mlkem768: true` (в Firefox 120 нет ML-KEM). У BadVPN tcp+REALITY-хосты с `firefox`. Upstream ждёт релиза uTLS 1.9.0 ([#3193](https://github.com/MetaCubeX/mihomo/issues/3193)) | `go.mod`, `go.sum` | коммит `28e9ea26` (свой). Код utls: [metacubex/utls@v1.9.0-mod-meta](https://github.com/metacubex/utls/tree/v1.9.0-mod-meta) (wwqgtxx и др.), BSD-3-Clause | v1.19.31 | `TestBPNFingerprintVersions` (firefox = 148, safari = 26.3), `TestBPNRealityMLKEMKeyShare`, interop-матрица | Когда upstream mihomo поднимет utls до версии с Firefox 148 / Safari 26.3 |
| **P3** | Необязательное поле `reality-opts.client-version: "x.y.z"` для каждого прокси. Версия по умолчанию задана в одном месте: `tlsC.DefaultRealityClientVersion` = 26.3.27. Значение `0.0.0` означает умолчание | Если на ноде задан `minClientVer` выше 26.3.27, версию можно поднять без пересборки ядра (через шаблон подписки) | `component/tls/reality.go`, `adapter/outbound/reality.go` + `*_bpn_test.go` | коммит `48d461ce` (свой, GPL-3.0 как mihomo). Идея — закрытый upstream [PR #3069](https://github.com/MetaCubeX/mihomo/pull/3069) | v1.19.31 | `TestBPNRealityDefaultClientVersion`, `TestBPNRealityClientVersionOverride`, `TestBPNParseRealityClientVersion`, `TestBPNRealityOptionsClientVersion` | Вместе с P1 |
| **P4** | X25519MLKEM768 снова вырезается из ClientHello (supported groups и key share), если в `reality-opts` не задано `support-x25519mlkem768: true`. Это семантика upstream mihomo; P1 её убирал. Поле `RealityConfig.SupportX25519MLKEM768` возвращено | 28.09.2026: сборка приложения с P1+P2 без P4 (ML-KEM в ClientHello chrome/firefox/safari, 1529–1881 байт вместо 307–659) не подключалась ни к одной REALITY-ноде (Xray 26.3.27, tcp, без flow, реальные target без X25519MLKEM768 — nginx на OpenSSL 3.0 / внешний сайт). Та же сборка с вырезанием ML-KEM — работает. На локальном стенде поломка **не воспроизводится** (см. «Проверка»): старый код проходит и с target без ML-KEM (Go и `openssl s_server`), и при дроблении ClientHello на TCP-сегменты; логика ключей клиента совпадает с Xray-клиентом. Причина, вероятно, на пути до ноды, а не в ядре. Цена: Xray ≥ 26.9.8 без ML-KEM не пускает — для таких нод в подписке нужен `support-x25519mlkem768: true` | `component/tls/reality.go`, `adapter/outbound/reality.go`; тесты `component/tls/reality_bpn_test.go`, `component/tls/reality_test.go`, `adapter/outbound/reality_bpn_test.go`, `listener/inbound/bpn_reality_xray_matrix_test.go`, `listener/inbound/vless_xray_reality_interop_test.go` | коммит `fix(reality): strip X25519MLKEM768 unless support-x25519mlkem768 (P4)` (свой, GPL-3.0 как mihomo); код — возврат upstream | v1.19.31 | `TestBPNRealityMLKEMKeyShare` (по умолчанию ML-KEM нет, с опцией — есть и стоит до X25519), `TestRealityChromeClientHelloPreservesFingerprint` (с опцией отпечаток не меняется), `TestBPNRealityOptionsSupportX25519MLKEM768`, interop-матрица; проверка на телефоне по всем типам нод | Вместе с P1 (без P1 это просто код upstream). Умолчание можно перевернуть, когда причина полевой поломки будет найдена и устранена, а ноды перейдут на Xray ≥ 26.9.8 |
| **P5** | XHTTP `packet-up`: запросы отправки (POST или `uplink-http-method: GET` с данными в заголовках `X-Payload-N`) идут параллельно, до **8** одновременно на сессию (`xhttp.PacketUpMaxInFlight`; предел в коде — 20), а не строго по одному с ожиданием ответа. `seq` — в порядке отправки; между началами запросов — не меньше `sc-min-posts-interval-ms`; `Write` блокируется, пока 8 запросов в пути (в памяти не больше 8 запросов + один буфер до `sc-max-each-post-bytes`); ошибка любого запроса отменяет остальные и рвёт сессию, как раньше. `stream-up` / `stream-one` не менялись. Для `alpn: [http/1.1]` у транспорта `MaxIdleConnsPerHost` = 8 (каждый запрос в пути — отдельное соединение). Настройки в конфиге нет: у Xray-клиента аналога нет (он число запросов вообще не ограничивает), поэтому константа | Линии через CDN, где не проходит POST (GET + заголовки): один запрос через CDN ~125–175 мс, отправка упиралась в размер запроса / RTT — 0,9–1,5 Мбит/с при 64 КБ. Xray шлёт запросы конвейером (пауза `scMinPostsIntervalMs` между началами, без ожидания ответов), сервер собирает по `seq` и держит до `scMaxBufferedPosts` (30). Почему 8: при 30 мс между запросами конвейер полон до RTT 240 мс; потолок 8 × 64 КБ / RTT (≈ 28 Мбит/с при 150 мс) выше потолка самого интервала (64 КБ / 30 мс ≈ 17 Мбит/с); 8 далеко от 30 даже при интервале 0 | `transport/xhttp/client.go`; тесты `transport/xhttp/packet_up_bpn_test.go`, `listener/inbound/bpn_xhttp_xray_interop_test.go` | коммит `69e5e055` (`feat(xhttp): send packet-up uploads in parallel, up to 8 in flight (P5)`) (свой, GPL-3.0 как mihomo); поведение — как у Xray `transport/internet/splithttp/dialer.go` | v1.19.31 | `TestBPNPacketUp*` (фейковый сервер с задержкой ответов; h2 и h1; POST и GET): (a) в пути ровно N и не больше, N = 1 — старое поведение; (b) `seq` без пропусков и повторов, поток собирается при ответах не по порядку (sha256); (c) ошибка → остальные запросы отменены, `Write` возвращает ошибку; (d) интервал между началами ≥ `sc-min-posts-interval-ms`; (e) после `Close` нет горутин `PacketUpWriter`, в том числе если запросы зависли и `Write` заблокирован; эхо через весь клиент и сервер mihomo. Interop с Xray 26.3.27 / 26.7.28 / 26.9.9: `TestBPNXHTTPPacketUpXrayInterop` (см. «Проверка»). На реальных линиях через CDN — ожидает (VPN PANEL) | Когда upstream mihomo сам станет слать запросы packet-up конвейером / параллельно, как Xray |

Только тесты, поведение не меняют: `ad4c3f42` — `listener/inbound/bpn_reality_xray_matrix_test.go`; `672fea5d` (ветка `bpn/v1.19.31-xhttp-par`) — `listener/inbound/bpn_xhttp_xray_interop_test.go`.

### Важно для потребителя: версия utls (P2)

Псевдоверсия `v0.0.0-2026…` по semver **меньше** `v1.8.7`. Если в главном модуле сборки (у приложения это `core/src/main/golang` и `core/src/foss/golang`) остаётся `github.com/metacubex/utls v1.8.7`, Go MVS молча выберет v1.8.7, и P2 не применится. Главный модуль должен закрепить версию:

```
replace github.com/metacubex/utls => github.com/metacubex/utls v0.0.0-20260930132604-78c9290bf587
```

`replace` в `go.mod` самого mihomo на главный модуль не действует. Проверка: `go list -m github.com/metacubex/utls` в модуле приложения должен показать псевдоверсию.

## Проверка

```sh
go build ./...
go test ./component/tls/... ./adapter/outbound/... ./transport/... ./listener/reality/...
go test ./...   # listener/inbound идёт ~2-3 мин и качает v2ray-core для своих interop-тестов
```

Interop с настоящим Xray, без интернета и без реальных серверов. Xray REALITY-сервер поднимается на 127.0.0.1, target — локальный TLS-сервер: Go с X25519MLKEM768 (`target-mlkem`), Go только с X25519 (`target-x25519`), Go с X25519 + P-256 (`target-x25519-p256`) и, если задан `OPENSSL_BINARY`, `openssl s_server` с группами OpenSSL 3.0 по умолчанию, без ML-KEM (`target-openssl-no-mlkem`):

```sh
# бинарь Xray: https://github.com/XTLS/Xray-core/releases, sha256 сверять с .dgst
XRAY_BINARY=/path/to/xray OPENSSL_BINARY=/path/to/openssl go test ./listener/inbound -run 'BPNRealityXrayMatrix|VLESSRealityXrayInterop' -v -count=1
```

На Windows после полного `go test ./listener/inbound` бывают ложные падения матрицы («Only one usage of each socket address», исчерпаны локальные порты, тысячи TIME_WAIT) — перезапустить позже.

Результат P4 на `bpn/v1.19.31` (28.09.2026, Windows amd64, VLESS tcp + REALITY без flow, без `minClientVer`; OpenSSL 3.5.6 с `-groups X25519:P-256:X448:P-521:P-384`). Одинаков для всех четырёх target:

| Клиент | Xray 26.3.27 | Xray 26.7.28 | Xray 26.9.9 |
|---|---|---|---|
| P4 по умолчанию (ML-KEM вырезан): chrome / firefox / safari / пустой | ok | ok | **fail** (Xray ≥ 26.9.8 требует ML-KEM; сервер отдаёт клиента target → «x509: certificate signed by unknown authority») |
| P4 + `support-x25519mlkem768: true`: chrome / firefox / safari / пустой | ok | ok | ok, в том числе с target без ML-KEM: сервер берёт группу, которую выбрал target (X25519) |
| edge (Edge 85, без ML-KEM) | ok | ok | fail (ожидаемо) |
| до P4 (`10e9fdc6`, ML-KEM всегда в ClientHello): chrome / firefox / safari / пустой | ok | ok | ok |

Итог: на стенде `10e9fdc6` против target без ML-KEM **не падает** — полевую поломку 28.09 стенд не воспроизводит. Проверено отдельно: target реально выбирает X25519; дробление ClientHello на сегменты по 1400 и 536 байт с паузой 50 мс тоже не ломает. Размеры ClientHello (в логе `TestBPNRealityMLKEMKeyShare`): chrome 526 → 1748 байт с ML-KEM, firefox 659 → 1881, safari 307 → 1529; с ML-KEM ClientHello не помещается в один TCP-сегмент.

Upstream v1.19.31 (utls v1.8.7), замер до P4 — только target с ML-KEM:

| Клиент | Xray 26.3.27 | Xray 26.7.28 | Xray 26.9.9 |
|---|---|---|---|
| upstream v1.19.31: chrome / firefox / safari | ok / ok / ok | fail / fail / fail | fail / fail / fail |
| upstream v1.19.31: chrome + `support-x25519mlkem768: true` | ok | fail | ok |
| upstream v1.19.31: firefox + `support-x25519mlkem768: true` | ok | fail | fail |
| upstream v1.19.31: пустой fingerprint | fail («please set a client-fingerprint») | fail | fail |
| upstream v1.19.31: edge | ok | fail | fail |

### P5: XHTTP packet-up, параллельная отправка

```sh
go test ./transport/xhttp/ -run BPNPacketUp -v -count=1     # фейковый сервер с задержкой ответов, ~20 с
XRAY_BINARY=/path/to/xray go test ./listener/inbound -run BPNXHTTPPacketUpXrayInterop -v -count=1   # ~1,5 мин
```

`TestBPNXHTTPPacketUpXrayInterop`: локальный Xray (VLESS + XHTTP `packet-up`, TLS, `alpn` h2 и http/1.1), отправка POST и `GET` с данными в `X-Payload-N` (`uplink-chunk-size: 8192-12288`, на сервере `serverMaxHeaderBytes: 131072` — у Xray по умолчанию 8192, 64 КБ данных в заголовках не пролезут). В подписке как у линий через CDN: `sc-max-each-post-bytes: 32768-65536`, `sc-min-posts-interval-ms: 30`. Без задержки — 16 МиБ туда и 16 МиБ обратно с проверкой sha256; затем через прокси с задержкой 75 мс в каждую сторону (RTT 150 мс, без ограничения полосы) — отправка 2 МиБ при N = 1 (как upstream) и N = 8, sha256 в обе стороны.

Результат на `bpn/v1.19.31-xhttp-par` (29.09.2026, Windows amd64), отправка при RTT 150 мс, Мбит/с, N = 1 → N = 8:

| Отправка | Xray 26.3.27 | Xray 26.7.28 | Xray 26.9.9 |
|---|---|---|---|
| POST, h2 | 2,3 → 12,3 | 2,3 → 11,8 | 2,1–3,2 → 9,1–10,6 |
| GET + заголовки, h2 | 1,8 → 12,9 | 2,7 → 12,8 | 2,0–3,0 → 7,4–9,9 |
| POST, h1 | 1,8 → 13,8 | 2,9 → 12,0 | 3,0 → 11,5–12,5 |
| GET + заголовки, h1 | 2,4 → 11,5 | 2,2 → 8,9 | 2,6–3,0 → 5,4–11,3 |

- Все 16 МиБ-прогоны и все sha256 — ok на всех трёх версиях Xray. Приём (download) от N не зависит (100–160 Мбит/с через прокси).
- С N = 8 отправка упирается уже не в RTT, а в `sc-min-posts-interval-ms`: не больше одного запроса за 30 мс, то есть ~48 КБ (среднее 32–64 КБ) / 30 мс ≈ 13 Мбит/с; при RTT 150 мс в пути 5–6 запросов, до 8 не доходит. То же ограничение у Xray-клиента. Больше — только уменьшив интервал в подписке (потолок тогда 8 × размер запроса / RTT).
- h1: каждый запрос в пути — своё TLS-соединение (2–3 RTT на установку), поэтому на коротком замере разброс больше.
- Фейковый сервер (`TestBPNPacketUpThroughput`, ответ через 150 мс, запросы по 64 КБ, интервал 30 мс): 3,4 → 13,1 Мбит/с.

## Перенос на новый тег mihomo

Каждому тегу — своя ветка `bpn/<тег>`. Старые ветки не переписываем и не форсим: приложение ссылается на конкретный коммит.

```sh
git fetch upstream --tags
git fetch origin
NEW=v1.19.32                                    # новый тег upstream
git switch -c bpn/$NEW origin/bpn/v1.19.31       # копия текущего набора
git rebase --onto $NEW v1.19.31                  # переносит коммиты, авторство сохраняется
# конфликт в go.mod/go.sum (P2): взять версию upstream, затем
#   go get github.com/metacubex/utls@<голова v1.9.0-mod-meta>   # git ls-remote https://github.com/metacubex/utls refs/heads/v1.9.0-mod-meta
#   go mod tidy && git add go.mod go.sum && git rebase --continue
go build ./... && go test ./component/tls/... ./adapter/outbound/... ./transport/... ./listener/reality/...
XRAY_BINARY=... go test ./listener/inbound -run 'BPNRealityXrayMatrix|VLESSRealityXrayInterop' -v -count=1
git push origin bpn/$NEW
```

По каждому патчу решить, нужен ли он ещё: upstream мог исправить сам (см. «Когда убрать»). Обновить таблицу здесь и `docs/core-patches.md` в приложении: заменить хеши, тег и «С версии». Снятый патч в приложении переносится в раздел «Сняты» с причиной.

## Как ядро попадает в приложение BadVPN

Submodule `core/src/foss/golang/clash` в [Rerowros/bpnclash](https://github.com/Rerowros/bpnclash):

1. В `.gitmodules` у `clash-foss`: `url = https://github.com/Rerowros/mihomo`, `branch = bpn/v1.19.31`. Затем `git submodule sync`.
2. `cd core/src/foss/golang/clash && git fetch origin bpn/v1.19.31 && git checkout <коммит>`. Коммит на ветке `bpn/<тег>`, в приложении фиксируется хеш.
3. В `core/src/main/golang/go.mod` и `core/src/foss/golang/go.mod` добавить `replace` для utls (см. выше), выполнить `go mod tidy` в обоих, проверить `go list -m github.com/metacubex/utls`.
4. Очистить `core/build`: golang-таск не видит изменений submodule, иначе останется старая `libclash.so`. Собрать `assembleAlphaDebug` и проверить на телефоне все типы нод.
5. Перенести P1–P4 (и P5, если принят) в `docs/core-patches.md` в «Действующие» с хешами этой ветки.

## Лицензии и атрибуция

- mihomo — GPL-3.0 (`LICENSE` в корне; код и теги — ветки Alpha/Meta upstream). Форк публичный, исходники всех патчей открыты, что покрывает требование GPL для распространяемой `libclash.so`.
- P1 взят из [legiz-ru/Prizrak-Core](https://github.com/legiz-ru/Prizrak-Core) (GPL-3.0, форк mihomo). Автор — Jolymmiles (`jesus <valmak29@gmail.com>`), сохранён как author коммита, в сообщении есть `(cherry picked from commit 2197a3c…)`.
- utls — BSD-3-Clause (The Go Authors, refraction-networking, metacubex). Лицензия идёт с модулем.
- Этот форк не связан с MetaCubeX и XTLS. Проблемы этой сборки в upstream не сообщаем.
