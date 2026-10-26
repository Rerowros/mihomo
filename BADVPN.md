# BadVPN: патчи поверх mihomo

Эта ветка (`bpn/<тег mihomo>`) — ядро mihomo для Android-клиента BadVPN. Это тег upstream [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) плюс небольшой набор патчей ниже. Больше ничего не меняется.

*English summary: MetaCubeX/mihomo tag + a small patch set for REALITY compatibility with current Xray-core (client version 26.10.21, empty fingerprint → chrome, optional `reality-opts.client-version`; X25519MLKEM768: the first handshake to a server is classic, then the core learns per server and public key whether it needs ML-KEM (Xray >= 26.9.8), `reality-opts.support-x25519mlkem768: true` forces it, `reality-opts.mlkem-client-fingerprint` switches the fingerprint for the ML-KEM handshake) and metacubex/utls `v1.9.0-mod-meta` (Firefox 148 / Safari 26.3). XHTTP packet-up (P5+P8) sends uploads in parallel, frees the write slot at WroteRequest and bounds the unanswered seqs with a 24-slot window. Xdrive (P9) is a byte-compatible port of the Xray-core cloud-storage transport, client and server. P10 adds the server-node pieces: per-user traffic counters with `/traffic/users`, a small idle relay buffer, a lazy BufferedConn reader, a server GC ballast and pre-auth XHTTP session limits. Not affiliated with MetaCubeX; please do not report issues from this build upstream.*

- Upstream: `MetaCubeX/mihomo`, тег **v1.19.32** (`88dcbf7f`). В нём новый TUN-стек `mips` (стек самого mihomo, теперь умолчание upstream) и `tun.congestion-controller` (cubic / reno / bbr / bbr3, только для `mips`).
- Ветка: `bpn/v1.19.32` = `bpn/v1.19.31` (`9b11ffbd`, P1–P5), перенесённая `git rebase --onto v1.19.32 v1.19.31` 02.10.2026. Коммиты патчей: `v1.19.32..bpn/v1.19.32`. Хеши в таблице ниже — исходные, с `bpn/v1.19.31`.
- При переносе: upstream поднял utls до v1.8.8 (Firefox 120 / Safari 16.0, как раньше), поэтому P2 остаётся — голова `v1.9.0-mod-meta` теперь `78c9290b` (`v0.0.0-20260930132604-78c9290bf587`, сверху та же правка HWCap, что в v1.8.8).
- Старые ветки `bpn/v1.19.31` и `bpn/v1.19.31-xhttp-par` не меняются.
- Версии: тег `v1.19.32-bpn.N` = тег upstream + номер нашей сборки, растёт при каждом изменении набора патчей. `v1.19.32-bpn.1` = `9dd9fd41` (P1–P5, приложение 1.1.11), `v1.19.32-bpn.2` = + P6. Теги не переносятся.
- Список патчей совпадает с реестром приложения `docs/core-patches.md` (AGENTS.md §11). ID те же. При изменении правятся оба файла.

## Патчи

| # | Что меняет | Зачем | Файлы | Источник / автор / лицензия | С версии mihomo | Проверка | Когда убрать |
|---|---|---|---|---|---|---|---|
| **P1** | REALITY-клиент шлёт в session ID версию **26.10.21** вместо 1.8.2. В исходном коммите P1 ещё переставал вырезать X25519MLKEM768 (`support-x25519mlkem768` игнорировался) — **это отменено патчем P4**, вырезание снова как в upstream. Пустой `client-fingerprint` у REALITY → `chrome` (раньше была ошибка). Заодно в серверной части (listener REALITY) `max-time-difference` считается в миллисекундах, а не в микросекундах; приложение listener не использует | Совместимость с Xray ≥ 26.7.11 (умолчание `minClientVer` 26.3.27) и ≥ 26.9.8 (обязателен X25519MLKEM768 раньше X25519, [XTLS/REALITY 8cdf7bf](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8)). Upstream отказался: [#2967](https://github.com/MetaCubeX/mihomo/issues/2967), [#3132](https://github.com/MetaCubeX/mihomo/issues/3132), [#3193](https://github.com/MetaCubeX/mihomo/issues/3193), [PR #3070](https://github.com/MetaCubeX/mihomo/pull/3070) | `component/tls/reality.go`, `adapter/outbound/reality.go`, `transport/vmess/tls.go`, `listener/reality/reality.go` + тесты | cherry-pick `84cc2c17` ← [legiz-ru/Prizrak-Core `2197a3c`](https://github.com/legiz-ru/Prizrak-Core/commit/2197a3cac1e960987e3844a638a281509bb265ae), автор Jolymmiles (авторство в git сохранено), GPL-3.0 | v1.19.31 | `component/tls/reality_test.go`, `transport/vmess/tls_test.go`, `listener/reality/reality_test.go`; interop с настоящим Xray: `TestVLESSRealityXrayInterop`, `TestBPNRealityXrayMatrix` (см. ниже) | Когда upstream mihomo сам начнёт слать актуальную версию. Или когда у BadVPN не останется REALITY-нод |
| **P2** | `github.com/metacubex/utls` v1.8.7 → голова ветки `v1.9.0-mod-meta` (`v0.0.0-20260924074610-04010625d68b`). Отпечатки: `firefox` Firefox 120 → **148**, `safari` Safari 16.0 → **26.3**, оба с X25519MLKEM768. `chrome` (133), `edge` (85), `ios` (14), `android` (OkHttp 11) не менялись. Кода mihomo правка не требует | Свежие отпечатки, те же, что у Xray ≥ 26.3.27. Без них `firefox` на Xray ≥ 26.9.8 не проходит даже с `support-x25519mlkem768: true` (в Firefox 120 нет ML-KEM). У BadVPN tcp+REALITY-хосты с `firefox`. Upstream ждёт релиза uTLS 1.9.0 ([#3193](https://github.com/MetaCubeX/mihomo/issues/3193)) | `go.mod`, `go.sum` | коммит `28e9ea26` (свой). Код utls: [metacubex/utls@v1.9.0-mod-meta](https://github.com/metacubex/utls/tree/v1.9.0-mod-meta) (wwqgtxx и др.), BSD-3-Clause | v1.19.31 | `TestBPNFingerprintVersions` (firefox = 148, safari = 26.3), `TestBPNRealityMLKEMKeyShare`, interop-матрица | Когда upstream mihomo поднимет utls до версии с Firefox 148 / Safari 26.3 |
| **P3** | Необязательное поле `reality-opts.client-version: "x.y.z"` для каждого прокси. Версия по умолчанию задана в одном месте: `tlsC.DefaultRealityClientVersion` = 26.10.21. Значение `0.0.0` означает умолчание | Если на ноде задан `minClientVer` выше версии по умолчанию, версию можно поднять без пересборки ядра (через шаблон подписки). С 26.10.21 по умолчанию проходят ноды Xray ≥ 26.9.8 с `minClientVer`; старые серверы `maxClientVer` не задают и версию принимают | `component/tls/reality.go`, `adapter/outbound/reality.go` + `*_bpn_test.go` | коммит `48d461ce` (свой, GPL-3.0 как mihomo). Идея — закрытый upstream [PR #3069](https://github.com/MetaCubeX/mihomo/pull/3069) | v1.19.31 | `TestBPNRealityDefaultClientVersion`, `TestBPNRealityClientVersionOverride`, `TestBPNParseRealityClientVersion`, `TestBPNRealityOptionsClientVersion` | Вместе с P1 |
| **P4** | X25519MLKEM768 снова вырезается из ClientHello (supported groups и key share), если в `reality-opts` не задано `support-x25519mlkem768: true`. Это семантика upstream mihomo; P1 её убирал. Поле `RealityConfig.SupportX25519MLKEM768` возвращено | 28.09.2026: сборка приложения с P1+P2 без P4 (ML-KEM в ClientHello chrome/firefox/safari, 1529–1881 байт вместо 307–659) не подключалась ни к одной REALITY-ноде (Xray 26.3.27, tcp, без flow, реальные target без X25519MLKEM768 — nginx на OpenSSL 3.0 / внешний сайт). Та же сборка с вырезанием ML-KEM — работает. На локальном стенде поломка **не воспроизводится** (см. «Проверка»): старый код проходит и с target без ML-KEM (Go и `openssl s_server`), и при дроблении ClientHello на TCP-сегменты; логика ключей клиента совпадает с Xray-клиентом. Причина, вероятно, на пути до ноды, а не в ядре. Цена: Xray ≥ 26.9.8 без ML-KEM не пускает — для таких нод в подписке нужен `support-x25519mlkem768: true` | `component/tls/reality.go`, `adapter/outbound/reality.go`; тесты `component/tls/reality_bpn_test.go`, `component/tls/reality_test.go`, `adapter/outbound/reality_bpn_test.go`, `listener/inbound/bpn_reality_xray_matrix_test.go`, `listener/inbound/vless_xray_reality_interop_test.go` | коммит `fix(reality): strip X25519MLKEM768 unless support-x25519mlkem768 (P4)` (свой, GPL-3.0 как mihomo); код — возврат upstream | v1.19.31 | `TestBPNRealityMLKEMKeyShare` (по умолчанию ML-KEM нет, с опцией — есть и стоит до X25519), `TestRealityChromeClientHelloPreservesFingerprint` (с опцией отпечаток не меняется), `TestBPNRealityOptionsSupportX25519MLKEM768`, interop-матрица; проверка на телефоне по всем типам нод | Вместе с P1 (без P1 это просто код upstream). Умолчание можно перевернуть, когда причина полевой поломки будет найдена и устранена, а ноды перейдут на Xray ≥ 26.9.8 |
| **P5** | XHTTP `packet-up`: запросы отправки (POST или `uplink-http-method: GET` с данными в заголовках `X-Payload-N`) идут параллельно, до **8** одновременно на сессию (`xhttp.PacketUpMaxInFlight`; предел в коде — 20), а не строго по одному с ожиданием ответа. `seq` — в порядке отправки; между началами запросов — не меньше `sc-min-posts-interval-ms`; `Write` блокируется, пока 8 запросов в пути (в памяти не больше 8 запросов + один буфер до `sc-max-each-post-bytes`); ошибка любого запроса отменяет остальные и рвёт сессию, как раньше. `stream-up` / `stream-one` не менялись. Для `alpn: [http/1.1]` у транспорта `MaxIdleConnsPerHost` = 8 (каждый запрос в пути — отдельное соединение). Настройки в конфиге нет: у Xray-клиента аналога нет (он число запросов вообще не ограничивает), поэтому константа | Линии через CDN, где не проходит POST (GET + заголовки): один запрос через CDN ~125–175 мс, отправка упиралась в размер запроса / RTT — 0,9–1,5 Мбит/с при 64 КБ. Xray шлёт запросы конвейером (пауза `scMinPostsIntervalMs` между началами, без ожидания ответов), сервер собирает по `seq` и держит до `scMaxBufferedPosts` (30). Почему 8: при 30 мс между запросами конвейер полон до RTT 240 мс; потолок 8 × 64 КБ / RTT (≈ 28 Мбит/с при 150 мс) выше потолка самого интервала (64 КБ / 30 мс ≈ 17 Мбит/с); 8 далеко от 30 даже при интервале 0 | `transport/xhttp/client.go`; тесты `transport/xhttp/packet_up_bpn_test.go`, `listener/inbound/bpn_xhttp_xray_interop_test.go` | коммит `69e5e055` (`feat(xhttp): send packet-up uploads in parallel, up to 8 in flight (P5)`) (свой, GPL-3.0 как mihomo); поведение — как у Xray `transport/internet/splithttp/dialer.go` | v1.19.31 | `TestBPNPacketUp*` (фейковый сервер с задержкой ответов; h2 и h1; POST и GET): (a) в пути ровно N и не больше, N = 1 — старое поведение; (b) `seq` без пропусков и повторов, поток собирается при ответах не по порядку (sha256); (c) ошибка → остальные запросы отменены, `Write` возвращает ошибку; (d) интервал между началами ≥ `sc-min-posts-interval-ms`; (e) после `Close` нет горутин `PacketUpWriter`, в том числе если запросы зависли и `Write` заблокирован; эхо через весь клиент и сервер mihomo. Interop с Xray 26.3.27 / 26.7.28 / 26.9.9: `TestBPNXHTTPPacketUpXrayInterop` (см. «Проверка»). На реальных линиях через CDN — ожидает (VPN PANEL) | Когда upstream mihomo сам станет слать запросы packet-up конвейером / параллельно, как Xray |
| **P6** | Адаптивный X25519MLKEM768 для REALITY без `support-x25519mlkem768`. Исход каждого рукопожатия запоминается по адресу сервера и публичному ключу (в памяти процесса): первое — без ML-KEM (как P4), после одного провала — с ML-KEM, после успеха вариант закрепляется, закреплённый меняется снова только после 3 провалов подряд (сервер обновили/откатили). Провалы «устаревшего» варианта, которые были в пути, не считаются. Если память хочет ML-KEM, а у отпечатка его нет (edge, ios, android, chrome120…), рукопожатие идёт с chrome. `support-x25519mlkem768: true` — как раньше: ML-KEM всегда, отпечаток не меняется, память не используется | Цена P4: Xray ≥ 26.9.8 без ML-KEM не пускает, а сервер не сообщает, какой он; Xray 24.x, наоборот, отбрасывает ClientHello с ML-KEM. С P6 ноды на 26.9.8+ работают без правки шаблона подписки, ценой одного неудачного соединения на сервер после старта ядра; поломка 28.09 (ML-KEM на пути) не повторяется — первое рукопожатие классическое | `component/tls/reality.go`, `adapter/outbound/reality.go` (комментарий); тесты `component/tls/reality_mlkem_memo_bpn_test.go`, `listener/inbound/bpn_reality_xray_matrix_test.go` | по мотивам патча ClashFest `core/patches/mihomo/0002-reality-adaptive-mlkem.patch` ([Nemu-x/ClashFest#239](https://github.com/Nemu-x/ClashFest/pull/239), автор Nemu-x, GPL-3.0); без глобальной политики Auto/On/Off и первого варианта «с ML-KEM» — у нас только «Авто», подмена на chrome только для выученного ML-KEM | v1.19.32 | `TestBPNRealityMLKEMMemoLearnsPerServer`, `TestBPNRealityMLKEMForcedSkipsMemo`, `TestBPNRealityMLKEMMemoReachesClientHello` (firefox оставляет свою ML-KEM-долю, edge → chrome); interop-матрица на Xray 24.12.31 / 26.3.27 / 26.7.28 / 26.9.9 (см. «P6: результаты»); проверка на телефоне по всем типам нод | Если upstream mihomo сам начнёт определять ML-KEM по серверу или все ноды перейдут на Xray ≥ 26.9.8 (тогда достаточно `support-x25519mlkem768: true` в шаблоне) |
| **P7** | `reality-opts.mlkem-client-fingerprint`: при рукопожатии, которое несёт X25519MLKEM768 (P6 выучил или задан `support-x25519mlkem768`), использовать указанный отпечаток вместо `client-fingerprint`. При разборе проверяется, что отпечаток реально содержит key share X25519MLKEM768 (edge/ios/android/chrome120 отклоняются). Выбор делается один раз до цикла повторов | Мобильные операторы РФ держат ClientHello с отпечатками Chrome/Safari/iOS к «подозрительным» зарубежным подсетям, а Firefox/Android/OkHttp/Edge пропускают ([XTLS/Xray-core#6293](https://github.com/XTLS/Xray-core/issues/6293)). Из отпечатков с ML-KEM в нашем utls это chrome, firefox, safari; firefox — рабочий для этих сетей. Шаблон подписки может оставить `client-fingerprint: chrome` и добавить `mlkem-client-fingerprint: firefox` | `component/tls/reality.go`, `component/tls/utls.go`, `adapter/outbound/reality.go` + `*_bpn_test.go` | свой, GPL-3.0 как mihomo; идея и данные — по issue Xray #6293 | v1.19.32-bpn.3 | `TestBPNRealityOptionsMLKEMClientFingerprint` (firefox ok, edge отклонён), `TestBPNRealityMLKEMFingerprintSelection`; матрица на Xray 26.10.21 (443 без `minClientVer`, 8443/9443 с 26.9.8; chrome/firefox × ML-KEM × vision) — см. «P7: результаты» | Если ТСПУ перестанет держать Chrome или в utls появятся отпечатки Firefox/Android с ML-KEM, не требующие подмены |
| **P8** | XHTTP `packet-up`: (a) слот записи освобождается по `httptrace.WroteRequest`, а не после ответа, поэтому скорость задаёт интервал, а не RTT; (b) окно seq — 24 кольцевых слота (`packetUpMaxUnacked`), сервер видит не больше 24 неподтверждённых сегментов при буфере 30; (c) первый чанк после простоя отправляется сразу, а не через `sc-min-posts-interval-ms`; (d) у каждого запроса таймаут 120 с, зависший запрос рвёт сессию; (e) сервер отбрасывает повтор seq ниже `nextSeq` (net/http может повторить GET) и держит очередь строго `>= maxPackets`; (f) карта сессий — `RWMutex` с быстрым путём чтения, `uploadQueue.Close` вне блокировки, reaper удаляет только свою сессию; (g) `transport/xhttp/conn.go` — дедлайн закрывает соединение только если операция уже заблокирована (порт из Citrus); (h) серверная ветка packet-up принимает **GET с seq** — раньше такой запрос уходил в ветку download и дедлокился; для GET-uplink в inbound `xhttp-config` обязательно задать `uplink-data-placement: header` и `uplink-data-key` (иначе payload в заголовках не читается, сервер отдаёт 200 с пустым сегментом, а у Xray то же самое: `firstLen = 0`) | Отправка GET+заголовки упиралась в `N/RTT` (8 × 64 КБ / 150 мс ≈ 13 Мбит/с); при интервале 30 мс N вообще перестал влиять; при интервале 0 один слот уже держит окно 24 и даёт ~55 Мбит/с на стенде (4×). Зависший запрос больше не блокирует `Write` навсегда; повторный seq не забивает буфер сервера; простаивающий туннель не рвётся по чужому дедлайну | `transport/xhttp/client.go`, `transport/xhttp/conn.go`, `transport/xhttp/server.go`, `transport/xhttp/upload_queue.go`; тесты `packet_up_bpn_test.go`, `conn_test.go`, `upload_queue_test.go`, `listener/inbound/bpn_xhttp_xray_interop_test.go` | своё, GPL-3.0 как mihomo; (g) — `getmikan/Citrus` `365fac3d` (GPL-3.0), (e) по замечанию Claude Code | v1.19.32-bpn.3 | `go test ./transport/xhttp/`; `XRAY_BINARY=... go test ./listener/inbound -run BPNXHTTPPacketUpXrayInterop`; замеры: интервал 30 — 13,2 Мбит/с при n=1 и n=8; интервал 0 — 54,7 Мбит/с при n=1 | Когда upstream сам перейдёт на отправку без ожидания ответа и добавит те же защиты |
| **P9** | Транспорт **xdrive** (порт Xray-core `transport/internet/xdrive`): поток режется на сегменты в общем каталоге облака, оба конца опрашивают каталог. Storage: `local`, `google-drive` (OAuth refresh token, inline ≤12 КБ / multipart, rate-limit retries), `template` (любой REST, пример — Yandex WebDAV). Клиент — `network: xdrive` + `xdrive-opts`; сервер — inbound `vless` с `xdrive-config`, **без сокета**. Имена объектов и seq совпадают с Xray; с серверной стороны требуется VLESS `decryption`, с клиентской — `encryption` (Xray требует это для xdrive), у Xray-клиента обязателен `mux` | Обмен через облако не требует открытого порта и переживает смену IP; полезно там, где прямое соединение недоступно. Google Drive может быть недоступен из РФ — тогда `template` на Yandex WebDAV | новый пакет `transport/xdrive/` (config, storage, local, drive, template, wal, conn, xdrive, http); `adapter/outbound/vless.go`, `listener/inbound/vless.go`, `listener/config/vless.go`, `listener/sing_vless/server.go`; тесты `transport/xdrive/*_test.go`, `listener/inbound/bpn_xdrive_xray_interop_test.go` | порт `XTLS/Xray-core` `transport/internet/xdrive` (GPL-3.0, авторы Xray); обвязка mihomo — своя | v1.19.32-bpn.3 | `go test ./transport/xdrive/`; `XRAY_BINARY=... go test ./listener/inbound -run BPNXDriveXrayInterop` (mihomo-клиент ↔ Xray 26.10.21, 1 МиБ в обе стороны, ~110 Мбит/с на local); вручную проверено и обратное направление: Xray-клиент (mux) ↔ mihomo-сервер, HTTPS 200 | Если транспорт не нужен или upstream mihomo его добавит |
| **P10** | Серверная часть для слабой ноды и панели: (a) per-user счётчики трафика/соединений в TCP и UDP tracker, `GET /traffic/users?inbound=&user=&reset=true` (сброс периода, аналог Xray `QueryStats`); (b) relay читает в маленький буфер 2 КиБ, пока соединение простаивает, и в полные буферы при передаче; (c) `BufferedConn` создаёт `bufio.Reader` лениво (4 КиБ на соединение только при первом использовании); (d) GC ballast 8 МиБ в серверных сборках (не Android/iOS/CMFA, не при `GOGC`/`GOMEMLIMIT`); (e) XHTTP cap 4096 неавторизованных сессий (503) и 15 с на тело до download. Подробное сравнение с Prizrak-Core, Citrus и Xray — `docs/SERVER.md` | Нода 1–2 vCPU / 2 ГБ: меньше памяти на idle-соединение (по замерам Citrus — до −30 КБ heap и −26% RSS на REALITY), меньше циклов GC, защита от флуда XHTTP-сессий; панель наконец видит трафик по пользователям без пересборки конфига | `tunnel/statistic/users.go`, `tunnel/statistic/tracker.go`, `hub/route/users.go`, `hub/route/server.go`, `common/net/relay_copy.go`, `common/net/sing.go`, `common/net/bufconn.go`, `common/net/bufconn_unsafe.go`, `component/gcballast/`, `main.go`, `transport/xhttp/server.go`; тесты `tunnel/statistic/users_test.go`, `common/net/relay_copy_test.go`, `transport/xhttp/pending_bpn_test.go`, `common/net/*_test.go` | (b)(c)(d) — `getmikan/Citrus` (GPL-3.0): PR #52, #118, `common/net/{relay_copy,bufconn,gcballast}`; (a)(e) — свои, GPL-3.0 как mihomo | v1.19.32-bpn.3 | `go test ./common/net/ ./tunnel/... ./transport/xhttp/ ./hub/route/`; сквозной тест: VLESS+xdrive, `GET /traffic/users` отдаёт `upload/download`, `reset=true` обнуляет, `conns` возвращается в 0; `TestServerPendingSessionCap`; `TestUserManager`, `TestCopyConn`, `TestRelay` | Когда upstream mihomo даст per-user API и малые буферы relay, либо если нода не используется как сервер |
| **P11** | Xray-совместимый gRPC API (`xray-api.listen`): `HandlerService` (`AlterInbound` = AddUser/RemoveUser, `GetInboundUsers`, `GetInboundUsersCount`, `ListInbounds`) и `StatsService` (`GetStats`, `QueryStats`, `GetUsersStats`, `GetStatsOnline`, `GetStatsOnlineIpList`, `GetAllOnlineUsers`, `GetSysStats`), плюс имена `v2ray.core.*`. Пользователи VLESS меняются в живом listener без рестарта (атомарная таблица), REST `GET/POST/PUT/PATCH/DELETE /inbounds/{name}/users`; per-user лимиты `user-limits` + `/limits/users` (соединения, скорость, квота upload+download, expiry). Снятие пользователя закрывает его живые сессии | Панель (Marzban/PasarGuard/Remnawave-совместимые клиенты) может добавлять/удалять пользователей и читать трафик через `xray api`, как у Xray-ноды, без SSH и рестарта. Лимиты закрывают дыру «безлимитный пароль» на слабой ноде | новый пакет `hub/xrayapi/`; `constant/inbound_users.go`, `listener/listener.go`, `listener/inbound/vless.go`, `listener/sing_vless/{service,server}.go`, `tunnel/statistic/{limits,users,manager,tracker}.go`, `tunnel/tunnel.go`, `hub/route/{inbounds,limits}.go`, `config/config.go`, `hub/executor/executor.go`; тесты `hub/xrayapi/*_test.go`, `tunnel/statistic/limits_test.go` | своё, GPL-3.0 как mihomo; формат — Xray-core `app/proxyman/command`, `app/stats/command` (GPL-3.0) | v1.19.32-bpn.4 | `go test ./hub/xrayapi ./tunnel/statistic ./common/net`; `xray api lsi/adu/inbounduser/stats/statsquery/statsonline/rmu` против mihomo (см. «P11: проверка»); REST + квота + удаление живой сессии проверены сквозным VLESS+xdrive | Пока панель не умеет говорить с mihomo напрямую или пока upstream не даст per-user API |
| **P12** | Relay: порт `common/net/relay_batch.go` и `relay_yield.go` из Citrus. При передаче (адаптивный размер буфера уже вырос) отдельная горутина читает/расшифровывает источник, а запись отправляет всё накопленное одним `writev(2)`; пачка до 9 буферов плюс до 8 в очереди (около 0,5 МиБ на направление), при простое источник возвращается в основной цикл. Цикл уступает процессор (`runtime.Gosched`) после 256 КиБ и 1 мс, чтобы интерактивные соединения не ждали за bulk-передачей | Отправка через TLS/Shadowsocks источник отдаёт по записи/чанку; поштучные `write(2)` на нагруженной ноде тратят время на каждый сегмент. Citrus намерил +50% upload; download обычно и так идёт из сокета и батчинг не включает | `common/net/relay_batch.go`, `common/net/relay_yield.go`, `common/net/relay_copy.go`; тесты `common/net/` | `getmikan/Citrus` (GPL-3.0), порт с заменой `clear()` для Go 1.20 | v1.19.32-bpn.4 | `go test ./common/net/`; сквозной обмен VLESS+xdrive (1 МиБ, sha256) | Если upstream mihomo сделает свой батчинг |

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

### P6: результаты

`bpn/v1.19.32` + P6, 07.10.2026, Windows amd64, VLESS tcp + REALITY без flow, все 4 target (OpenSSL 3.5.6). В случаях без `support-x25519mlkem768` память перед каждым случаем очищается, даётся до двух соединений:

| | Xray 24.12.31 | Xray 26.3.27 | Xray 26.7.28 | Xray 26.9.9 |
|---|---|---|---|---|
| chrome / firefox / safari / пустой / edge, по умолчанию | ok, 1-е соединение | ok, 1-е | ok, 1-е | ok, **2-е** (1-е классическое отвергнуто, затем ML-KEM; edge → chrome) |
| то же + `support-x25519mlkem768: true` | ok с target без ML-KEM; **fail** с `target-mlkem` | ok | ok | ok, 1-е |

Xray 24.12.31 подтверждает, почему первое рукопожатие классическое: с ML-KEM старый сервер (при target с ML-KEM) не пускает.

### P7: результаты (Xray 26.10.21, 26.10.2026)

Стенд: Debian 13 (Aeza, Paris), Xray 26.10.21. Четыре входа с одним ключом: 443 и 4443 — без `minClientVer`; 8443 и 9443 — `minClientVer: "26.9.8"`; 4443/9443 — `flow: xtls-rprx-vision`. Клиент — этот форк, Batumi (Georgia), ~60 мс до стенда.

| Вход | chrome + ML-KEM | chrome без ML-KEM | firefox + ML-KEM | firefox без ML-KEM |
|---|---|---|---|---|
| 443, без `minClientVer` | ok | ok (P6: 1 отказ, затем ML-KEM) | ok | ok |
| 4443, vision, без `minClientVer` | ok | ok (P6: 1 отказ, затем ML-KEM) | ok | ok |
| 8443, `minClientVer` 26.9.8, **client-version 26.3.27** | **fail** | **fail** | **fail** | **fail** |
| 8443, `minClientVer` 26.9.8, client-version 26.10.21 | ok | ok (P6) | ok | ok |
| 9443, vision, `minClientVer` 26.9.8, client-version 26.10.21 | ok | ok (P6) | ok | ok |

Лог сервера для падающих строк: `hs.c.ClientVer: [26 3 27]` → `REALITY: processed invalid connection`; после поднятия версии — `[26 10 21]` и соединение проходит. Отсюда: «новый Xray с требованием» — это `minClientVer`, а не сам ML-KEM; P1/P3 теперь по умолчанию шлют 26.10.21, отдельный `client-version` в подписке не нужен. ML-KEM без `support-x25519mlkem768` P6 выучивает за одно неудачное соединение — и на новом Xray это работает.

**RF mobile.** В датацентровых сетях (Batumi, Paris) поломка не воспроизводится: chrome+ML-KEM проходит. По [XTLS/Xray-core#6293](https://github.com/XTLS/Xray-core/issues/6293) ТСПУ на мобильных операторах оценивает ClientHello по подсети/AS сервера, SNI и отпечатку: Chrome, Safari и iOS «держит», Firefox, Android, OkHttp и Edge пропускает; отдельно замораживает при 3+ рукопожатиях за 20–50 мс и после ~15–20 КБ данных. Поэтому «chrome + mlkem не работает» — это блокировка Chrome-отпечатка, а не ML-KEM: firefox с ML-KEM проходит. Для таких сетей в шаблоне подписки: `client-fingerprint: chrome` + `mlkem-client-fingerprint: firefox` (P7); для мультиплексирования браузерных соединений — XHTTP/HTTP2 или mux, а не пачка TLS-рукопожатий. Проверить на реальном телефоне оператора: в датацентре не воспроизводится.

### P8: результаты XHTTP (фейковый сервер, ответ через 150 мс, 64 КБ)

`go test ./transport/xhttp/ -run TestBPNPacketUpThroughput -v` (Windows amd64):

| Интервал | Слотов записи | POST/h2 | GET+заголовки/h2 |
|---|---|---|---|
| 30 мс | 1 | 13,2 Мбит/с | 13,1 Мбит/с |
| 30 мс | 8 | 13,2 Мбит/с | 13,2 Мбит/с |
| 0 | 1 | 54,9 Мбит/с | 50,5 Мбит/с |
| 0 | 8 | 54,7 Мбит/с | 50,7 Мбит/с |

На интервале 30 мс число слотов больше не влияет — потолок задаёт интервал (P5 раньше давал 13 Мбит/с только при N=8, а при N=1 — около 2). На интервале 0 один слот уже держит окно из 24 seq, поэтому n=1 и n=8 совпадают и дают ~4× к прежнему потолку. Interop с Xray (26.10.21, h2/h1, POST и GET, 16 МиБ + sha256) проходит; на 150 мс n=8 больше не обязателен. Серверные правки P8 проверены тем же interop-тестом, `TestBPNPacketUpClientEchoWithServerHandler` (POST и GET-header) и `go test ./transport/xhttp/`.

Сравнение серверов Xray и mihomo на арендованном Debian (Paris, 1 vCPU) с клиентом из Батуми оказалось неинформативным: оба сервера упираются в канал/CPU стенда одинаково (download ~6 Мбит/с, upload ~1,5 Мбит/с, 16 МиБ не успевает за 90 с), разницы между реализациями не видно. Клиентские числа выше сняты на детерминированном фейковом сервере и от стенда не зависят.

### P9: xdrive, конфигурация и результаты

Протокол тот же, что у Xray: `sessions/<ns>-<id>`, `streams/<id>/c2s|s2c/<seq>.seg`, `.end`, `.err`; опрос каталога, TTL сессии, hole timeout. Реализованы `local`, `google-drive` и `template` (Yandex WebDAV). Xray требует для xdrive VLESS-шифрование (TLS у потока нет), а Xray-клиенту нужен `mux`.

Клиент (mihomo):

```yaml
- name: xdrive
  type: vless
  server: 127.0.0.1   # xdrive не дозванивается сюда; поле обязательно
  port: 1
  uuid: 11111111-2222-3333-4444-555555555555
  encryption: mlkem768x25519plus.native.0rtt.<...>   # xray vlessenc
  network: xdrive
  xdrive-opts:
    service: template
    remote-folder: xdrive            # каталог/папка
    secrets: ["<user>", "<password>"]
    template: '{"flatten":true,"auth":{"type":"basic","username":"{secret0}","password":"{secret1}"},"put":{"method":"PUT","url":"https://webdav.yandex.ru/{folder}/{name}"},"get":{"method":"GET","url":"https://webdav.yandex.ru/{folder}/{name}"},"delete":{"method":"DELETE","url":"https://webdav.yandex.ru/{folder}/{name}"},"list":{"method":"PROPFIND","url":"https://webdav.yandex.ru/{folder}/","headers":{"Depth":"1"},"namesRegex":"<d:href>[^<]*/([^/<]+)</d:href>"},"retry":{"status":[429,500,502,503]}}'
    segment-bytes: 262144
    flush-interval-ms: 100
    poll-interval-ms: 300
    max-poll-interval-ms: 1500
    session-ttl-seconds: 120
    concurrency: 8
```

Сервер (mihomo), без `port`:

```yaml
listeners:
- name: xdrive
  type: vless
  listen: 127.0.0.1
  users:
  - uuid: 11111111-2222-3333-4444-555555555555
  decryption: mlkem768x25519plus.native.600s.<...>
  xdrive-config:
    service: google-drive
    remote-folder: <folder id>
    secrets: [<client id>, <client secret>, <refresh token>]
```

Проверка:

```sh
go test ./transport/xdrive/
XRAY_BINARY=/path/to/xray go test ./listener/inbound -run BPNXDriveXrayInterop -v
```

`TestBPNXDriveXrayInterop` поднимает Xray 26.10.21 с `xdriveSettings.service: local` и гоняет mihomo-клиент через общий каталог: 1 МиБ вверх и 1 МиБ вниз, sha256, ~110 Мбит/с на local. Вручную проверено и обратное: Xray-клиент (с `mux`) через xdrive к mihomo-серверу открывает HTTPS, ответ 200. Ограничения: у Xray-клиента обязателен `mux`; `stream-one`/`stream-up` xdrive не использует; Google Drive может быть недоступен из РФ — берите `template` на Yandex WebDAV.

### P11: Xray API, пользователи и лимиты

Конфиг сервера:

```yaml
xray-api:
  listen: 127.0.0.1:10085      # пусто/нет секции — выключено

listeners:
- name: vless-in
  type: vless
  listen: 0.0.0.0
  port: 443
  users:
  - username: alice           # email в терминах Xray
    uuid: 11111111-2222-3333-4444-555555555555
    flow: xtls-rprx-vision
  decryption: none
  reality-config: { ... }

user-limits:
- inbound: vless-in
  user: alice
  max-conns: 4
  up-bps: 20000000            # байт/с, 0 — без лимита
  down-bps: 50000000
  quota: 107374182400         # upload+download, байт
  expire-at: "2026-12-31T00:00:00Z"   # или unix seconds
```

Панель или `xray api`:

```sh
xray api lsi --server=127.0.0.1:10085
xray api adu --server=127.0.0.1:10085 user.json   # AddUserOperation
xray api inbounduser --server=127.0.0.1:10085 -tag=vless-in
xray api stats --server=127.0.0.1:10085 -name "user>>>alice>>>traffic>>>uplink" -reset
xray api statsquery --server=127.0.0.1:10085 --pattern "user>>>"
xray api statsgetallonlineusers --server=127.0.0.1:10085
xray api rmu --server=127.0.0.1:10085 -tag=vless-in alice
```

REST (тот же `external-controller` и secret):

```sh
GET    /inbounds
GET    /inbounds/vless-in/users
PUT    /inbounds/vless-in/users            {"users":[{"username":"alice","uuid":"...","flow":""}]}
POST   /inbounds/vless-in/users            {"username":"bob","uuid":"..."}
PATCH  /inbounds/vless-in/users/alice      {"uuid":"...","flow":"xtls-rprx-vision"}
DELETE /inbounds/vless-in/users/bob
GET    /limits/users?inbound=vless-in&user=alice
POST   /limits/users                       {"inbound":"vless-in","user":"alice","quota":107374182400}
POST   /limits/users/reset-quota?inbound=vless-in&user=alice
DELETE /limits/users?inbound=vless-in&user=alice
```

Что важно знать:

- API без пароля, как у Xray: слушайте только `127.0.0.1` или unix-сокет. `AddInbound`/`RemoveInbound`/outbounds не поддерживаются (панель должна задавать inbound в конфиге mihomo); `ListInbounds` отдаёт теги.
- Пользователи — только VLESS (`xray.proxy.vless.Account`); VMess/Trojan-аккаунты через API отклоняются. `email` = `username`, он должен быть непустым и уникальным в inbound.
- `user>>>email>>>traffic>>>*` суммируется по всем inbound с этим именем; `inbound>>>tag>>>traffic>>>*` — отдельный счётчик inbound (включает и трафик без пользователя); его reset не обнуляет счётчики пользователей.
- `GetStatsOnlineIpList` отдаёт пустой список IP: mihomo не хранит IP пользователя, только число соединений.
- Runtime-пользователи живут в памяти: reload с изменённым `users:` пересоздаёт listener; добавленные через API пользователи при этом теряются, как и у Xray.
- Скорость ограничивается после чтения/записи (token bucket, всплеск 100 мс); квота проверяется на новом соединении и после каждого блока, при исчерпании сессия закрывается. Снятие пользователя закрывает его живые сессии (`DELETE` и `rmu`).

Проверка (Windows, Xray 26.10.21):

```sh
go test ./hub/xrayapi ./tunnel/statistic ./common/net
```

Сквозной сценарий: `xray api adu` добавляет `bob`, `bob` подключается через VLESS+xdrive (200), `stats` отдаёт upload/download, `statsonline` — 1, `rmu` во время живой сессии её закрывает, после `rmu` новый коннект — 502.

### P12: relay batching

Порт Citrus: при передаче источник читается отдельной горутиной, а запись идёт одним `writev(2)` на все уже прочитанные буферы (пачка до 9 буферов плюс до 8 в очереди, около 0,5 МиБ на направление). Это ускоряет upload через TLS/Shadowsocks, где каждый `Read` — одна запись; download из сокета идёт прежним путём. Проверка: `go test ./common/net/`; поведение relay не меняется, добавочные буферы выделяются только во время передачи.

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
- P6 написан по мотивам патча ClashFest 0002 ([Nemu-x/ClashFest](https://github.com/Nemu-x/ClashFest), GPL-3.0, автор Nemu-x); ссылка — в коде и в сообщении коммита.
- utls — BSD-3-Clause (The Go Authors, refraction-networking, metacubex). Лицензия идёт с модулем.
- Этот форк не связан с MetaCubeX и XTLS. Проблемы этой сборки в upstream не сообщаем.
