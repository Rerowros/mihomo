# BadVPN: патчи поверх mihomo

Эта ветка (`bpn/<тег mihomo>`) — ядро mihomo для Android-клиента BadVPN. Это тег upstream [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) плюс небольшой набор патчей ниже. Больше ничего не меняется.

*English summary: MetaCubeX/mihomo tag + a small patch set for REALITY compatibility with current Xray-core (client version 26.3.27, empty fingerprint → chrome, optional `reality-opts.client-version`; X25519MLKEM768: the first handshake to a server is classic, then the core learns per server and public key whether it needs ML-KEM (Xray >= 26.9.8), `reality-opts.support-x25519mlkem768: true` forces it) and metacubex/utls `v1.9.0-mod-meta` (Firefox 148 / Safari 26.3). Branch `bpn/v1.19.31-xhttp-par` adds P5: XHTTP packet-up sends up to 8 upload requests in parallel (Xray-style pipelining) instead of one at a time. Branch `bpn/v1.19.33-frag` adds P19: optional per-proxy `fragment-opts` that splits the TLS ClientHello into several TLS records (or raw TCP pieces), same semantics as Xray finalmask `fragment`. Not affiliated with MetaCubeX; please do not report issues from this build upstream.*

- Upstream: `MetaCubeX/mihomo`, тег **v1.19.33** (`3f27ef39`). В нём `metacubex/tls` 0.1.9 (CVE-2026-97031, проверка ECH outer extensions на сервере), сохранение fake-IP при перезагрузке конфига, URL-тест быстрее 1 мс больше не считается неудачей, ограничение зависших DoH-запросов, `tun.dns-mode`.
- Ветка: `bpn/v1.19.33` = `bpn/v1.19.32` (`67555dc7`, `v1.19.32-bpn.2`, P1–P6), перенесённая cherry-pick `v1.19.32..bpn/v1.19.32` на `v1.19.33` 28.10.2026. Коммиты патчей: `v1.19.33..bpn/v1.19.33`. Конфликт только в `go.mod`/`go.sum` (P2): `metacubex/tls` взят из upstream (0.1.9), utls оставлен на `78c9290b`. Хеши в таблице ниже — исходные, с `bpn/v1.19.31` / `bpn/v1.19.32`.
- utls: upstream v1.19.33 остался на v1.8.8, поэтому P2 нужен. Голова `v1.9.0-mod-meta` ушла вперёд (`a6a364af`, 27.10.2026: правки ECH/QUIC — сжатие ALPN во внутреннем ClientHello, обработка ошибки BuildHandshakeState у QUIC, transcript 0-RTT с ECH); на REALITY не влияет, ветка оставлена на проверенной `78c9290b` — её же закрепляет приложение. Исправление CVE-2026-97031 в utls не перенесено, но уязвимый `decodeInnerClientHello` там достигается только сервером с ECH-ключами, а через utls в mihomo идут только клиенты и REALITY-сервер без ECH (ECH-сервер — через `metacubex/tls`).
- Проверка после переноса (28.10.2026, Windows amd64): `go build`/`go vet`, сборки android/arm64 (`with_gvisor,cmfa`) и windows, тесты из «Проверки» — ok; матрица REALITY (Xray 24.12.31 / 26.3.27 / 26.7.28 / 26.9.9, 4 target, 144 случая) построчно совпадает с `bpn/v1.19.32`; `TestBPNXHTTPPacketUpXrayInterop` с Xray 26.9.9 — ok.
- Старые ветки `bpn/v1.19.31`, `bpn/v1.19.31-xhttp-par` и `bpn/v1.19.32` не меняются.
- Версии: тег `v1.19.32-bpn.N` = тег upstream + номер нашей сборки, растёт при каждом изменении набора патчей. `v1.19.32-bpn.1` = `9dd9fd41` (P1–P5, приложение 1.1.11), `v1.19.32-bpn.2` = + P6. Теги не переносятся.
- Список патчей совпадает с реестром приложения `docs/core-patches.md` (AGENTS.md §11). ID те же. При изменении правятся оба файла.

## Патчи

| # | Что меняет | Зачем | Файлы | Источник / автор / лицензия | С версии mihomo | Проверка | Когда убрать |
|---|---|---|---|---|---|---|---|
| **P1** | REALITY-клиент шлёт в session ID версию **26.3.27** вместо 1.8.2. В исходном коммите P1 ещё переставал вырезать X25519MLKEM768 (`support-x25519mlkem768` игнорировался) — **это отменено патчем P4**, вырезание снова как в upstream. Пустой `client-fingerprint` у REALITY → `chrome` (раньше была ошибка). Заодно в серверной части (listener REALITY) `max-time-difference` считается в миллисекундах, а не в микросекундах; приложение listener не использует | Совместимость с Xray ≥ 26.7.11 (умолчание `minClientVer` 26.3.27) и ≥ 26.9.8 (обязателен X25519MLKEM768 раньше X25519, [XTLS/REALITY 8cdf7bf](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8)). Upstream отказался: [#2967](https://github.com/MetaCubeX/mihomo/issues/2967), [#3132](https://github.com/MetaCubeX/mihomo/issues/3132), [#3193](https://github.com/MetaCubeX/mihomo/issues/3193), [PR #3070](https://github.com/MetaCubeX/mihomo/pull/3070) | `component/tls/reality.go`, `adapter/outbound/reality.go`, `transport/vmess/tls.go`, `listener/reality/reality.go` + тесты | cherry-pick `84cc2c17` ← [legiz-ru/Prizrak-Core `2197a3c`](https://github.com/legiz-ru/Prizrak-Core/commit/2197a3cac1e960987e3844a638a281509bb265ae), автор Jolymmiles (авторство в git сохранено), GPL-3.0 | v1.19.31 | `component/tls/reality_test.go`, `transport/vmess/tls_test.go`, `listener/reality/reality_test.go`; interop с настоящим Xray: `TestVLESSRealityXrayInterop`, `TestBPNRealityXrayMatrix` (см. ниже) | Когда upstream mihomo сам начнёт слать актуальную версию. Или когда у BadVPN не останется REALITY-нод |
| **P2** | `github.com/metacubex/utls` v1.8.7 → голова ветки `v1.9.0-mod-meta` (`v0.0.0-20260924074610-04010625d68b`). Отпечатки: `firefox` Firefox 120 → **148**, `safari` Safari 16.0 → **26.3**, оба с X25519MLKEM768. `chrome` (133), `edge` (85), `ios` (14), `android` (OkHttp 11) не менялись. Кода mihomo правка не требует | Свежие отпечатки, те же, что у Xray ≥ 26.3.27. Без них `firefox` на Xray ≥ 26.9.8 не проходит даже с `support-x25519mlkem768: true` (в Firefox 120 нет ML-KEM). У BadVPN tcp+REALITY-хосты с `firefox`. Upstream ждёт релиза uTLS 1.9.0 ([#3193](https://github.com/MetaCubeX/mihomo/issues/3193)) | `go.mod`, `go.sum` | коммит `28e9ea26` (свой). Код utls: [metacubex/utls@v1.9.0-mod-meta](https://github.com/metacubex/utls/tree/v1.9.0-mod-meta) (wwqgtxx и др.), BSD-3-Clause | v1.19.31 | `TestBPNFingerprintVersions` (firefox = 148, safari = 26.3), `TestBPNRealityMLKEMKeyShare`, interop-матрица | Когда upstream mihomo поднимет utls до версии с Firefox 148 / Safari 26.3 |
| **P3** | Необязательное поле `reality-opts.client-version: "x.y.z"` для каждого прокси. Версия по умолчанию задана в одном месте: `tlsC.DefaultRealityClientVersion` = 26.3.27. Значение `0.0.0` означает умолчание | Если на ноде задан `minClientVer` выше 26.3.27, версию можно поднять без пересборки ядра (через шаблон подписки) | `component/tls/reality.go`, `adapter/outbound/reality.go` + `*_bpn_test.go` | коммит `48d461ce` (свой, GPL-3.0 как mihomo). Идея — закрытый upstream [PR #3069](https://github.com/MetaCubeX/mihomo/pull/3069) | v1.19.31 | `TestBPNRealityDefaultClientVersion`, `TestBPNRealityClientVersionOverride`, `TestBPNParseRealityClientVersion`, `TestBPNRealityOptionsClientVersion` | Вместе с P1 |
| **P4** | X25519MLKEM768 снова вырезается из ClientHello (supported groups и key share), если в `reality-opts` не задано `support-x25519mlkem768: true`. Это семантика upstream mihomo; P1 её убирал. Поле `RealityConfig.SupportX25519MLKEM768` возвращено | 28.09.2026: сборка приложения с P1+P2 без P4 (ML-KEM в ClientHello chrome/firefox/safari, 1529–1881 байт вместо 307–659) не подключалась ни к одной REALITY-ноде (Xray 26.3.27, tcp, без flow, реальные target без X25519MLKEM768 — nginx на OpenSSL 3.0 / внешний сайт). Та же сборка с вырезанием ML-KEM — работает. На локальном стенде поломка **не воспроизводится** (см. «Проверка»): старый код проходит и с target без ML-KEM (Go и `openssl s_server`), и при дроблении ClientHello на TCP-сегменты; логика ключей клиента совпадает с Xray-клиентом. Причина, вероятно, на пути до ноды, а не в ядре. Цена: Xray ≥ 26.9.8 без ML-KEM не пускает — для таких нод в подписке нужен `support-x25519mlkem768: true` | `component/tls/reality.go`, `adapter/outbound/reality.go`; тесты `component/tls/reality_bpn_test.go`, `component/tls/reality_test.go`, `adapter/outbound/reality_bpn_test.go`, `listener/inbound/bpn_reality_xray_matrix_test.go`, `listener/inbound/vless_xray_reality_interop_test.go` | коммит `fix(reality): strip X25519MLKEM768 unless support-x25519mlkem768 (P4)` (свой, GPL-3.0 как mihomo); код — возврат upstream | v1.19.31 | `TestBPNRealityMLKEMKeyShare` (по умолчанию ML-KEM нет, с опцией — есть и стоит до X25519), `TestRealityChromeClientHelloPreservesFingerprint` (с опцией отпечаток не меняется), `TestBPNRealityOptionsSupportX25519MLKEM768`, interop-матрица; проверка на телефоне по всем типам нод | Вместе с P1 (без P1 это просто код upstream). Умолчание можно перевернуть, когда причина полевой поломки будет найдена и устранена, а ноды перейдут на Xray ≥ 26.9.8 |
| **P5** | XHTTP `packet-up`: запросы отправки (POST или `uplink-http-method: GET` с данными в заголовках `X-Payload-N`) идут параллельно, до **8** одновременно на сессию (`xhttp.PacketUpMaxInFlight`; предел в коде — 20), а не строго по одному с ожиданием ответа. `seq` — в порядке отправки; между началами запросов — не меньше `sc-min-posts-interval-ms`; `Write` блокируется, пока 8 запросов в пути (в памяти не больше 8 запросов + один буфер до `sc-max-each-post-bytes`); ошибка любого запроса отменяет остальные и рвёт сессию, как раньше. `stream-up` / `stream-one` не менялись. Для `alpn: [http/1.1]` у транспорта `MaxIdleConnsPerHost` = 8 (каждый запрос в пути — отдельное соединение). Настройки в конфиге нет: у Xray-клиента аналога нет (он число запросов вообще не ограничивает), поэтому константа | Линии через CDN, где не проходит POST (GET + заголовки): один запрос через CDN ~125–175 мс, отправка упиралась в размер запроса / RTT — 0,9–1,5 Мбит/с при 64 КБ. Xray шлёт запросы конвейером (пауза `scMinPostsIntervalMs` между началами, без ожидания ответов), сервер собирает по `seq` и держит до `scMaxBufferedPosts` (30). Почему 8: при 30 мс между запросами конвейер полон до RTT 240 мс; потолок 8 × 64 КБ / RTT (≈ 28 Мбит/с при 150 мс) выше потолка самого интервала (64 КБ / 30 мс ≈ 17 Мбит/с); 8 далеко от 30 даже при интервале 0 | `transport/xhttp/client.go`; тесты `transport/xhttp/packet_up_bpn_test.go`, `listener/inbound/bpn_xhttp_xray_interop_test.go` | коммит `69e5e055` (`feat(xhttp): send packet-up uploads in parallel, up to 8 in flight (P5)`) (свой, GPL-3.0 как mihomo); поведение — как у Xray `transport/internet/splithttp/dialer.go` | v1.19.31 | `TestBPNPacketUp*` (фейковый сервер с задержкой ответов; h2 и h1; POST и GET): (a) в пути ровно N и не больше, N = 1 — старое поведение; (b) `seq` без пропусков и повторов, поток собирается при ответах не по порядку (sha256); (c) ошибка → остальные запросы отменены, `Write` возвращает ошибку; (d) интервал между началами ≥ `sc-min-posts-interval-ms`; (e) после `Close` нет горутин `PacketUpWriter`, в том числе если запросы зависли и `Write` заблокирован; эхо через весь клиент и сервер mihomo. Interop с Xray 26.3.27 / 26.7.28 / 26.9.9: `TestBPNXHTTPPacketUpXrayInterop` (см. «Проверка»). На реальных линиях через CDN — ожидает (VPN PANEL) | Когда upstream mihomo сам станет слать запросы packet-up конвейером / параллельно, как Xray |
| **P6** | Адаптивный X25519MLKEM768 для REALITY без `support-x25519mlkem768`. Исход каждого рукопожатия запоминается по адресу сервера и публичному ключу (в памяти процесса): первое — без ML-KEM (как P4), после одного провала — с ML-KEM, после успеха вариант закрепляется, закреплённый меняется снова только после 3 провалов подряд (сервер обновили/откатили). Провалы «устаревшего» варианта, которые были в пути, не считаются. Если память хочет ML-KEM, а у отпечатка его нет (edge, ios, android, chrome120…), рукопожатие идёт с chrome. `support-x25519mlkem768: true` — как раньше: ML-KEM всегда, отпечаток не меняется, память не используется | Цена P4: Xray ≥ 26.9.8 без ML-KEM не пускает, а сервер не сообщает, какой он; Xray 24.x, наоборот, отбрасывает ClientHello с ML-KEM. С P6 ноды на 26.9.8+ работают без правки шаблона подписки, ценой одного неудачного соединения на сервер после старта ядра; поломка 28.09 (ML-KEM на пути) не повторяется — первое рукопожатие классическое | `component/tls/reality.go`, `adapter/outbound/reality.go` (комментарий); тесты `component/tls/reality_mlkem_memo_bpn_test.go`, `listener/inbound/bpn_reality_xray_matrix_test.go` | по мотивам патча ClashFest `core/patches/mihomo/0002-reality-adaptive-mlkem.patch` ([Nemu-x/ClashFest#239](https://github.com/Nemu-x/ClashFest/pull/239), автор Nemu-x, GPL-3.0); без глобальной политики Auto/On/Off и первого варианта «с ML-KEM» — у нас только «Авто», подмена на chrome только для выученного ML-KEM | v1.19.32 | `TestBPNRealityMLKEMMemoLearnsPerServer`, `TestBPNRealityMLKEMForcedSkipsMemo`, `TestBPNRealityMLKEMMemoReachesClientHello` (firefox оставляет свою ML-KEM-долю, edge → chrome); interop-матрица на Xray 24.12.31 / 26.3.27 / 26.7.28 / 26.9.9 (см. «P6: результаты»); проверка на телефоне по всем типам нод | Если upstream mihomo сам начнёт определять ML-KEM по серверу или все ноды перейдут на Xray ≥ 26.9.8 (тогда достаточно `support-x25519mlkem768: true` в шаблоне) |
| **P19** | Нарезка начала TLS-соединения (ClientHello) для отдельного прокси: новый блок `fragment-opts` у любого прокси, который строит дозвон через `BasicOption.NewDialer` (vless, vmess, trojan и др.). По умолчанию выключено (нет блока — поведение как раньше). `packets: tlshello` — первое ClientHello режется на несколько TLS-записей по `length` байт (по умолчанию 10–20); при `delay: 0` все записи уходят одной записью в сокет (ядро ОС режет на сегменты как обычно), при `delay` > 0 — каждая запись отдельно с паузой в мс. `packets: "N-M"` — записи N…M соединения режутся на куски по `length` байт без новых TLS-записей (только TCP-сегменты). `max-split` — предел числа кусков. Обёртка стоит под TLS/REALITY, поэтому одинаково работает для tcp, ws, grpc, xhttp и для `download-settings`. Неверный блок — ошибка при загрузке конфига. В ссылках `vless://`/`vmess://` параметр Xray `fm` (первая TCP-маска `fragment`) переводится в `fragment-opts`. Пример: `fragment-opts: {packets: tlshello, length: "10-20", delay: 0}` | Полевой замер 01.11.2026, Теле2 мобильный, Иркутск (AS41330): REALITY к иностранному IP без нарезки не проходит ни с каким SNI, с нарезкой Xray `tlshello`, 10–20, delay 0 — проходит (6,6–7,9 Мбит/с); российские IP проходят всегда. В Xray это нарезка TLS-записей одной записью в сокет, т. е. фильтр, вероятно, разбирает целую первую TLS-запись. Один человек, одна сеть — гипотеза. Upstream mihomo такого не принимает (см. «P19: разведка») | `component/fragment/fragment.go`, `adapter/outbound/base.go` (`BasicOption.FragmentOpts`, обёртка в `NewDialer`), `adapter/parser.go` (проверка при загрузке), `common/convert/v.go` (`fm`); тесты `component/fragment/fragment_bpn_test.go`, `component/fragment/dpifilter` (модель фильтра, только для тестов), `adapter/parser_bpn_test.go`, `adapter/outbound/fragment_bpn_test.go`, `common/convert/fragment_bpn_test.go`, `listener/inbound/bpn_fragment_xray_interop_test.go` | коммит `eb7a9782` (свой, GPL-3.0 как mihomo). Поведение и имена настроек — как у Xray-core finalmask `fragment` (`transport/internet/finalmask/fragment/conn.go`, v26.10.21 `1b1647cd`, MPL-2.0; код написан заново по этой логике) | v1.19.33 | `TestBPNFragment*`: записи по 10–20 байт, вместе дают то же ClientHello, сервер завершает рукопожатие; с паузой — одна запись на запись в сокет; режим TCP — те же байты кусками; выключено — одним куском; данные после рукопожатия не меняются; первая запись не-ClientHello не трогается. Модель фильтра (`TestBPNFragmentFilterModel`): без нарезки — сброс, с нужным режимом — рукопожатие и эхо 256 КБ по sha256. Interop с настоящим Xray 26.3.27 / 26.9.9 / 26.10.21 за моделью фильтра (`TestBPNFragmentXrayInterop`, 9 входов × 3 варианта): REALITY tcp / vision / xhttp, TLS tcp / ws / grpc / xhttp, trojan, vmess ws — без нарезки сброс, с нарезкой эхо 1 МБ по sha256. Полевая проверка — скрипт проверки (mihomo с нарезкой рядом с Xray) | Когда upstream mihomo сам получит нарезку ClientHello. Или когда операторы перестанут резать ClientHello к иностранным адресам |

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

### P19: нарезка ClientHello — разведка (01.11.2026)

Номер P19, а не P7: P7–P18 уже заняты ветками `bpn/p7-reality` … `bpn/p18-user-ips` (сводка — `BADVPN.md` на `bpn/docs-p13-p17`).

**Что есть в MetaCubeX/mihomo.** Нарезки ClientHello нет (поиск по коду v1.19.33 `3f27ef39`). Просили давно, мейнтейнеры не взяли:

| Где | Дата | Что предлагали | Итог |
|---|---|---|---|
| [#1046](https://github.com/MetaCubeX/mihomo/issues/1046) | 18.02.2024 | fragment и noise в конфиге, как в Xray | открыт, ответа мейнтейнеров нет; в комментариях 2026 года люди пишут, что делают свои форки |
| [#1797](https://github.com/MetaCubeX/mihomo/issues/1797) | 19.01.2025 | «будет ли TLS fragment» | закрыт NOT_PLANNED сразу после создания |
| [#2814](https://github.com/MetaCubeX/mihomo/issues/2814) | 20.05.2026 | `tlshello` как в Xray; в комментарии — вариант sing-box `record_fragment` без FinalMask | открыт, ответа мейнтейнеров нет |
| [PR #2954](https://github.com/MetaCubeX/mihomo/pull/2954) | закрыт 10.07.2026 | FinalMask TCP (fragment + header-custom), автор SantaGitHub | не принят: wwqgtxx — «We are not interested in FinalMask» |

Готового кода в форках mihomo, который стоило бы взять, нет: у legiz-ru/Prizrak-Core, FlClash, Clash Verge Rev нарезки нет. Есть клиент enkinvsh/dropweb (GPL-3.0) с `component/dialer/tlsfragment.go` — режет первую запись в сокет по TCP-кускам вокруг SNI с паузой, ключи в корне конфига и сразу для всех соединений, включая DIRECT; TLS-записи не режет, то есть повторяет не тот режим, что сработал в замере. Не взят.

**Как в других ядрах** (`D:\vpn-wiki\raw\src`):

| Ядро | Что режет | Параметры | Пауза, TCP_NODELAY | REALITY / uTLS / ECH | Источник |
|---|---|---|---|---|---|
| Xray finalmask `fragment`, `packets: tlshello` | первую запись в сокет, если это целая TLS-запись handshake: ClientHello → несколько TLS-записей по `length` байт | `length`, `delay`, `lengths[]`/`delays[]` (с 26.9.x), `maxSplit` | `delay: 0` → все записи **одной** записью в сокет (сегменты режет ОС); иначе запись → пауза → запись. NODELAY — как у Go (включён) | маска стоит под TLS/REALITY на сыром TCP, работает для всех | `transport/internet/finalmask/fragment/conn.go:65-128@1b1647cd`, `infra/conf/transport_finalmask.go:275@1b1647cd` |
| Xray finalmask `fragment`, `packets: "N-M"` | записи N…M в сокет кусками `length` байт, без новых TLS-записей | те же | пауза после каждого куска | то же | `conn.go:131-156@1b1647cd` |
| Xray freedom `fragment` (старый способ, через `dialerProxy`) | то же, `interval` вместо `delay` | `packets`, `length`, `interval` | `interval: 0` → записи одной записью в сокет | то же | `proxy/freedom/freedom.go:713-795@1b1647cd` |
| sing-box `tls.record_fragment` (с 1.12.0) | ClientHello → TLS-записи, границы — случайно внутри каждой метки SNI | вкл/выкл | одной записью в сокет | только `std` и `utls`-клиент; **у REALITY-клиента нарезки нет** | `common/tlsfragment/conn.go:46-128@21befb11a`, `common/tls/utls_client.go:87@21befb11a`, в `reality_client.go` вызова нет |
| sing-box `tls.fragment` (с 1.12.0) | те же куски — отдельными TCP-сегментами | `fragment_fallback_delay` (500 мс) | NODELAY включает на время ClientHello; ждёт подтверждения каждого сегмента (`TCP_INFO.Unacked == 0` на Linux, `winiphlpapi` на Windows с правами админа), иначе фиксированная пауза; документация: медленно, пробовать сначала `record_fragment` | как выше | `conn.go:52,103@21befb11a`, `wait_linux.go:30@21befb11a`, `docs/configuration/shared/tls.md:653-690` |
| byedpi / zapret (справочно) | split/disorder/fake TCP-сегментов и TLS-записей (`tlsrec`) на уровне системы или SOCKS | много | сырые сокеты, TTL-трюки | не зависят от протокола | не разбирались подробно |

**Выбор.**

| Способ | Что режет | Сложность в mihomo | Риски | Совместим с Xray REALITY-сервером |
|---|---|---|---|---|
| A. Как Xray `tlshello` (TLS-записи), обёртка сырого TCP у прокси | записи (одной записью в сокет или с паузами) | маленькая: обёртка `C.Dialer` в `BasicOption.NewDialer` — покрывает все транспорты и REALITY сразу | ClientHello растёт на ~5 байт на кусок (301 → 396 байт на тесте); фильтр, который собирает записи, обойдётся | да: Go `crypto/tls` у сервера собирает handshake из нескольких записей; проверено interop-тестом и полевым замером Xray↔Xray |
| B. Как Xray `packets: "1-1"` (только TCP-сегменты) | сегменты | та же обёртка, тот же код | проверен только с паузой (без неё ОС может склеить куски в один сегмент); пауза добавляет delay × кусков к каждому новому соединению | да (сервер видит обычный поток) |
| C. Как sing-box: границы по SNI, ожидание ACK | записи или сегменты | надо тянуть `winiphlpapi`/`TCP_INFO`, на Windows без админа — фиксированная пауза | медленно (по документации sing-box); в замере не проверялся | да |
| D. Отдельный прокси-цепочка (`dialer-proxy` на direct с фрагментом) | — | надо менять direct и цепочки в подписке | сложнее для шаблона подписки | да |

Взят **A** (обязательный режим) + **B** (почти даром, тот же код), с именами и семантикой Xray: `fragment-opts.packets` / `length` / `delay` / `max-split` — шаблон подписки и ссылки с `fm` переносятся один в один, а на ноде можно включать по одной. В Xray `delay: 0` при `tlshello` — склейка записей, повторено так же: именно этот вариант прошёл в замере.

**Отличия от Xray** (ревью 01.11.2026): пустой `packets` у нас = `tlshello` (в Xray — резать все записи в сокет); без `length` у нас 10–20 (Xray отвергает); списки `lengths`/`delays` не поддерживаются — из `fm` берётся первый элемент; пауза только между кусками (Xray ждёт и после последнего); перевёрнутый диапазон переставляется, как в Xray; значения больше 2³¹−1 — ошибка. Ссылка с `fm`, который не разбирается, приходит **без** нарезки (одна плохая ссылка не ломает подписку). У `type: direct` блок принимается, но не действует (DIRECT дозванивается мимо `NewDialer`). Проверка «первая запись — целая TLS-запись ClientHello» строже, чем у Xray (`p[1] == 3`, `p[5] == 1`); ClientHello больше 16 КБ (ECH, большой padding) режется только в первой записи.

**Модель фильтра** (`component/fragment/dpifilter`, только тесты): `Record` собирает TCP-поток до конца первой TLS-записи и рвёт соединение (RST), если в ней целое ClientHello с SNI; `Segment` смотрит только первый кусок, отданный ядром ОС, и рвёт, если записи в нём вместе дают целое ClientHello. Результат (`TestBPNFragmentFilterModel`):

| Фильтр | выкл | tlshello, delay 0 | tlshello, delay > 0 | только TCP, delay 5 |
|---|---|---|---|---|
| Record | сброс | проходит | проходит | сброс |
| Segment | сброс | сброс | проходит | проходит |

Interop (`TestBPNFragmentXrayInterop`, фильтр `Record` перед каждым входом Xray, 01.11.2026, Windows amd64): Xray 26.3.27 (sha256 zip `d004c392…`, сверен с `.dgst`), 26.9.9, 26.10.21 — по 27/27: без нарезки 9/9 сброс, `tlshello 10-20 delay 0` 9/9 и `delay 1` 9/9 — эхо 1 МБ совпадает. После P19 без изменений: `TestBPNRealityXrayMatrix`, `TestVLESSRealityXrayInterop`, `TestBPNXHTTPPacketUpXrayInterop` (Xray 26.10.21), тесты `component/tls`, `adapter/...`, `transport/...`, `listener/reality`, сборка android/arm64 `with_gvisor,cmfa`.

```sh
go test ./component/fragment/... ./adapter/... ./common/convert/ -count=1
XRAY_BINARY=/path/to/xray go test ./listener/inbound -run BPNFragmentXrayInterop -v -count=1
```

Не проверено: реальная сеть с фильтром (ждёт полевого замера скриптом проверки), Android-сборка приложения с P19, TFO/MPTCP вместе с нарезкой, `dialer-proxy` вместе с нарезкой (обёртка ставится и туда — режется первая запись в цепочку).

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
