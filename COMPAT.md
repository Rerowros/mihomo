# Совместимость: наше ядро, обычный mihomo и Xray

Для тех, кто пишет шаблон подписки и конфиги нод BadVPN. Здесь — какие ключи и какое поведение есть только в нашем ядре (форк mihomo, патчи P1–P18 из [BADVPN.md](BADVPN.md)), как их понимают обычный mihomo (Clash Meta) и нода Xray и что из этого можно класть в общую подписку.

Состояние на 28.10.2026. Обычный mihomo проверен на тегах upstream **v1.19.32** и **v1.19.33** (между ними в REALITY, XHTTP, VLESS и utls изменений нет).

## Коротко

1. **Обычный mihomo неизвестные ключи молча пропускает.** Конфиг из-за них не падает — ни в прокси, ни в группах, ни в корне, ни в `listeners`. Но и не делает того, что ключ обещает: где без ключа соединение не собирается (xdrive), прокси просто будет «мёртвым».
2. **Наше ядро на неверное значение своего ключа отвечает ошибкой всего профиля** (опечатка в `mlkem-client-fingerprint`, `client-version: abc`, `mux.cool` вместе с `flow: xtls-rprx-vision`). Одна плохая строка в подписке — у наших клиентов не загрузится ничего.
3. **Главная разница на проводе — REALITY.** Обычный mihomo шлёт версию клиента 1.8.2, наши выпущенные клиенты — 26.3.27, ветка P7 — 26.10.21. Ноды Xray ≥ 26.9.8 пускают только ClientHello с X25519MLKEM768; обычный mihomo умеет его только с `client-fingerprint: chrome` + `support-x25519mlkem768: true`.
4. **Ключи из открытых PR (P7–P18) сейчас не работают ни у одного клиента**: в приложения они не попали. Их можно писать в подписку только тогда, когда версия с ними выйдет, и только если обычный mihomo без них не ломается (см. таблицу).

## Кто на каком ядре

| Кто | Ядро | Что из наших патчей есть |
|---|---|---|
| Android (BPNclash, `main`) | наш форк, тег `v1.19.32-bpn.2` (`67555dc7`) | P1–P6 |
| ПК (bpn-client, `main`) | наш форк `v1.19.31-9-g9b11ffbd` (`resources/hashes/components.windows.json`); ветки после 10.10 — `v1.19.32-10-g9dd9fd41` = `v1.19.32-bpn.1` | P1–P5, **без P6** |
| iOS | обычный mihomo (Clash Meta), версия у каждого своя | ничего |
| Ноды | Xray (PasarGuard) | — |
| Открытые PR форка | P7 [#2](https://github.com/Rerowros/mihomo/pull/2), P8 [#3](https://github.com/Rerowros/mihomo/pull/3), P9 [#4](https://github.com/Rerowros/mihomo/pull/4), P10 [#5](https://github.com/Rerowros/mihomo/pull/5), P11 [#6](https://github.com/Rerowros/mihomo/pull/6), P12 [#7](https://github.com/Rerowros/mihomo/pull/7), P13 [#11](https://github.com/Rerowros/mihomo/pull/11), P14 [#10](https://github.com/Rerowros/mihomo/pull/10), P15 [#9](https://github.com/Rerowros/mihomo/pull/9), P16 [#13](https://github.com/Rerowros/mihomo/pull/13), P17 [#12](https://github.com/Rerowros/mihomo/pull/12), P18 [#14](https://github.com/Rerowros/mihomo/pull/14) | не влиты в `bpn/v1.19.32`, ни в одном клиенте их нет |

Важно для ПК: без P6 ПК ведёт себя с ML-KEM как обычный mihomo — ML-KEM только по `support-x25519mlkem768: true`.

## Как обычный mihomo читает чужие ключи

- Прокси и группы разбирает `structure.NewDecoder` (`adapter/parser.go`, `adapter/outboundgroup/parser.go`). Ключи, которых нет в структуре, складываются в `dataValKeysUnused` и в ошибку не превращаются (`common/structure/structure.go`, режима ErrorUnused нет).
- Корень конфига — `yaml.Unmarshal` без strict (`config/config.go`), неизвестный ключ верхнего уровня пропускается.
- Проверено прогоном: все ключи из таблиц ниже на upstream v1.19.32 и v1.19.33 дают `test is successful`, а контрольные ошибки (`port: abc`, группа со ссылкой на несуществующий прокси) — `test failed`. Значит, проверка настоящая.
- Ошибка одного прокси в `proxies:` или в proxy-provider роняет весь профиль или провайдер (`config/config.go`: `proxy %d: …`, `adapter/provider/provider.go`: `proxy %d error: …`). Это касается и нашего ядра: наши проверки значений бьют по всему профилю.
- `mihomo -t` не запускает listeners и контроллер. Ошибки, которые всплывают только при старте (файл `fallback-page`, отказ контроллера без `secret`), прогоном `-t` не ловятся — для них ниже указан код.

## Ключи прокси (то, что идёт в подписку)

«Наше ядро» — с какого патча и где он сейчас. «Обычный mihomo» — upstream v1.19.32/33. «Xray» — что видит нода Xray на проводе.

| Ключ | Наше ядро | Обычный mihomo | Xray-нода | Как писать в подписку | Чем подтверждено |
|---|---|---|---|---|---|
| `reality-opts.client-version: "x.y.z"` | P3, влито, есть на Android и ПК. Без ключа шлёт 26.3.27 (P7, PR #2: 26.10.21). Неверное значение (`abc`) — **ошибка профиля** | Игнор. Всегда шлёт 1.8.2 | Сверяет с `minClientVer`/`maxClientVer` inbound. Умолчание `minClientVer` = 26.3.27 в Xray 26.7.11 и 26.7.28 (обычный mihomo туда не попадает); в 26.9.9, 26.9.30, 26.10.21 умолчание выключено | Можно всем. Нужен, только если на ноде `minClientVer` выше 26.3.27 (например 26.9.8): без ключа наши текущие клиенты туда не попадут. iOS на такую ноду не попадёт никак. Значение — строкой в кавычках | `-t`: upstream 32/33 — ok; форк `bpn/p7-reality` — `abc` → `invalid REALITY client version`. Умолчания — `component/tls/reality.go` в `67555dc7`, `9dd9fd41`, `9b11ffbd`, `bpn/p7-reality`. Xray — `infra/conf/transport_security.go` по тегам. Отказ при версии ниже `minClientVer` — «P7: результаты» в BADVPN.md |
| `reality-opts.support-x25519mlkem768: true` | Ключ upstream. У нас: ML-KEM всегда, адаптивный выбор P6 выключен, отпечаток не меняется. С ML-KEM у нас `chrome`, `firefox` (148), `safari` (26.3) | Работает так же: ML-KEM всегда. Но в utls v1.8.8 ML-KEM есть только у `chrome` (133); у `firefox` (120) и `safari` (16.0) его нет, с ними флаг не помогает | Xray ≥ 26.9.8 отклоняет ClientHello без X25519MLKEM768 перед X25519. Xray 24.12.31 с target, у которого есть ML-KEM, отклоняет ClientHello с ML-KEM | **Решать по ноде.** Нода Xray ≥ 26.9.8: ставить (иначе не войдут iOS и ПК без P6) и давать `client-fingerprint: chrome`. Нода старше: не ставить (поломка 28.09: с ML-KEM не подключалась ни одна нода; Xray 24.x отбрасывает) | `-t` upstream 32/33 — ok. REALITY-сервер `xtls/reality@…83f621788ca8`, `tls.go`: «reject … Client Hello that doesn't have X25519MLKEM768 before optional X25519». Наборы отпечатков — `metacubex/utls@v1.8.8` `u_parrots.go`. Матрица Xray — BADVPN.md, P4 и P6 |
| `reality-opts.mlkem-client-fingerprint` | P7, **открытый PR #2**, ни в одном клиенте. Если рукопожатие идёт с ML-KEM, берётся этот отпечаток. Значение без ML-KEM (`edge`, `ios`, `android`) или опечатка — **ошибка профиля** | Игнор, используется `client-fingerprint` | Обычный ClientHello, нода разницы не видит | После выхода P7 — можно всем (обычный mihomo пропустит), только значения `chrome`, `firefox`, `safari`. До выхода не нужен | `-t`: upstream — ok; `bpn/p7-reality`: `edge` → `has no X25519MLKEM768 key share`, `firefx` → `invalid mlkem-client-fingerprint` |
| `client-fingerprint` пустой у REALITY | P1, влито: подставляется `chrome` | `-t` проходит, а **каждое соединение** падает с «REALITY is based on uTLS, please set a client-fingerprint» | — | Всегда задавать явно | `-t` upstream — ok; код `transport/vmess/tls.go` v1.19.33 (ветка `cfg.Reality != nil`); дифф P1 в `bpn/v1.19.32` |
| `client-fingerprint: firefox` / `safari` | P2, влито: Firefox 148 / Safari 26.3, оба с ML-KEM (без флага/обучения ML-KEM вырезается) | Firefox 120 / Safari 16.0, ML-KEM нет. Другой отпечаток на проводе, в том числе для обычного TLS | Для Xray ≥ 26.9.8 обычный mihomo с этими отпечатками не войдёт ни с какими флагами | На нодах Xray ≥ 26.9.8, куда ходит iOS, — `chrome`. Цена: на мобильных сетях РФ отпечаток Chrome могут «держать» (BADVPN.md, «P7: результаты») | utls v1.8.8 и голова `v1.9.0-mod-meta` (P2), `TestBPNFingerprintVersions` |
| `mux.cool: {enabled: true, …}` | P15, **открытый PR #9**, ни в одном клиенте. Только `type: vless`. Вместе с `flow: xtls-rprx-vision` или `smux.enabled` — **ошибка профиля** | Игнор: каждое соединение — отдельное VLESS-соединение, как без ключа | Xray Mux понимает. Но если у пользователя на ноде `flow: xtls-rprx-vision`, а клиент шлёт mux без flow, Xray отклоняет mux с TCP-сессиями | После выхода P15 — можно всем, но **только у прокси без vision** (и если у пользователя на ноде flow пустой). С vision наши клиенты с P15 потеряют весь профиль | `-t`: upstream — ok и с vision; `bpn/p15-muxcool`: vision → `mux.cool cannot be used with VLESS flow`, smux → `smux and mux.cool cannot be enabled together`. Xray: `proxy/vless/inbound/inbound.go` (исходники 26.5.9, ветка `case ""`) |
| `network: xdrive` + `xdrive-opts` | P9, **открытый PR #4**, ни в одном клиенте | `-t` проходит, а `network` неизвестен: уходит в ветку «обычный tcp» и стучится на `server:port` (у xdrive там заглушка) — **прокси мёртвый** | Работает с Xray-сервером с xdrive (проверено на 26.10.21); нужен VLESS `encryption`; Xray-клиенту нужен `mux` | **Только нашим клиентам**, и только версиям с P9. В общей подписке у iOS будет мёртвая строка в группах | `-t` upstream — ok; `adapter/outbound/vless.go` v1.19.33, `StreamConnContext`, `default: // default tcp network`. Interop — BADVPN.md, P9 |
| XHTTP `mode: packet-up`, `uplink-http-method: GET`, `uplink-data-placement`, `sc-*` | Ключи upstream. У нас P5 (влито): до 8 запросов отправки в пути; P8 (PR #3): слот освобождается после отправки, окно 24 seq | Работает, но запросы отправки идут по одному с ожиданием ответа: через CDN отправка ~2–3 Мбит/с при RTT 150 мс | Совместимо (interop с Xray 26.3.27–26.10.21). Для GET на сервере нужен приём данных из заголовков и запас `serverMaxHeaderBytes` | Можно всем. Разница только в скорости отправки | `-t` upstream — ok; замеры и interop — BADVPN.md, P5 и P8 |
| `x-badvpn-ui` в группах (и в корне) | Ядро не читает, читают приложения (контракт v1/v1.1, `BPNclash/docs/badvpn/panel/ui-groups-contract.md`) | Игнор, в группах и в корне | — | Можно всем | `-t` upstream 32/33 — ok (карта в группе, карта в корне, скаляр на прокси); тот же вывод в контракте §3 для ядра приложения |

Ссылки `vless://`: в них этих ключей нет вообще. ПК, получив подписку-список ссылок, сам собирает прокси только из `type`, `sni`, `fp`, `pbk`, `sid`, `flow`, `encryption`, `path`, `host`, `mode`, `serviceName` (`crates/badvpn-common/src/mihomo_config.rs`, `build_vless_config_yaml`). Всё из этой таблицы, включая `support-x25519mlkem768`, работает только в YAML-подписке. YAML-подписку оба клиента передают в ядро без правки прокси (ПК подменяет корневые разделы — `tun`, `dns`, `rules` и т. п.; Android конфиг не трансформирует).

## Ключи только для конфига ноды на нашем ядре

В клиентскую подписку не класть: клиенту они не нужны. Обычный mihomo их пропускает **молча** — нода на обычном mihomo с таким конфигом запустится, но без защиты, лимитов и API.

| Ключ | Наше ядро | Обычный mihomo | Аналог в Xray | Чем подтверждено |
|---|---|---|---|---|
| `listeners[].fallback-page` | P14, PR #10. Файл вне безопасных путей или больше 1 МБ — inbound не стартует (при старте, не в `-t`) | Игнор: на чужой запрос — голый 404 / 400 | `fallbacks` (у Xray — пересылка на другой адрес, а не страница) | `-t` upstream — ok; `-t` P14 с несуществующим файлом — ok (проверка при старте, код `listener/fallback/`) |
| `listeners[].proxy-protocol`, `proxy-protocol-trusted` | P14, PR #10. На UDP/QUIC-типах — **ошибка конфига** | Игнор. За балансировщиком, который шлёт PROXY-заголовок, upstream примет заголовок за данные протокола — **соединения не пройдут** | `sockopt.acceptProxyProtocol` | `-t`: upstream — ok и на hysteria2; P14 на hysteria2 → `proxy-protocol: this listener type does not accept TCP streams` |
| `listeners[].xdrive-config` (vless без `port`) | P9, PR #4 | Игнор; что делает listener без `port` — не проверено | `xdriveSettings` | `-t` upstream — ok |
| `xray-api.listen` | P11, PR #6 | Игнор: gRPC API нет, панель не сможет добавлять пользователей | Xray API (`HandlerService`, `StatsService`) — совместимое подмножество | `-t` upstream — ok |
| `user-limits` (`max-conns`, `up-bps`, `down-bps`, `quota`, `expire-at`) | P11, PR #6 | Игнор: **лимитов нет** | Нет (лимиты обычно делает панель) | `-t` upstream — ok |
| `user-limits[].max-ips` | P18, PR #14 | Игнор: лимита нет | Нет встроенного; онлайн-IP через `GetStatsOnlineIpList` | `-t` upstream — ok |
| `metrics.enable`, `metrics.per-user`, `health-without-auth` | P16, PR #13 | Игнор: `/metrics`, `/healthz`, `/readyz`, `/events` нет | `metrics` у Xray устроен иначе | `-t` upstream — ok |
| `external-controller-allow-insecure` | P17, PR #12. Без него контроллер на сетевом адресе без `secret` не поднимается (ядро работает) | Игнор, контроллер открыт без пароля | — | `-t` upstream и P17 — ok (контроллер в `-t` не стартует); отказ — код `hub/route/security.go`, BADVPN.md P17 |

Проверка вида «`-t` прошёл» для нод на обычном mihomo ничего не гарантирует: проверяйте, что ключ реально подхвачен (API отвечает, `/metrics` есть).

## Что наше ядро делает иначе без всяких ключей

- **Версия REALITY-клиента**: 26.3.27 в выпущенных клиентах (P1/P3), 26.10.21 с P7; у обычного mihomo — 1.8.2. Ноды с `minClientVer` выше версии клиента его не пускают.
- **Пустой `client-fingerprint` у REALITY** → `chrome` (P1). У обычного mihomo — ошибка на каждом соединении.
- **Отпечатки `firefox` и `safari` новее** (P2): Firefox 148 / Safari 26.3 против Firefox 120 / Safari 16.0. ClientHello на проводе разный.
- **ML-KEM у REALITY**: без флага вырезается (P4, как upstream). На Android дополнительно P6: первое рукопожатие с сервером классическое, после провала — с ML-KEM, удачный вариант запоминается по серверу и ключу (в памяти процесса). Поэтому Android входит на Xray ≥ 26.9.8 без флага, со второго соединения; ПК и iOS — только с флагом.
- **XHTTP packet-up**: отправка идёт параллельно (P5; P8 — окно 24 seq, таймаут 120 с на запрос). Быстрее upstream при большом RTT, с Xray совместимо.
- **Только в открытых PR, в клиентах пока нет**: P13 — 15 с на приветствие у локальных mixed/http/socks и лимиты потоков на сервере; P10 — GC ballast 8 МиБ в сборках не для Android (ПК его получит); P12 — пакетная запись в relay; P17 — контроллер без `secret` только на loopback; P15 — сервер принимает mux.cool от Xray-клиентов.

## Как отличить наших клиентов по User-Agent

- Android, свои подписки (`BadVpnLinks.isOwnSubscriptionUrl`): `BadVPN/<версия приложения> (Android <версия>; mihomo/<x.y.z>)`, у debug — `BadVPN/<версия>-debug (…)` (`common/…/branding/BadVpnUserAgent.kt`). Версия ядра — без номера сборки `-bpn.N`, по ней набор патчей не понять; понять можно по версии приложения.
- ПК: `mihomo/1.19.24 BadVpn/0.1.0` (константа `SUBSCRIPTION_USER_AGENT`, `apps/badvpn-client/src-tauri/src/commands.rs`). Строка постоянная: ни версия приложения, ни реальная версия ядра в ней не меняются.
- Общий признак — подстрока `badvpn` без учёта регистра. Учтите, что на ПК строка начинается с `mihomo/`: правило, привязанное к началу строки (в PasarGuard правила подписки проверяются через `re.match`, то есть с начала), должно быть вида `(?i).*badvpn`. Правило `^mihomo` поймает и ПК.
- В обоих клиентах пользователь может задать свой User-Agent. Это способ выбрать формат, а не защита: на «чужой» ключ клиент всё равно должен реагировать безопасно.

## Правила для подписки

1. **Общая подписка должна целиком работать в обычном mihomo.** Всё, без чего у iOS прокси не подключится (xdrive), — только нашим клиентам по User-Agent или в отдельной подписке.
2. **Значения наших ключей проверять так же строго, как наше ядро**: одна опечатка в `mlkem-client-fingerprint`, `client-version` или сочетание `mux.cool` + vision роняет у наших клиентов весь профиль. Перед выкаткой шаблона — `mihomo -t` на сборке нашего ядра с нужными патчами и на upstream.
3. **Ключи открытых PR (P7, P9, P15) в подписку не добавлять, пока версия клиента с ними не выйдет.** До этого они либо ничего не делают, либо (xdrive) дают мёртвый прокси.
4. **REALITY: всегда явный `client-fingerprint`.** Пустой работает только у нас.
5. **Ноды на Xray ≥ 26.9.8**: `support-x25519mlkem768: true` и `client-fingerprint: chrome` — иначе не войдут iOS и ПК. **Ноды старше** — без флага (поломка 28.09; Xray 24.x с ML-KEM отбрасывает). Узнать версию ноды можно только у самой ноды: сервер её не сообщает.
6. **`minClientVer` на нодах не поднимать выше 26.3.27**, пока такие ноды нужны iOS (обычный mihomo шлёт 1.8.2 — с любым `minClientVer` выше он не войдёт) и пока наши клиенты не получили 26.10.21. Если подняли — в подписку `client-version` не ниже `minClientVer`, в кавычках. Xray 26.7.11–26.7.28 без `minClientVer` в конфиге уже требует 26.3.27: iOS на такие ноды не попадает.
7. **`mux.cool` — только у прокси без `flow: xtls-rprx-vision`** и только там, где у пользователя на ноде flow пустой.
8. **Наши ключи — только в YAML-подписке.** В ссылках `vless://` их нет, ПК из ссылок их не соберёт.
9. **`x-badvpn-ui` можно всем**: обычный mihomo его пропускает.
10. **Серверные ключи** (`xray-api`, `user-limits`, `metrics`, `fallback-page`, `proxy-protocol`, `external-controller-allow-insecure`) — только в конфиг ноды на нашем ядре, не в подписку.

## Как проверено

- Сборки в отдельной папке (`git archive`, рабочие копии не трогались), Windows amd64, Go 1.26: upstream `v1.19.32` (`88dcbf7f`) и `v1.19.33` (`3f27ef39`); форк `bpn/p7-reality` (`2de12fbf`, содержит P1–P7), `bpn/p9-xdrive` (`02a99106`), `bpn/p14-fallback-proxyproto` (`83186f65`), `bpn/p15-muxcool` (`1ce9ef60`), `bpn/p17-controller-hardening` (`a9a0fc0a`), `bpn/p18-user-ips` (`af237ab5`, содержит P11 и P16).
- Каждый ключ — отдельный файл с одним прокси / listener / корневым разделом, `mihomo -t -d <home> -f <файл>`. На upstream 32 и 33 результаты одинаковые: всё `test is successful`; контрольные `port: abc` и группа со ссылкой на несуществующий прокси — `test failed`.
- Xray: `minClientVer` — `infra/conf/transport_security.go` тегов v26.7.11, v26.7.28, v26.9.9, v26.9.30, v26.10.21; ML-KEM — модуль `github.com/xtls/reality` (`v0.0.0-20261014101318-83f621788ca8`), `tls.go`; mux и vision — `proxy/vless/inbound/inbound.go` в локальных исходниках Xray 26.5.9.
- Клиенты — код веток `main` (Android `3c9f6f5a`, ПК `d5ba416`) и свежих веток ПК.

Не проверено:

- Настоящие соединения обычного mihomo с нодами Xray по каждому случаю — выводы о проводе взяты из кода и из матриц в BADVPN.md (там клиентом был наш форк).
- iOS-приложения, которые разбирают YAML сами, а не через mihomo (Stash, Shadowrocket и т. п.), и iOS-клиенты на mihomo старше v1.19.32.
- Правило mux + vision в Xray новее 26.5.9.
- Как ведёт себя у upstream vless-listener без `port` (`xdrive-config`).
- Умеет ли панель BadVPN отдавать разные шаблоны по User-Agent: в PasarGuard upstream правило по User-Agent выбирает формат (`clash_meta`, `xray`, …), а не шаблон.
