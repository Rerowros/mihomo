# Серверная часть: Prizrak-Core, Citrus, Xray и этот форк

Коротко: **Xray-совместимого API для панелей нет ни у Prizrak-Core, ни у Citrus, ни у этого форка.** Панели, написанные под Xray (Marzban, PasarGuard, Remnawave, 3x-ui), управляют нодой через gRPC `HandlerService`/`StatsService`; mihomo-форки говорят только на своём REST. Всё остальное — насколько полно сервер умеет работать нодой — у форков разное.

## Матрица

| Возможность | Xray-core | Prizrak-Core `v1-19-33` | Citrus | Этот форк |
|---|---|---|---|---|
| Протоколы сервера | VLESS/VMess/Trojan/SS/WG/SOCKS/HTTP | mihomo-набор + native mux.cool server | mihomo-набор | mihomo-набор + xdrive |
| Xray gRPC API (`AddUser`/`RemoveUser`, `GetStats`/`QueryStats`) | **да** | нет | нет | **да** (`xray-api.listen`; VLESS-пользователи, без AddInbound) |
| Динамические пользователи без рестарта | да (gRPC) | нет (только reload конфига) | **да** (REST `/inbounds/{name}/users`) | **да** (gRPC + REST `/inbounds/{name}/users`) |
| Per-user трафик | да (`StatsService`) | нет | **да** (`/traffic/users`) | **да** (`/traffic/users`, TCP+UDP, gRPC stats) |
| Per-user лимиты: скорость, conns, IP, квота, expiry | нет в ядре (политики уровня) | нет | **да** (`/limits/users`) | скорость/conns/квота/expiry — да; IP — нет |
| Online IPs пользователя | через policy/панель | нет | да (`ips[]`) | нет (только число соединений) |
| Prometheus `/metrics` | нет | нет | **да** | нет |
| Push-события (`/events`) | нет | нет | **да** | нет |
| Pre-auth лимиты (XHTTP/QUIC/mux) | частично | частично | **да** (4096 сессий, 64 MiB, 15 с) | **частично** (4096 XHTTP-сессий, 15 с body) |
| Native mux.cool server | да | **да** (свой, XUDP, лимиты carrier) | через sing-mux | через sing-mux |
| HTTP/2 flow governor для XHTTP | в их форке Xray (`mux-ka`) | **да** (клиент) | нет | нет |
| REALITY fallback rate limit | да | да | да | **да** (уже было) |
| xdrive | **да** (26.10.10+) | нет | нет | **да** |
| Маленький буфер relay для idle-соединений | — | нет | **да** (−30 КБ/conn) | **да** (порт) |
| GC ballast для серверных сборок | — | нет | **да** (8 MiB) | **да** (порт) |
| Панельная интеграция «как Xray» | эталон | **нет** | нет (mihomo REST) | **нет** |

## Prizrak-Core

Серверная часть улучшена **на уровне протоколов**, а не панельного API:

- `transport/muxcool/` — нативный сервер mux.cool (stream + XUDP, лимиты carrier, ротация), совместимый с Xray-клиентами; раньше mihomo умел mux.cool только через sing-mux. Коммит `8ab053b1`.
- `transport/xhttp/h2flow*.go` — HTTP/2 flow governor: клиент показывает серверу маленькое окно (64 КБ), ограничивает `MAX_FRAME_SIZE` 16 КБ и измеряет RTT своим PING раз в секунду; сервер не заливает буферы быстрее, чем клиент читает. Включается `xhttp-opts.h2-flow`, по умолчанию выключен; синхронизирован с их форком Xray `mux-ka-24`. Коммиты `54a09e76`, `b0816f06`, далее sync-серия.
- `listener/reality` — `limit-fallback-upload/download` (лимит на неаутентифицированные fallback-соединения). У нас это уже есть.
- `adapter/outbound/freedom.go` + `component/sockopt` — DIRECT/freedom с TLS fragment и per-outbound sockopt (клиентская вещь, но полезная для ноды-релея).
- `component/smart` — LightGBM-выбор узлов (клиент).
- Панельного API (gRPC/StatsService/динамических пользователей) нет.

## Citrus

Серверная часть ближе всего к тому, что нужно панели, но в **mihomo REST**, не в Xray gRPC:

- `tunnel/statistic/{users,limits,units,metrics,manager,tracker}.go` — per-user up/down, conns, online IPs, скорость (GCRA), max-conns/max-ips, квота, expiry; проверка до dial, счёт байт на outbound-стороне.
- `listener/inbounduser/*`, `listener/inbound/users.go` — copy-on-write таблицы пользователей, атомарная замена, закрытие сессий удалённого пользователя; REST `/inbounds/{name}/users` (GET/PUT/POST/PATCH/DELETE) для 7 типов inbound.
- `hub/route/{users,limits,inbounds,events,metrics,rules,connections}.go` — `/traffic/users?reset=true`, `/limits/users`, `/metrics`, `/events`, `PUT /rules`, `DELETE /connections?inbound=&user=`.
- Pre-auth бюджеты: 4096 XHTTP-сессий, 30 с reaper, 15 с на тело, 64 MiB pending, лимиты QUIC/mux/ShadowQUIC, handshake deadline 15 с.
- Память/CPU: маленький буфер relay (−30 КБ heap на idle conn, −26% RSS REALITY), GC ballast 8 MiB, read-ahead batching (+50% upload, −35% CPU/GB), 64 КиБ чтения и совместные TLS-записи.
- Замеры Citrus: RSS/idle REALITY 5000 туннелей — 55.1 КиБ против 74.3 у mihomo и 68.1 у Xray; upload REALITY +52% к Xray; CPU/GB REALITY −35%; XHTTP upload −19%.
- Чего нет: gRPC, динамических inbound, per-user policy как Xray levels, персистентности, единого `email` на все inbound.

## Что теперь есть в этом форке

- **Per-user трафик**: `tunnel/statistic/users.go`, счётчики в TCP/UDP tracker, `GET /traffic/users?inbound=&user=&reset=true` (сброс периода как Xray `QueryStats`), поля `inbound,user,upload,download,conns,lastActive`. Считаются только пользователи inbound (DNS/dialer-proxy трекеры исключены), байты payload на outbound-стороне.
- **Xray gRPC API**: `hub/xrayapi/` — `HandlerService` (AlterInbound AddUser/RemoveUser, GetInboundUsers(+Count), ListInbounds) и `StatsService` (GetStats, QueryStats, GetUsersStats, GetStatsOnline(IpList), GetAllOnlineUsers, GetSysStats), имена `xray.*` и `v2ray.core.*`; gRPC поверх штатного HTTP/2 (h2c), без новых зависимостей. `xray api adu/rmu/lsi/inbounduser/stats/statsquery/statsonline` проверены против mihomo.
- **Динамические пользователи**: атомарная (copy-on-write) таблица VLESS в `listener/sing_vless`, `SetUsers` на живом listener, REST `/inbounds/{name}/users`; снятие пользователя закрывает его сессии (`Manager.CloseByUser`).
- **Per-user лимиты**: `tunnel/statistic/limits.go` — max-conns, up/down Bps (token bucket), квота upload+download, expiry; проверка до dial (TCP и UDP), расход в tracker; `user-limits:` и `/limits/users` (+ `reset-quota`).
- **Память idle-соединений**: `common/net/relay_copy.go` — маленький буфер 2 КиБ, пока соединение простаивает, полные буферы при передаче; `common/net/bufconn.go` — ленивый `bufio.Reader` (4 КиБ только при первом использовании); GC ballast 8 МиБ в серверных сборках (`component/gcballast`).
- **XHTTP**: cap 4096 неавторизованных сессий (503), 15 с на тело до download, reaper 30 с, быстрый путь карты сессий, окно seq 24, GET-uplink; P8.
- **Xdrive**: P9 (клиент + сервер, local/Google Drive/template).
- **REALITY**: версия 26.10.21 по умолчанию, адаптивный ML-KEM, `mlkem-client-fingerprint`; fallback rate limit уже был.
- **Relay-batching**: `common/net/relay_batch.go` (Citrus) — read-ahead 8 буферов, один `writev(2)` на пачку, yield каждые 256 КиБ/1 мс; включается только во время передачи.

## Чего не хватает (по приоритету для ноды 1–2 vCPU / 2 ГБ)

1. **Динамические inbound** — gRPC `AddInbound`/`RemoveInbound` не поддержаны: панель задаёт inbound в конфиге mihomo, через API меняются только пользователи (VLESS) и статистика.
2. **Per-user policy** — handshake/idle timeout, buffer size, sniffing override, как Xray `policy.levels`.
3. **Online IPs и лимит по IP** — хранится только число соединений, не адреса.
4. **Персистентность трафика** — сейчас всё in-memory; панель должна сама опрашивать `reset=true` и хранить итоги.
5. **h2-flow governor** (Prizrak) и **нативный mux.cool server** — полезны, но не панельная интеграция.
6. **Сертификаты/fallback** — автоматическая ротация уже есть через fswatch; отдельного ACME и nginx-fallback, как в Xray-гайдах, нет.

## Слабая нода: что включать

- Не включать TUN, `rule-providers`, geosite/geoip, если они не нужны: серверу достаточно `mode: rule` с `MATCH` на outbound/direct.
- `log-level: warning`, без debug; `external-controller` только с `secret` и на loopback/unix-сокете.
- `profile: {store-selected: false, store-fake-ip: false}` (если нет TUN), `find-process-mode: off`, `unified-delay: true`, `tcp-concurrent: true` по необходимости.
- `GOMEMLIMIT` под размер ноды (например 512MiB для 2 ГБ) — тогда GC ballast не включается, и память не растёт выше лимита; без лимита ballast даёт меньше циклов GC.
- XHTTP GET-uplink: на сервере обязательно `uplink-data-placement: header` и `uplink-data-key: X-Payload` (иначе payload в заголовках не читается); `sc-max-each-post-bytes` не больше лимита заголовков nginx/CDN; `sc-max-buffered-posts` 30.
- Для мобильных клиентов — XHTTP/HTTP2 или mux, чтобы не было пачки TLS-рукопожатий (детектор 3+ за 20–50 мс).
- REALITY fallback limit включать только осознанно: это дополнительный признак для DPI, значения лучше рандомизировать.

## Проверки

```sh
go test ./common/net/ ./tunnel/... ./transport/xhttp/ ./hub/route/
go test ./transport/xdrive/
XRAY_BINARY=/path/to/xray go test ./listener/inbound -run 'BPNXHTTPPacketUpXrayInterop|BPNXDriveXrayInterop'
```
