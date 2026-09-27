# BadVPN: патчи поверх mihomo

Эта ветка (`bpn/<тег mihomo>`) — ядро mihomo для Android-клиента BadVPN. Это тег upstream [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) плюс небольшой набор патчей ниже. Больше ничего не меняется.

*English summary: MetaCubeX/mihomo tag + a small patch set for REALITY compatibility with current Xray-core (client version 26.3.27, keep ML-KEM key share, empty fingerprint → chrome, optional `reality-opts.client-version`) and metacubex/utls `v1.9.0-mod-meta` (Firefox 148 / Safari 26.3). Not affiliated with MetaCubeX; please do not report issues from this build upstream.*

- Upstream: `MetaCubeX/mihomo`, тег **v1.19.31** (`ab405bad`).
- Ветка: `bpn/v1.19.31`. Коммиты патчей: `v1.19.31..bpn/v1.19.31`.
- Список патчей совпадает с реестром приложения `docs/core-patches.md` (AGENTS.md §11). ID те же. При изменении правятся оба файла.

## Патчи

| # | Что меняет | Зачем | Файлы | Источник / автор / лицензия | С версии mihomo | Проверка | Когда убрать |
|---|---|---|---|---|---|---|---|
| **P1** | REALITY-клиент шлёт в session ID версию **26.3.27** вместо 1.8.2. Не вырезает X25519MLKEM768 из отпечатка: опция `support-x25519mlkem768` устарела и игнорируется, для старых серверов есть `chrome120`/`firefox120`/`safari16`. Пустой `client-fingerprint` у REALITY → `chrome` (раньше была ошибка). Заодно в серверной части (listener REALITY) `max-time-difference` считается в миллисекундах, а не в микросекундах; приложение listener не использует | Совместимость с Xray ≥ 26.7.11 (умолчание `minClientVer` 26.3.27) и ≥ 26.9.8 (обязателен X25519MLKEM768 раньше X25519, [XTLS/REALITY 8cdf7bf](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8)). Upstream отказался: [#2967](https://github.com/MetaCubeX/mihomo/issues/2967), [#3132](https://github.com/MetaCubeX/mihomo/issues/3132), [#3193](https://github.com/MetaCubeX/mihomo/issues/3193), [PR #3070](https://github.com/MetaCubeX/mihomo/pull/3070) | `component/tls/reality.go`, `adapter/outbound/reality.go`, `transport/vmess/tls.go`, `listener/reality/reality.go` + тесты | cherry-pick `84cc2c17` ← [legiz-ru/Prizrak-Core `2197a3c`](https://github.com/legiz-ru/Prizrak-Core/commit/2197a3cac1e960987e3844a638a281509bb265ae), автор Jolymmiles (авторство в git сохранено), GPL-3.0 | v1.19.31 | `component/tls/reality_test.go`, `transport/vmess/tls_test.go`, `listener/reality/reality_test.go`; interop с настоящим Xray: `TestVLESSRealityXrayInterop`, `TestBPNRealityXrayMatrix` (см. ниже) | Когда upstream mihomo сам начнёт слать актуальную версию и перестанет вырезать ML-KEM. Или когда у BadVPN не останется REALITY-нод |
| **P2** | `github.com/metacubex/utls` v1.8.7 → голова ветки `v1.9.0-mod-meta` (`v0.0.0-20260924074610-04010625d68b`). Отпечатки: `firefox` Firefox 120 → **148**, `safari` Safari 16.0 → **26.3**, оба с X25519MLKEM768. `chrome` (133), `edge` (85), `ios` (14), `android` (OkHttp 11) не менялись. Кода mihomo правка не требует | Свежие отпечатки, те же, что у Xray ≥ 26.3.27. Без них `firefox` на Xray ≥ 26.9.8 не проходит (нет ML-KEM). У BadVPN tcp+REALITY-хосты с `firefox`. Upstream ждёт релиза uTLS 1.9.0 ([#3193](https://github.com/MetaCubeX/mihomo/issues/3193)) | `go.mod`, `go.sum` | коммит `28e9ea26` (свой). Код utls: [metacubex/utls@v1.9.0-mod-meta](https://github.com/metacubex/utls/tree/v1.9.0-mod-meta) (wwqgtxx и др.), BSD-3-Clause | v1.19.31 | `TestBPNFingerprintVersions` (firefox = 148, safari = 26.3), `TestBPNRealityKeepsMLKEMKeyShare`, interop-матрица | Когда upstream mihomo поднимет utls до версии с Firefox 148 / Safari 26.3 |
| **P3** | Необязательное поле `reality-opts.client-version: "x.y.z"` для каждого прокси. Версия по умолчанию задана в одном месте: `tlsC.DefaultRealityClientVersion` = 26.3.27. Значение `0.0.0` означает умолчание | Если на ноде задан `minClientVer` выше 26.3.27, версию можно поднять без пересборки ядра (через шаблон подписки) | `component/tls/reality.go`, `adapter/outbound/reality.go` + `*_bpn_test.go` | коммит `48d461ce` (свой, GPL-3.0 как mihomo). Идея — закрытый upstream [PR #3069](https://github.com/MetaCubeX/mihomo/pull/3069) | v1.19.31 | `TestBPNRealityDefaultClientVersion`, `TestBPNRealityClientVersionOverride`, `TestBPNParseRealityClientVersion`, `TestBPNRealityOptionsClientVersion` | Вместе с P1 |

Только тесты, поведение не меняют: `ad4c3f42` — `listener/inbound/bpn_reality_xray_matrix_test.go`.

### Важно для потребителя: версия utls (P2)

Псевдоверсия `v0.0.0-2026…` по semver **меньше** `v1.8.7`. Если в главном модуле сборки (у приложения это `core/src/main/golang` и `core/src/foss/golang`) остаётся `github.com/metacubex/utls v1.8.7`, Go MVS молча выберет v1.8.7, и P2 не применится. Главный модуль должен закрепить версию:

```
replace github.com/metacubex/utls => github.com/metacubex/utls v0.0.0-20260924074610-04010625d68b
```

`replace` в `go.mod` самого mihomo на главный модуль не действует. Проверка: `go list -m github.com/metacubex/utls` в модуле приложения должен показать псевдоверсию.

## Проверка

```sh
go build ./...
go test ./component/tls/... ./adapter/outbound/... ./transport/... ./listener/reality/...
go test ./...   # listener/inbound идёт ~2-3 мин и качает v2ray-core для своих interop-тестов
```

Interop с настоящим Xray, без интернета и без реальных серверов. Xray REALITY-сервер поднимается на 127.0.0.1, target — локальный TLS-сервер:

```sh
# бинарь Xray: https://github.com/XTLS/Xray-core/releases, sha256 сверять с .dgst
XRAY_BINARY=/path/to/xray go test ./listener/inbound -run 'BPNRealityXrayMatrix|VLESSRealityXrayInterop' -v -count=1
```

Результат на `bpn/v1.19.31` (28.09.2026, Windows amd64, VLESS tcp + REALITY, без `minClientVer`):

| Клиент | Xray 26.3.27 | Xray 26.7.28 | Xray 26.9.9 |
|---|---|---|---|
| bpn: chrome / firefox / safari | ok / ok / ok | ok / ok / ok | ok / ok / ok |
| bpn: пустой fingerprint (→ chrome) | ok | ok | ok |
| bpn: edge (Edge 85, без ML-KEM) | ok | ok | **fail** (ожидаемо) |
| upstream v1.19.31: chrome / firefox / safari | ok / ok / ok | fail / fail / fail | fail / fail / fail |
| upstream v1.19.31: chrome + `support-x25519mlkem768: true` | ok | fail | ok |
| upstream v1.19.31: firefox + `support-x25519mlkem768: true` | ok | fail | fail |
| upstream v1.19.31: пустой fingerprint | fail («please set a client-fingerprint») | fail | fail |
| upstream v1.19.31: edge | ok | fail | fail |

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
5. Перенести P1–P3 в `docs/core-patches.md` в «Действующие» с хешами этой ветки.

## Лицензии и атрибуция

- mihomo — GPL-3.0 (`LICENSE` в корне; код и теги — ветки Alpha/Meta upstream). Форк публичный, исходники всех патчей открыты, что покрывает требование GPL для распространяемой `libclash.so`.
- P1 взят из [legiz-ru/Prizrak-Core](https://github.com/legiz-ru/Prizrak-Core) (GPL-3.0, форк mihomo). Автор — Jolymmiles (`jesus <valmak29@gmail.com>`), сохранён как author коммита, в сообщении есть `(cherry picked from commit 2197a3c…)`.
- utls — BSD-3-Clause (The Go Authors, refraction-networking, metacubex). Лицензия идёт с модулем.
- Этот форк не связан с MetaCubeX и XTLS. Проблемы этой сборки в upstream не сообщаем.
