<p align="center">
  <img src="docs/veles/hero.svg" alt="Veles: ядро на базе Mihomo. 19 патчей, 148 коммитов поверх v1.19.33, лицензия GPL-3.0" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Rerowros/veles/tree/v1.19.34-veles.1"><img src="https://img.shields.io/badge/версия-v1.19.34--veles.1-a85f00?style=flat-square" alt="Версия v1.19.34-veles.1"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/лицензия-GPL--3.0-23291f?style=flat-square" alt="Лицензия GPL-3.0"></a>
  <a href="https://github.com/MetaCubeX/mihomo"><img src="https://img.shields.io/badge/основа-Mihomo-5d6455?style=flat-square" alt="Основа: Mihomo"></a>
</p>

**Veles** — форк [Mihomo](https://github.com/MetaCubeX/mihomo), ядро приложения BadVPN. Формат конфига тот же, что у Mihomo, а сверху добавлены три вещи: REALITY, который подключается к новым серверам Xray, быстрая отправка по XHTTP и серверная часть для нод.

*English: Veles is a Mihomo fork. Same configs, plus REALITY that works with current Xray servers, faster XHTTP upload and server-side features for nodes. Patch details are in [BADVPN.md](BADVPN.md), in Russian.*

## Чем отличается

<img src="docs/veles/reality-matrix.svg" alt="С настройками по умолчанию Mihomo v1.19.31 подключается только к Xray 26.3.27 и только с отпечатком. Veles подключается ко всем трём версиям Xray, к 26.9.9 со второго соединения." width="100%">

<img src="docs/veles/xhttp-upload.svg" alt="Отправка по XHTTP на тестовом сервере: без патчей 3,4 Мбит/с, Veles 13,2 Мбит/с с интервалом 30 мс и 54,9 Мбит/с без интервала." width="100%">

<img src="docs/veles/patch-map.svg" alt="19 патчей поверх Mihomo v1.19.33: маскировка, транспорт и скорость, серверная часть." width="100%">

## Сравнение с другими ядрами

| | Veles | Mihomo v1.19.33 | Xray-core 26.10.31 |
|---|---|---|---|
| Конфиг в формате Clash, правила и группы | ✓ | ✓ | ✕ свой формат |
| TUIC, AnyTLS, Mieru | ✓ | ✓ | ✕ |
| Hysteria 2, MASQUE | ✓ | ✓ | ✓ |
| Версия клиента в REALITY | 26.11.9, настраивается | 1.8.2, не настраивается | своя |
| Подбор ML-KEM под сервер | ✓ сам | ✕ только вручную | не проверяли |
| Xray Mux: mux.cool и XUDP | ✓ | ✕ | ✓ |
| Транспорт xdrive | ✓ | ✕ | ✓ |
| gRPC API, совместимый с Xray | ✓ | ✕ | ✓ |
| Нарезка ClientHello | ✓ для каждого прокси | ✕ | не проверяли |
| `/metrics` для Prometheus | ✓ | ✕ | не проверяли |
| Лимит IP на пользователя | ✓ | ✕ | не проверяли |

Сравнение составлено по исходному коду этих версий. sing-box в таблицу не вошёл: его мы не проверяли.

## Запуск

```sh
go build -trimpath -ldflags "-s -w" -o veles .
./veles -v
./veles -d ./config-dir -f config.yaml
```

Настройки те же, что у Mihomo: [документация Mihomo](https://wiki.metacubex.one). Ключи, которые есть только здесь, описаны в [COMPAT.md](COMPAT.md).

Два отличия от Mihomo, о которых стоит знать заранее:

- без `secret` контроллер на сетевом адресе не запустится. Обойти можно настройкой `external-controller-allow-insecure`;
- неподдерживаемые или конфликтные значения ключей прокси Veles (`fragment-opts`, `mux.cool`, `mlkem-client-fingerprint`, `client-version`) не роняют профиль, а пропускаются с предупреждением в лог (как в оригинальном Mihomo); строгая проверка оставлена только у серверных лимитов `user-limits` и `proxy-protocol`.

Для совместимости оставлены:

- `User-Agent: clash.meta/…`: по нему панели понимают, какой конфиг отдавать;
- путь модуля `github.com/metacubex/mihomo`: так проще переносить новые версии Mihomo.

## Документы

| Файл | Что внутри |
|---|---|
| [BADVPN.md](BADVPN.md) | Все патчи, замеры, как проверять и как переносить на новую версию |
| [COMPAT.md](COMPAT.md) | Чем ключи Veles отличаются для Mihomo и Xray |

## Авторы и лицензия

Veles выпускается под лицензией [GPL-3.0](LICENSE), как и Mihomo. Проект не связан с MetaCubeX и XTLS, ошибки этой сборки направляйте сюда, а не авторам Mihomo.

Спасибо проектам, код которых здесь использован:

- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo): основа ядра;
- [legiz-ru/Prizrak-Core](https://github.com/legiz-ru/Prizrak-Core): P1 и P15;
- [Nemu-x/ClashFest](https://github.com/Nemu-x/ClashFest): идея P6;
- [getmikan/Citrus](https://github.com/getmikan/Citrus): P12, P13, P14, P16 и P17;
- [refraction-networking/utls](https://github.com/refraction-networking/utls) и [metacubex/utls](https://github.com/metacubex/utls): отпечатки TLS.
