#!/usr/bin/env python3
"""Draw charts/*.png from data/*.csv and refresh the generated tables in README.md.

Usage: python tools/charts.py

Every number on a chart, in a chart title and in the README tables comes from
data/runs.csv (medians over repeats) or data/attack_samples.csv. For each netem
profile the newest run that has it is used; an old profile version (v1) is shown
only while no v2 run of the same profile exists, and is labelled "v1".
"""

import csv
import os
import re
import textwrap
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
CHARTS = os.path.join(ROOT, "charts")
README = os.path.join(ROOT, "README.md")

PROFILE_ORDER = ["good", "mobile", "bad", "far"]
COLORS = {"U": "#9e9e9e", "R": "#64b5f6", "B": "#1565c0", "XC": "#ef6c00",
          "A": "#9e9e9e", "X": "#ef6c00", "S2X": "#2e7d32"}
NAMES = {"U": "U upstream", "R": "R приложение", "B": "B все PR", "XC": "XC Xray"}

plt.rcParams.update({
    "figure.dpi": 150, "font.size": 11, "axes.titlesize": 11, "axes.labelsize": 10,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.alpha": 0.25, "axes.axisbelow": True, "figure.facecolor": "white",
})


def load(name):
    with open(os.path.join(DATA, name), newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


RUNS = load("runs.csv")
SAMPLES = load("attack_samples.csv")
MED = {}
for r in RUNS:
    if r["repeat"] == "median":
        MED[(r["run"], r["kind"], r["profile"], r["scenario"], r["client"], r["server"],
             r["variant"], r["metric"])] = (float(r["value"]), int(r["n"]), r["profile_ver"])


def netem_profiles():
    """[(profile, version, run)] newest run per profile; v1 only if no v2."""
    best = {}
    for (run, kind, prof, *_), (_, _, ver) in MED.items():
        if kind != "netem":
            continue
        key = (prof, ver)
        if key not in best or run > best[key]:
            best[key] = run
    out = []
    for (prof, ver), run in best.items():
        if ver == "v1" and (prof, "v2") in best:
            continue
        out.append((prof, ver, run))
    order = {p: i for i, p in enumerate(PROFILE_ORDER)}
    return sorted(out, key=lambda x: (order.get(x[0], 99), x[1]))


PROFILES = netem_profiles()


def nm(prof, sc, client, metric):
    """Netem median for the profile as chosen in PROFILES: (value, n) or None."""
    for p, ver, run in PROFILES:
        if p == prof:
            v = MED.get((run, "netem", p, sc, client, "X", "", metric))
            return (v[0], v[1]) if v else None
    return None


def plabel(prof):
    for p, ver, run in PROFILES:
        if p == prof:
            return p + (" (v1)" if ver == "v1" else "")
    return prof


def num(v, digits=None):
    if v is None:
        return "—"
    if digits is None:
        digits = 0 if abs(v) >= 100 else (1 if abs(v) >= 10 else 2)
    return f"{v:.{digits}f}".replace(".", ",")


def bar_label(ax, rect, value, n):
    txt = num(value) + ("" if n is None or n >= 3 else f"\nn={n}")
    ax.annotate(txt, (rect.get_x() + rect.get_width() / 2, rect.get_height()),
                ha="center", va="bottom", fontsize=8, xytext=(0, 2), textcoords="offset points")


def profile_grid(fname, title, bars, rows, baseline=None, note=None):
    """One column per profile, one row per metric; bars = [(label, sc, client, color)].

    rows = [(metric, axis label, scale)]; baseline = {metric: (sc, client)} draws
    the bare-link value as a dashed line."""
    profs = [p for p, _, _ in PROFILES]
    fig, axes = plt.subplots(len(rows), len(profs), figsize=(3.0 * len(profs) + 0.6,
                                                              2.9 * len(rows) + 1.0),
                             squeeze=False)
    for i, (metric, ylabel, scale) in enumerate(rows):
        for j, prof in enumerate(profs):
            ax = axes[i][j]
            xs = range(len(bars))
            for x, (lab, sc, cl, color) in zip(xs, bars):
                v = nm(prof, sc, cl, metric)
                if v is None:
                    ax.text(x, 0, "нет\nданных", ha="center", va="bottom", fontsize=7,
                            color="#757575")
                    continue
                rect = ax.bar(x, v[0] * scale, color=color, width=0.7)[0]
                bar_label(ax, rect, v[0] * scale, v[1])
            if baseline and metric in baseline:
                b = nm(prof, *baseline[metric], metric)
                if b:
                    ax.axhline(b[0] * scale, color="#424242", ls="--", lw=1)
            ax.set_xticks(list(xs))
            ax.set_xticklabels([b[0] for b in bars], fontsize=8)
            ax.margins(y=0.18)
            if j == 0:
                ax.set_ylabel(ylabel)
            if i == 0:
                ax.set_title(plabel(prof), fontsize=10, color="#424242")
    fig.suptitle(textwrap.fill(title, 78), fontsize=12, fontweight="bold")
    if baseline:
        note = "Пунктир — та же сеть без прокси. " + (note or "")
    if note:
        fig.text(0.01, 0.005, textwrap.fill(note, 150), fontsize=7.5, color="#616161", va="bottom")
    fig.tight_layout(rect=(0, 0.03 if note else 0, 1, 0.95))
    fig.savefig(os.path.join(CHARTS, fname))
    plt.close(fig)
    print(f"charts/{fname}: {title}")
    return title


def val(prof, sc, client, metric, scale=1.0):
    v = nm(prof, sc, client, metric)
    return None if v is None else v[0] * scale


V1_NOTE = ("v1 = старый профиль: mobile с jitter (TCP видит перестановку пакетов как потери), "
           "bad с 3 % потерь на сторону; не сравнивать с v2. n<3 — меньше трёх повторов.")


# ---------------------------------------------------------------- (a) P8 xhttp
def chart_p8():
    g = lambda c, m, s=1.0: val("good", "S2", c, m, s)  # noqa: E731
    title = (f"xhttp: с P8 (B) пинг {num(g('B', 'ping_us.p50', 1e-3))} мс как у Xray "
             f"({num(g('XC', 'ping_us.p50', 1e-3))}), у upstream {num(g('U', 'ping_us.p50', 1e-3))}; "
             f"отдача {num(g('B', 'upload_1.mbps'))} против {num(g('U', 'upload_1.mbps'))} Мбит/с")
    return profile_grid(
        "p8-xhttp.png", title,
        [(c, "S2", c, COLORS[c]) for c in ("U", "R", "B", "XC")],
        [("ping_us.p50", "пинг p50, мс", 1e-3), ("upload_1.mbps", "отдача, 1 поток, Мбит/с", 1)],
        baseline={"ping_us.p50": ("NET", "-"), "upload_1.mbps": ("NET", "-")}, note=V1_NOTE)


# ---------------------------------------------------------------- (b) xmux
def chart_xmux():
    b, x = val("good", "S2", "B", "connect_ms.p50"), val("good", "S2", "XC", "connect_ms.p50")
    bx = val("good", "S2X", "B", "connect_ms.p50")
    if bx is None:
        title = (f"Новое xhttp-соединение: Xray {num(x)} мс, B {num(b)} мс — Xray переиспользует "
                 f"соединения (xmux); S2X ещё не замерен")
    else:
        title = (f"xmux = настройка подписки: B с reuse-settings {num(bx)} мс против {num(b)} мс "
                 f"без них, Xray {num(x)} мс")
    return profile_grid(
        "xmux-connect.png", title,
        [("B\nS2", "S2", "B", COLORS["B"]), ("B\nS2X", "S2X", "B", COLORS["S2X"]),
         ("XC\nS2", "S2", "XC", COLORS["XC"]), ("XC\nS2X", "S2X", "XC", "#ffb74d")],
        [("connect_ms.p50", "новое соединение p50, мс", 1)],
        baseline={"connect_ms.p50": ("NET", "-")},
        note="S2 = REALITY + xhttp packet-up; S2X = то же + reuse-settings (как умолчание Xray). "
             + V1_NOTE)


# ---------------------------------------------------------------- (c) mux.cool
def chart_mux():
    u, b = val("good", "S3M", "U", "connect_ms.p50"), val("good", "S3M", "B", "connect_ms.p50")
    worst = None
    for p, _, _ in PROFILES:
        bu, bb = val(p, "S3M", "U", "download_8.mbps"), val(p, "S3M", "B", "download_8.mbps")
        nb = nm(p, "S3M", "B", "download_8.mbps")
        if bu and bb and nb[1] >= 3 and (worst is None or bb / bu < worst[1] / worst[2]):
            worst = (p, bb, bu)
    title = f"mux.cool (P15): новое соединение {num(b)} мс вместо {num(u)}"
    if worst:
        title += (f"; цена — 8 потоков в одном TCP: {num(worst[1])} против {num(worst[2])} "
                  f"Мбит/с на {plabel(worst[0])}")
    return profile_grid(
        "mux-cool.png", title,
        [("U\nбез mux", "S3M", "U", COLORS["U"]), ("R\nбез mux", "S3M", "R", COLORS["R"]),
         ("B\nmux", "S3M", "B", COLORS["B"]), ("XC\nmux", "S3M", "XC", COLORS["XC"])],
        [("connect_ms.p50", "новое соединение p50, мс", 1),
         ("download_8.mbps", "загрузка, 8 потоков, Мбит/с", 1)],
        baseline={"connect_ms.p50": ("NET", "-"), "download_8.mbps": ("NET", "-")},
        note="У U и R mux.cool нет — это обычные соединения. " + V1_NOTE)


# ---------------------------------------------------------------- (d) REALITY control
def chart_control():
    vals = [val("good", "S1", c, "download_1.mbps") for c in ("U", "R", "B", "XC")]
    vals = [v for v in vals if v is not None]
    title = (f"REALITY + vision (контроль): все клиенты равны — "
             f"{num(min(vals))}–{num(max(vals))} Мбит/с на good")
    return profile_grid(
        "reality-control.png", title,
        [(c, "S1", c, COLORS[c]) for c in ("U", "R", "B", "XC")],
        [("download_1.mbps", "загрузка, 1 поток, Мбит/с", 1),
         ("connect_ms.p50", "новое соединение p50, мс", 1)],
        baseline={"download_1.mbps": ("NET", "-"), "connect_ms.p50": ("NET", "-")},
        note=V1_NOTE)


# ---------------------------------------------------------------- (e) P13 attack
def attack_run():
    runs = sorted({s["run"] for s in SAMPLES})
    return runs[-1] if runs else None


def attack_metric(run, srv, sc, variant, metric):
    v = MED.get((run, "attack", "good", sc, "attacker", srv, variant, "attack." + metric))
    if v is None:  # profile name may differ; search
        for k, vv in MED.items():
            if k[0] == run and k[3:] == (sc, "attacker", srv, variant, "attack." + metric):
                return vv[0]
        return None
    return v[0]


def chart_attack():
    run = attack_run()
    panels = [("SAT", "silent-2000", "SAT: 2000 молчащих после TLS"),
              ("SAT", "silent-5000", "SAT: 5000 молчащих после TLS"),
              ("SAT", "leak-200x5", "SAT: утечка, +200 каждые 5 с"),
              ("SATX", "silent-2000", "SATX (xhttp): 2000 молчащих")]
    fig, axes = plt.subplots(2, 2, figsize=(9.6, 7.4), squeeze=False)
    for ax, (sc, var, sub) in zip([a for row in axes for a in row], panels):
        for srv, lab, col in (("A", "A без P13", COLORS["A"]), ("B", "B с P13", COLORS["B"])):
            pts = [(float(s["t"]), int(s["alive"])) for s in SAMPLES
                   if s["run"] == run and s["server"] == srv and s["scenario"] == sc
                   and s["variant"] == var]
            if not pts:
                continue
            end = attack_metric(run, srv, sc, var, "alive_end")
            ax.plot([p[0] for p in pts], [p[1] for p in pts], color=col, lw=2.2 if srv == "B" else 2,
                    ls="-" if srv == "B" else "--",
                    label=f"{lab}: в конце {num(end, 0)}")
        ax.set_title(sub, fontsize=10, color="#424242")
        ax.set_xlabel("время, с")
        ax.set_ylabel("соединений держит сервер")
        ax.set_ylim(bottom=0)
        ax.legend(fontsize=8, loc="upper right", frameon=False)
    a2 = attack_metric(run, "A", "SAT", "silent-2000", "alive_end")
    b2 = attack_metric(run, "B", "SAT", "silent-2000", "alive_end")
    al = attack_metric(run, "A", "SAT", "leak-200x5", "alive_end")
    bl = attack_metric(run, "B", "SAT", "leak-200x5", "alive_end")
    pts = [(float(s["t"]), int(s["alive"])) for s in SAMPLES if s["run"] == run
           and s["server"] == "B" and s["scenario"] == "SAT" and s["variant"] == "silent-2000"]
    peak_t = next((t for t, a in pts if a == max(a for _, a in pts)), 0)
    zero_t = next((t for t, a in pts if t > peak_t and a == 0), None)
    title = (f"P13: без него сервер держит молчащие соединения до конца ({num(a2, 0)} из 2000, "
             f"утечка {num(al, 0)}), с ним сбрасывает их за {num(zero_t - peak_t, 0)} с "
             f"({num(b2, 0)}; утечка стоит на {num(bl, 0)})")
    fig.suptitle(textwrap.fill(title, 78), fontsize=12, fontweight="bold")
    fig.text(0.01, 0.005, "Атака держится ~65 с (утечка — 180 с), потом атакующий закрывает "
             "соединения. В конце = alive_end, на момент конца удержания. Профиль good.",
             fontsize=7.5, color="#616161")
    fig.tight_layout(rect=(0, 0.03, 1, 0.93))
    fig.savefig(os.path.join(CHARTS, "p13-attack.png"))
    plt.close(fig)
    print(f"charts/p13-attack.png: {title}")
    return title


# ---------------------------------------------------------------- (f) loopback cost
def lb(srv, sc, metric):
    runs = sorted({k[0] for k in MED if k[1] == "loopback"})
    for run in reversed(runs):
        v = MED.get((run, "loopback", "loopback", sc, "B", srv, "", metric))
        if v:
            return v
    return None


def chart_loopback():
    rows = [("download_8.server.cpu_s_per_gbit", "CPU сервера, с на Гбит\n(загрузка, 8 потоков)", 1),
            ("load.1000.server.rss_peak_mb", "память сервера, МБ\n(1000 соединений)", 1)]
    scens = [("S1", "REALITY + vision"), ("S2", "REALITY + xhttp")]
    servers = [("A", "A база"), ("B", "B все PR"), ("X", "X Xray")]
    fig, axes = plt.subplots(len(rows), len(scens), figsize=(8.4, 6.8), squeeze=False)
    for i, (metric, ylabel, _) in enumerate(rows):
        for j, (sc, sub) in enumerate(scens):
            ax = axes[i][j]
            for x, (srv, lab) in enumerate(servers):
                v = lb(srv, sc, metric)
                if v is None:
                    continue
                rect = ax.bar(x, v[0], color=COLORS[srv], width=0.65)[0]
                bar_label(ax, rect, v[0], v[1])
            ax.set_xticks(range(len(servers)))
            ax.set_xticklabels([s[1] for s in servers], fontsize=8)
            ax.margins(y=0.18)
            if j == 0:
                ax.set_ylabel(ylabel)
            if i == 0:
                ax.set_title(sub, fontsize=10, color="#424242")
    ra, rb = lb("A", "S1", rows[1][0]), lb("B", "S1", rows[1][0])
    ca, cb = lb("A", "S1", rows[0][0]), lb("B", "S1", rows[0][0])
    title = (f"Сервер на ПК (loopback): CPU у B как у A ({num(cb[0])} и {num(ca[0])} с/Гбит), "
             f"памяти под 1000 соединений меньше ({num(rb[0])} против {num(ra[0])} МБ)")
    fig.suptitle(textwrap.fill(title, 78), fontsize=12, fontweight="bold")
    fig.text(0.01, 0.005, "Всё на 127.0.0.1 одного ПК (16 потоков), клиент — mihomo B. "
             "Это стоимость CPU и памяти, а не скорость сети.", fontsize=7.5, color="#616161")
    fig.tight_layout(rect=(0, 0.03, 1, 0.92))
    fig.savefig(os.path.join(CHARTS, "loopback-cost.png"))
    plt.close(fig)
    print(f"charts/loopback-cost.png: {title}")
    return title


# ---------------------------------------------------------------- README tables
def cell(prof, sc, client, metric, scale=1.0):
    v = nm(prof, sc, client, metric)
    if v is None:
        return "—"
    return num(v[0] * scale) + ("" if v[1] >= 3 else f" (n={v[1]})")


CLIENT_ROWS = [
    # patch, what, scenario, metric, scale, profiles, verdict
    ("P8 xhttp", "пинг p50, мс", "S2", "ping_us.p50", 1e-3, None,
     "доказано: B = Xray, U и R хуже"),
    ("P8 xhttp", "отдача 1 поток, Мбит/с", "S2", "upload_1.mbps", 1, ["good"],
     "доказано на good; на mobile/bad упор в канал"),
    ("P8 xhttp", "новое соединение p50, мс", "S2", "connect_ms.p50", 1, None,
     "лучше U/R; Xray быстрее за счёт xmux — см. строку ниже"),
    ("xmux (S2X)", "новое соединение p50, мс", "S2X", "connect_ms.p50", 1, None,
     "ждёт прогона 2"),
    ("P15 mux.cool", "новое соединение p50, мс", "S3M", "connect_ms.p50", 1, None,
     "доказано: B = Xray, быстрее U и R"),
    ("P15 mux.cool", "загрузка 8 потоков, Мбит/с", "S3M", "download_8.mbps", 1, None,
     "цена: все потоки в одном TCP; у Xray так же"),
    ("P1–P6 (R)", "REALITY+vision, загрузка 1 поток, Мбит/с", "S1", "download_1.mbps", 1, None,
     "контроль: все равны, патчи не мешают"),
]


def client_table():
    out = ["| Патч | Что меряем | Профиль | U upstream | R приложение | B все PR | XC Xray | Вывод |",
           "|---|---|---|---|---|---|---|---|"]
    for patch, what, sc, metric, scale, profs, verdict in CLIENT_ROWS:
        for k, (p, _, _) in enumerate(PROFILES):
            if profs and p not in profs:
                continue
            cells = [cell(p, sc, c, metric, scale) for c in ("U", "R", "B", "XC")]
            if all(c == "—" for c in cells):  # not measured in any shown profile yet
                if all(cell(q, sc, c, metric) == "—" for q, _, _ in PROFILES
                       for c in ("U", "R", "B", "XC")):
                    out.append(f"| {patch} | {what} ({sc}) | все | — | — | — | — | {verdict} |")
                    break
                continue
            out.append(f"| {patch} | {what} ({sc}) | {plabel(p)} | " + " | ".join(cells) +
                       f" | {verdict if (k == 0 or profs) else '〃'} |")
    return "\n".join(out)


SERVER_ROWS = [
    ("P13", "SAT", "silent-2000", "alive_end", "2000 молчащих после TLS: держит в конце",
     "доказано"),
    ("P13", "SAT", "silent-5000", "alive_end", "5000 молчащих после TLS: держит в конце",
     "доказано"),
    ("P13", "SAT", "leak-200x5", "alive_end", "утечка +200/5 с, 180 с: держит в конце",
     "доказано: без P13 растёт без предела"),
    ("P13", "SAT", "silent-5000", "rss_peak_mb", "5000 молчащих: пик памяти, МБ",
     "разницы нет — P13 рвёт, а не экономит"),
    ("P13", "SATX", "silent-2000", "alive_end", "xhttp, 2000 молчащих: держит в конце",
     "не доказано: A тоже сбрасывает"),
    ("P13", "SATX", "leak-200x5", "alive_end", "xhttp, утечка: держит в конце",
     "не доказано: одинаково"),
    ("P13", "SAT", "byte-2000", "established_peak", "по байту: пик соединений",
     "неинформативно: оба сервера рвут сразу"),
]


def server_table():
    run = attack_run()
    out = ["| Патч | Сценарий | Что меряем | A без P13 | B с P13 | Вывод |", "|---|---|---|---|---|---|"]
    for patch, sc, var, metric, what, verdict in SERVER_ROWS:
        a = attack_metric(run, "A", sc, var, metric)
        b = attack_metric(run, "B", sc, var, metric)
        out.append(f"| {patch} | {sc} {var} | {what} | {num(a, 0)} | {num(b, 0)} | {verdict} |")
    # honest client latency under the heaviest attack
    for sc in ("SAT", "SATX"):
        def hon(srv, var):
            for k, v in MED.items():
                if (k[0] == run and k[3] == sc and k[5] == srv and k[6] == var
                        and k[7] == "connect_ms.p50"):
                    return v[0]
            return None
        out.append(f"| P13 | {sc} silent-5000 | честный клиент: новое соединение p50, мс "
                   f"(спокойно → под атакой) | {num(hon('A', 'calm'))} → {num(hon('A', 'silent-5000-under'))}"
                   f" | {num(hon('B', 'calm'))} → {num(hon('B', 'silent-5000-under'))} | "
                   f"честному клиенту атака на этом стенде не мешает |")
    return "\n".join(out)


def loopback_table():
    out = ["| Сценарий | Что меряем | A база | B все PR | X Xray |", "|---|---|---|---|---|"]
    for sc in ("S1", "S2"):
        for metric, what in (("download_8.mbps", "загрузка 8 потоков, Мбит/с"),
                             ("download_8.server.cpu_s_per_gbit", "CPU сервера, с/Гбит (загрузка, 8 потоков)"),
                             ("upload_8.server.cpu_s_per_gbit", "CPU сервера, с/Гбит (отдача, 8 потоков)"),
                             ("load.1000.server.rss_peak_mb", "память сервера при 1000 соединений, МБ"),
                             ("load.1000.total_sec", "1000 соединений: открыть + 20 эхо, с")):
            cells = []
            for srv in ("A", "B", "X"):
                v = lb(srv, sc, metric)
                cells.append("—" if v is None else num(v[0]) + ("" if v[1] >= 3 else f" (n={v[1]})"))
            out.append(f"| {sc} | {what} | " + " | ".join(cells) + " |")
    return "\n".join(out)


def runs_table():
    meta = load("meta.csv")
    out = ["| Прогон | Вид | Профиль | Сеть (RTT / jitter / потери на сторону / канал) | "
           "Пинг сети, мс | Повторов | Длительность, мин |", "|---|---|---|---|---|---|---|"]
    for m in meta:
        net = (f"{m['rtt_ms']} мс / {m['jitter_ms']} мс / {m['loss_pct_per_dir']} % / "
               f"{m['rate_mbit']} Мбит/с" if m.get("rtt_ms") else "127.0.0.1")
        ver = "" if m["profile_ver"] in ("v2", "-", "?") else f" ({m['profile_ver']})"
        if m.get("net_ping_p50_ms"):
            ping = num(float(m["net_ping_p50_ms"]))
        elif m.get("icmp_rtt_avg_ms"):
            ping = num(float(m["icmp_rtt_avg_ms"])) + " (ICMP, среднее)"
        else:
            ping = "—"
        dur = str(round(int(m["duration_s"]) / 60)) if m.get("duration_s") else "—"
        out.append(f"| {m['run']} | {m['kind']} | {m['profile']}{ver} | {net} | "
                   f"{ping} | "
                   f"{m.get('repeats_max') or '—'} | {dur} |")
    return "\n".join(out)


def update_readme(blocks):
    if not os.path.exists(README):
        return
    with open(README, encoding="utf-8") as f:
        text = f.read()
    for name, body in blocks.items():
        pat = re.compile(rf"(<!-- gen:{name} -->\n).*?(<!-- /gen:{name} -->)", re.S)
        text, n = pat.subn(lambda m: m.group(1) + body + "\n" + m.group(2), text)
        if not n:
            print(f"README.md: no block gen:{name}")
    with open(README, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("README.md: tables refreshed")


def main():
    os.makedirs(CHARTS, exist_ok=True)
    titles = {
        "p8-xhttp": chart_p8(),
        "xmux-connect": chart_xmux(),
        "mux-cool": chart_mux(),
        "reality-control": chart_control(),
        "p13-attack": chart_attack(),
        "loopback-cost": chart_loopback(),
    }
    blocks = {"clients": client_table(), "server": server_table(),
              "loopback": loopback_table(), "runs": runs_table()}
    for name, t in titles.items():
        blocks["title-" + name] = f"**{t}**"
    update_readme(blocks)


if __name__ == "__main__":
    main()
