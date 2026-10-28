#!/usr/bin/env python3
"""Collect bench result folders into flat CSV files under data/.

Usage:
  python tools/collect.py <result folder> [<result folder> ...]
  python tools/collect.py            # re-read every folder already in data/meta.csv

A folder is one of:
  netem    <run>/<profile>/runs/*.json   (client comparison through tc/netem)
  attack   <run>/runs/*.attack.json      (connection-holding attack on the server)
  loopback <run>/runs/*.json             (all on 127.0.0.1 of one PC)

Re-running is idempotent: rows of the given runs are replaced, other runs kept.
A netem profile is taken only when the stand finished it (results.json exists),
so a run that is still going contributes only its finished profiles.

Outputs:
  data/runs.csv            one row = run x profile x scenario x client x server
                           x variant x repeat x metric; repeat=median rows carry
                           the median over repeats and n = number of repeats
  data/meta.csv            one row = run x profile: date, netem spec, measured
                           baseline, binary hashes, duration
  data/attack_samples.csv  attack time series (alive connections, RSS, CPU)
"""

import csv
import glob
import json
import os
import re
import statistics
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

# Current netem profiles (.bench/netem/lib.sh profile_spec): RTT ms, jitter ms,
# loss % per direction, rate Mbit/s. A profile measured with other numbers is an
# older version ("v1") and must not be compared with the current one ("v2").
CURRENT_SPECS = {
    "good": (20, 0, 0, 100),
    "mobile": (70, 0, 1, 30),
    "bad": (150, 0, 1, 8),
}

RUN_COLS = ["run", "kind", "profile", "profile_ver", "scenario", "client", "server",
            "variant", "repeat", "n", "metric", "value", "unit"]
SAMPLE_COLS = ["run", "server", "scenario", "variant", "t", "alive", "established",
               "rss_mb", "threads", "cpu_pct"]
META_BASE = ["run", "kind", "profile", "profile_ver", "date", "source",
             "rtt_ms", "jitter_ms", "loss_pct_per_dir", "rate_mbit",
             "icmp_rtt_avg_ms", "net_ping_p50_ms", "net_down1_mbps",
             "repeats_max", "cells", "failed_lines", "duration_s", "cpu_model", "num_cpu"]

SKIP_KEYS = {"repeat", "num_cpu", "time", "scenario", "server", "mode", "tls", "unit",
             "samples"}


def fmt(v):
    return f"{v:.6g}"


def unit_of(metric):
    leaf = metric.split(".")[-1]
    if metric.endswith("cpu_s_per_gbit"):
        return "s/Gbit"
    if leaf == "mbps":
        return "Mbit/s"
    if leaf.endswith("_pct") or leaf == "err_pct":
        return "%"
    if leaf.endswith("_mb"):
        return "MB"
    if leaf.endswith("_sec") or leaf == "sec":
        return "s"
    if leaf.endswith("_ms"):
        return "ms"
    if metric.startswith("ping_us.") and leaf in ("p50", "p95", "p99"):
        return "us"
    if metric.startswith("connect_ms.") and leaf in ("p50", "p95", "p99"):
        return "ms"
    return ""


def flatten(obj, prefix=""):
    """Numeric leaves of a measure/attack json as {dotted.path: float}."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not prefix and k in SKIP_KEYS:  # top-level labels, not nested "server" stats
                continue
            out.update(flatten(v, f"{prefix}{k}."))
    elif isinstance(obj, bool) or obj is None:
        pass
    elif isinstance(obj, (int, float)):
        out[prefix[:-1]] = float(obj)
    return out


def measure_metrics(d):
    m = flatten(d)
    # server CPU-seconds per gigabit moved, as in the stand's report
    for ph in ("download_1", "upload_1", "download_8", "upload_8"):
        p = d.get(ph) or {}
        cs = (p.get("server") or {}).get("cpu_sec")
        if cs is not None and p.get("bytes"):
            m[f"{ph}.server.cpu_s_per_gbit"] = cs / (p["bytes"] * 8 / 1e9)
    return m


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def parse_netem(text):
    """(rtt, jitter, loss per direction, rate) from the first `qdisc netem` line."""
    m = re.search(r"qdisc netem .*", text)
    if not m:
        return None
    line = m.group(0)
    d = re.search(r"delay ([\d.]+)ms(?:\s+([\d.]+)ms)?", line)
    loss = re.search(r"loss ([\d.]+)%", line)
    rate = re.search(r"rate ([\d.]+)([GMK]?)bit", line)
    rtt = 2 * float(d.group(1)) if d else 0.0
    jit = 2 * float(d.group(2)) if d and d.group(2) else 0.0
    lp = float(loss.group(1)) if loss else 0.0
    r = None
    if rate:
        r = float(rate.group(1)) * {"G": 1000, "M": 1, "K": 0.001, "": 1e-6}[rate.group(2)]
    return (rtt, jit, lp, r)


def icmp_avg(text):
    m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", text)
    return float(m.group(1)) if m else None


def profile_version(profile, spec):
    if spec is None or profile not in CURRENT_SPECS:
        return "?"
    want = CURRENT_SPECS[profile]
    same = all(abs(a - b) < 1e-6 for a, b in zip(spec, want))
    return "v2" if same else "v1"


def run_date(name):
    m = re.match(r"(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})", name)
    return f"{m[1]}-{m[2]}-{m[3]} {m[4]}:{m[5]}:{m[6]}" if m else ""


def common_meta(run_dir):
    meta = {}
    info = read_text(os.path.join(run_dir, "server-info.txt")) + read_text(
        os.path.join(run_dir, "summary.md"))
    m = re.search(r"model name\s*:\s*(.+)", info)
    if m:
        meta["cpu_model"] = m.group(1).strip()
    dur = read_text(os.path.join(run_dir, "duration.txt")) or read_text(
        os.path.join(run_dir, "duration_sec"))
    m = re.search(r"(\d+)", dur)
    if m:
        meta["duration_s"] = m.group(1)
    for line in read_text(os.path.join(run_dir, "server-bin.sha256")).splitlines():
        parts = line.split()
        if len(parts) == 2:
            meta["sha_" + os.path.basename(parts[1])] = parts[0][:12]
    return meta


def count_failed(path):
    return sum(1 for l in read_text(path).splitlines() if re.match(r"^\S+: ", l))


def add_medians(rows):
    groups = defaultdict(list)
    for r in rows:
        key = tuple(r[c] for c in RUN_COLS if c not in ("repeat", "n", "value"))
        groups[key].append(float(r["value"]))
    out = []
    keys = [c for c in RUN_COLS if c not in ("repeat", "n", "value")]
    for key, vals in groups.items():
        r = dict(zip(keys, key))
        r.update(repeat="median", n=str(len(vals)), value=fmt(statistics.median(vals)))
        out.append(r)
    return out


def collect_measure_dir(run, kind, profile, ver, runs_dir, client_fixed=None):
    rows = []
    for f in sorted(glob.glob(os.path.join(runs_dir, "*.json"))):
        if f.endswith(".attack.json"):
            continue
        with open(f, encoding="utf-8") as fh:
            d = json.load(fh)
        label = d.get("server", "")
        if kind == "netem":
            client, server, variant = label, "X", ""
        elif kind == "loopback":
            client, server, variant = "B", label, ""
        else:  # attack: honest mihomo-B client against server A/B
            stem = os.path.basename(f)[: -len(".json")]
            server, _, rest = stem.partition("-")
            variant = rest[len(d.get("scenario", "")) + 1:]
            client = "B-honest"
        for metric, v in measure_metrics(d).items():
            rows.append({"run": run, "kind": kind, "profile": profile, "profile_ver": ver,
                         "scenario": d.get("scenario", ""), "client": client,
                         "server": server, "variant": variant,
                         "repeat": str(d.get("repeat", 1)), "n": "1",
                         "metric": metric, "value": fmt(v), "unit": unit_of(metric)})
    return rows


def collect(path):
    path = os.path.abspath(path)
    run = os.path.basename(path.rstrip("/\\"))
    if "quick" in run and "--allow-quick" not in sys.argv:
        print(f"skip {run}: quick runs (1 repeat) are not recorded; --allow-quick to force")
        return None
    rows, samples, metas = [], [], []
    base = common_meta(path)
    src = path.replace("\\", "/")
    runs_dir = os.path.join(path, "runs")
    if os.path.isdir(runs_dir) and glob.glob(os.path.join(runs_dir, "*.attack.json")):
        kind = "attack"
        summ = read_text(os.path.join(path, "summary.md"))
        m = re.search(r"profile (\w+)", summ)
        profile = m.group(1) if m else "good"
        bl = read_text(os.path.join(path, "logs", "baseline.txt"))
        spec = parse_netem(bl)
        ver = profile_version(profile, spec)
        rows += collect_measure_dir(run, kind, profile, ver, runs_dir)
        for f in sorted(glob.glob(os.path.join(runs_dir, "*.attack.json"))):
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
            stem = os.path.basename(f)[: -len(".attack.json")]
            server, sc, variant = stem.split("-", 2)
            for metric, v in flatten(d).items():
                rows.append({"run": run, "kind": kind, "profile": profile, "profile_ver": ver,
                             "scenario": sc, "client": "attacker", "server": server,
                             "variant": variant, "repeat": "1", "n": "1",
                             "metric": "attack." + metric, "value": fmt(v),
                             "unit": unit_of(metric) or ("conns" if "alive" in metric
                                                         or "dial" in metric
                                                         or "estab" in metric else "")})
            for s in d.get("samples") or []:
                samples.append({"run": run, "server": server, "scenario": sc,
                                "variant": variant, "t": fmt(s["t"]), "alive": str(s["alive"]),
                                "established": str(s["established"]), "rss_mb": fmt(s["rss_mb"]),
                                "threads": str(s["threads"]), "cpu_pct": fmt(s["cpu_pct"])})
        metas.append(dict(base, run=run, kind=kind, profile=profile, profile_ver=ver,
                          **spec_meta(spec), icmp_rtt_avg_ms=fmt_opt(icmp_avg(bl)),
                          failed_lines=str(count_failed(os.path.join(path, "failed.txt")))))
    elif os.path.isdir(runs_dir):
        kind = "loopback"
        rows += collect_measure_dir(run, kind, "loopback", "-", runs_dir)
        metas.append(dict(base, run=run, kind=kind, profile="loopback", profile_ver="-",
                          failed_lines=str(count_failed(os.path.join(path, "failed.txt")))))
    else:
        kind = "netem"
        top = read_text(os.path.join(path, "summary.md"))
        for pdir in sorted(glob.glob(os.path.join(path, "*", "runs"))):
            pdir = os.path.dirname(pdir)
            profile = os.path.basename(pdir)
            if not os.path.exists(os.path.join(pdir, "results.json")):
                print(f"skip {run}/{profile}: profile not finished (no results.json)")
                continue
            bl = read_text(os.path.join(pdir, "logs", "baseline.txt"))
            if not bl:  # fall back to the run summary section of this profile
                m = re.search(rf"## Profile: {profile}\n(.*?)(?=\n## Profile|\Z)", top, re.S)
                bl = m.group(1) if m else ""
            spec = parse_netem(bl)
            ver = profile_version(profile, spec)
            prow = collect_measure_dir(run, kind, profile, ver, os.path.join(pdir, "runs"))
            rows += prow
            reps = defaultdict(set)
            for r in prow:
                reps[(r["scenario"], r["client"])].add(r["repeat"])
            net = [float(r["value"]) for r in prow if r["scenario"] == "NET"
                   and r["metric"] == "ping_us.p50"]
            down = [float(r["value"]) for r in prow if r["scenario"] == "NET"
                    and r["metric"] == "download_1.mbps"]
            metas.append(dict(base, run=run, kind=kind, profile=profile, profile_ver=ver,
                              **spec_meta(spec), icmp_rtt_avg_ms=fmt_opt(icmp_avg(bl)),
                              net_ping_p50_ms=fmt_opt(statistics.median(net) / 1000 if net else None),
                              net_down1_mbps=fmt_opt(statistics.median(down) if down else None),
                              repeats_max=str(max((len(v) for v in reps.values()), default=0)),
                              cells=str(len(reps)),
                              failed_lines=str(count_failed(os.path.join(pdir, "failed.txt")))))
    for m in metas:
        m.setdefault("date", run_date(run))
        m.setdefault("source", src)
    first = sorted(glob.glob(os.path.join(path, "runs", "*.json")) +
                   glob.glob(os.path.join(path, "*", "runs", "*.json")))
    if first:
        with open(first[0], encoding="utf-8") as fh:
            ncpu = json.load(fh).get("num_cpu")
        for m in metas:
            m.setdefault("num_cpu", "" if ncpu is None else str(ncpu))
    print(f"{run}: {kind}, {len(rows)} raw rows, profiles "
          f"{', '.join(m['profile'] + '/' + m['profile_ver'] for m in metas) or '-'}")
    return run, rows + add_medians(rows), samples, metas


def spec_meta(spec):
    if not spec:
        return {}
    return {"rtt_ms": fmt(spec[0]), "jitter_ms": fmt(spec[1]),
            "loss_pct_per_dir": fmt(spec[2]), "rate_mbit": fmt_opt(spec[3])}


def fmt_opt(v):
    return "" if v is None else fmt(v)


def load_csv(name):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return []
    with open(p, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(name, cols, rows, sort_key):
    os.makedirs(DATA, exist_ok=True)
    rows = sorted(rows, key=sort_key)
    with open(os.path.join(DATA, name), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    old_meta = load_csv("meta.csv")
    if not args:
        args = sorted({m["source"] for m in old_meta if m.get("source")})
        if not args:
            sys.exit(__doc__)
    results = [r for r in (collect(a) for a in args) if r]
    if not results:
        sys.exit("nothing collected")
    new_runs = {r[0] for r in results}
    runs = [r for r in load_csv("runs.csv") if r["run"] not in new_runs]
    samples = [r for r in load_csv("attack_samples.csv") if r["run"] not in new_runs]
    metas = [r for r in old_meta if r["run"] not in new_runs]
    for _, rr, ss, mm in results:
        runs += rr
        samples += ss
        metas += mm
    sha_cols = sorted({k for m in metas for k in m if k.startswith("sha_")})
    write_csv("runs.csv", RUN_COLS, runs,
              lambda r: (r["run"], r["profile"], r["scenario"], r["client"], r["server"],
                         r["variant"], r["metric"], r["repeat"] == "median", r["repeat"]))
    write_csv("attack_samples.csv", SAMPLE_COLS, samples,
              lambda r: (r["run"], r["server"], r["scenario"], r["variant"], float(r["t"])))
    write_csv("meta.csv", META_BASE + sha_cols, metas, lambda r: (r["run"], r["profile"]))
    print(f"data/runs.csv: {len(runs)} rows; data/meta.csv: {len(metas)} rows; "
          f"data/attack_samples.csv: {len(samples)} rows")


if __name__ == "__main__":
    main()
