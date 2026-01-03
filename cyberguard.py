import os
import sys
import time
import json
import math
import sqlite3
import socket
import hashlib
import datetime as dt
import subprocess
from collections import deque, Counter

import requests
import psutil
import pygame

APP_NAME = "CyberGuard"
MODEL_NAME = "dolphin-mistral:latest"
OLLAMA_URL = "http://localhost:11434/api/generate"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "cyberguard_data")
LOG_DIR = os.path.join(DATA_DIR, "logs")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
DB_PATH = os.path.join(DATA_DIR, "cyberguard.sqlite3")

DEFAULT_INTERVAL = 5.0
AI_EVERY_N_LOOPS = 1

SUSPICIOUS_PORTS = {1337, 2222, 2323, 31337, 4444, 5555, 6666, 7777, 9001, 9999, 12345, 54321}
SUSPICIOUS_KEYWORDS = {"miner", "xmrig", "payload", "rat", "stealer", "keylog", "inject", "bot", "c2", "beacon"}
WEIRD_TLDS = {".zip", ".mov", ".top", ".xyz", ".click", ".gq", ".tk", ".ml", ".cf", ".work", ".rest"}

WINDOW_W, WINDOW_H = 1280, 760

def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)

def now_iso():
    return dt.datetime.now().isoformat(timespec="seconds")

def run_cmd(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, shell=False)
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        return out.strip()
    except Exception as e:
        return f"ERROR running {cmd}: {e}"

def safe_open_text(path, max_bytes=200_000):
    try:
        with open(path, "rb") as f:
            b = f.read(max_bytes)
        return b.decode("utf-8", errors="replace")
    except Exception:
        return ""

def sha1(s):
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def is_private_ip(ip):
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 169 and parts[1] == 254:
            return True
        return False
    except Exception:
        return False

def looks_like_random_domain(d):
    if not d or "." not in d:
        return False
    s = d.lower()
    if s.startswith("xn--"):
        return True
    if len(s) > 45:
        return True
    chunk = s.split(".")[0]
    if len(chunk) >= 16:
        vowels = sum(1 for c in chunk if c in "aeiou")
        if vowels <= 2:
            return True
    digits = sum(1 for c in s if c.isdigit())
    if digits >= 6:
        return True
    return False

def wrap_text(font, text, max_w):
    words = (text or "").split()
    lines = []
    cur = ""
    for w in words:
        test = (cur + " " + w).strip()
        if font.size(test)[0] <= max_w:
            cur = test
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines

def clamp(v, a, b):
    return max(a, min(b, v))

def ema(prev, cur, alpha):
    if prev is None:
        return cur
    return (alpha * cur) + ((1 - alpha) * prev)

class Storage:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self._init()

    def _init(self):
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            local_ips TEXT,
            conn_count INTEGER,
            listen_count INTEGER,
            unique_remote_ips INTEGER,
            dns_suspicious_count INTEGER,
            hosts_hash TEXT,
            summary_json TEXT
        );
        """)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            severity TEXT,
            category TEXT,
            message TEXT,
            evidence_json TEXT
        );
        """)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            model TEXT,
            overall_risk INTEGER,
            report_json TEXT,
            raw_text TEXT
        );
        """)
        self.conn.commit()

    def insert_observation(self, obs):
        self.conn.execute("""
        INSERT INTO observations (ts, local_ips, conn_count, listen_count, unique_remote_ips, dns_suspicious_count, hosts_hash, summary_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            obs["ts"],
            json.dumps(obs["local_ips"]),
            obs["conn_count"],
            obs["listen_count"],
            obs["unique_remote_ips"],
            obs["dns_suspicious_count"],
            obs["hosts_hash"],
            json.dumps(obs["summary"], ensure_ascii=False),
        ))
        self.conn.commit()

    def insert_event(self, ev):
        self.conn.execute("""
        INSERT INTO events (ts, severity, category, message, evidence_json)
        VALUES (?, ?, ?, ?, ?);
        """, (
            ev["ts"],
            ev["severity"],
            ev["category"],
            ev["message"],
            json.dumps(ev.get("evidence", {}), ensure_ascii=False),
        ))
        self.conn.commit()

    def insert_ai_report(self, rpt):
        self.conn.execute("""
        INSERT INTO ai_reports (ts, model, overall_risk, report_json, raw_text)
        VALUES (?, ?, ?, ?, ?);
        """, (
            rpt["ts"],
            rpt["model"],
            int(rpt.get("overall_risk", 0) or 0),
            json.dumps(rpt.get("report", {}), ensure_ascii=False),
            rpt.get("raw_text", ""),
        ))
        self.conn.commit()

class RiskEngine:
    def __init__(self):
        self.stable_risk = None
        self.last_ai_raw = 0
        self.last_ai_clamped = 0
        self.last_heur = 0
        self.last_final = 0

    def heuristic_risk(self, snap):
        score = 0

        dns_susp = snap.get("dns_suspicious_count", 0)
        uniq_remote = snap.get("unique_remote_ips", 0)
        listen_count = snap.get("listen_count", 0)

        suspicious_items = snap.get("summary", {}).get("suspicious_samples", []) or []
        sus_conn_hits = 0
        sus_dns_hits = 0
        hosts_changed = False

        for item in suspicious_items:
            if isinstance(item, dict) and item.get("type") == "dns":
                sus_dns_hits += item.get("count", 0) or 0
            elif isinstance(item, dict) and item.get("type") == "hosts":
                hosts_changed = True
            elif isinstance(item, dict) and item.get("remote_port", 0) in SUSPICIOUS_PORTS:
                sus_conn_hits += 1
            elif isinstance(item, dict) and (item.get("process") or "").lower() != "unknown" and item.get("reasons"):
                sus_conn_hits += 1

        score += min(20, dns_susp * 1.5)
        score += min(15, max(0, uniq_remote - 10) * 0.8)

        if listen_count > 25:
            score += min(10, (listen_count - 25) * 0.4)

        score += min(30, sus_conn_hits * 6)
        score += min(15, sus_dns_hits * 0.5)

        if hosts_changed:
            score += 12

        return int(clamp(score, 0, 85))

    def combine(self, heur, ai_raw):
        ai_clamped = int(clamp(ai_raw, 5, 75))

        # If heuristics are calm, strongly dampen AI spikes.
        if heur < 20 and ai_clamped > 45:
            ai_clamped = 35

        # Weighted blend: heuristics lead, AI assists.
        blended = (0.70 * heur) + (0.30 * ai_clamped)

        # Smooth with EMA
        target = float(blended)
        self.stable_risk = ema(self.stable_risk, target, alpha=0.25)

        # Hysteresis: rise quicker than fall (prevents 100->0 yo-yo)
        final = self.stable_risk
        if final > self.last_final:
            final = ema(self.last_final, final, alpha=0.55)
        else:
            final = ema(self.last_final, final, alpha=0.15)

        final_i = int(clamp(round(final), 0, 100))

        self.last_ai_raw = int(ai_raw or 0)
        self.last_ai_clamped = ai_clamped
        self.last_heur = int(heur)
        self.last_final = final_i
        return final_i

class Monitor:
    def __init__(self):
        self.prev_remote_ips = set()
        self.prev_listeners = set()
        self.prev_hosts_hash = None

    def get_local_ips(self):
        ips = set()
        for _, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address:
                    ips.add(a.address)
        return sorted(ips)

    def get_hosts_hash(self):
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        text = safe_open_text(hosts_path)
        cleaned = "\n".join([ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")])
        return sha1(cleaned), cleaned[:2000]

    def get_arp_table(self):
        out = run_cmd(["arp", "-a"])
        entries = []
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            if ln.startswith("Interface:") or ln.startswith("Internet Address") or ln.startswith("---"):
                continue
            parts = [p for p in ln.split() if p]
            if len(parts) >= 3:
                ip = parts[0]
                mac = parts[1]
                typ = parts[2]
                if "." in ip:
                    entries.append({"ip": ip, "mac": mac, "type": typ})
        return entries

    def get_dns_cache(self):
        out = run_cmd(["ipconfig", "/displaydns"])
        names = []
        for ln in out.splitlines():
            s = ln.strip()
            if "Record Name" in s:
                try:
                    cur = s.split(":", 1)[1].strip()
                    if cur:
                        names.append(cur)
                except Exception:
                    pass
        uniq = sorted(set(names))
        suspicious = []
        for d in uniq:
            dl = d.lower()
            if any(dl.endswith(t) for t in WEIRD_TLDS) or looks_like_random_domain(dl):
                suspicious.append(d)
        return uniq[:2000], suspicious[:2000]

    def get_connections(self):
        conns = []
        try:
            for c in psutil.net_connections(kind="inet"):
                laddr = c.laddr if c.laddr else None
                raddr = c.raddr if c.raddr else None
                pid = c.pid
                status = c.status
                if not laddr:
                    continue
                local_ip = laddr.ip if hasattr(laddr, "ip") else laddr[0]
                local_port = laddr.port if hasattr(laddr, "port") else laddr[1]
                remote_ip = ""
                remote_port = 0
                if raddr:
                    remote_ip = raddr.ip if hasattr(raddr, "ip") else raddr[0]
                    remote_port = raddr.port if hasattr(raddr, "port") else raddr[1]
                pname = "unknown"
                pexe = ""
                if pid:
                    try:
                        p = psutil.Process(pid)
                        pname = p.name() or "unknown"
                        pexe = p.exe() or ""
                    except Exception:
                        pass
                conns.append({
                    "pid": pid,
                    "process": pname,
                    "exe": pexe,
                    "status": status,
                    "local_ip": local_ip,
                    "local_port": int(local_port),
                    "remote_ip": remote_ip or "",
                    "remote_port": int(remote_port) if remote_port else 0
                })
        except Exception:
            pass
        return conns

    def classify_suspicious(self, conns, dns_suspicious, hosts_hash_changed):
        sus = []
        for c in conns:
            rp = c["remote_port"]
            rip = c["remote_ip"]
            proc = (c["process"] or "").lower()
            exe = (c["exe"] or "").lower()
            reasons = []

            if rp in SUSPICIOUS_PORTS:
                reasons.append(f"remote_port={rp} suspicious")

            if any(k in proc for k in SUSPICIOUS_KEYWORDS) or any(k in exe for k in SUSPICIOUS_KEYWORDS):
                reasons.append("process/exe keyword hit")

            if c["status"] == "LISTEN":
                if c["local_port"] in {23, 2323}:
                    reasons.append("telnet listening")
                if c["local_port"] in {445, 3389}:
                    reasons.append("sensitive service port listening")

            if reasons:
                sus.append({**c, "reasons": reasons})

        if dns_suspicious:
            sus.append({"type": "dns", "count": len(dns_suspicious), "examples": dns_suspicious[:8], "reasons": ["suspicious domains in DNS cache"]})
        if hosts_hash_changed:
            sus.append({"type": "hosts", "reasons": ["hosts file changed since last loop"]})
        return sus

    def build_events(self, listeners, remote_ips, dns_suspicious, hosts_hash_changed):
        events = []
        ts = now_iso()

        new_remote = sorted(set(remote_ips) - self.prev_remote_ips)
        if new_remote:
            events.append({
                "ts": ts,
                "severity": "info",
                "category": "network",
                "message": f"New remote IPs observed: {len(new_remote)}",
                "evidence": {"new_remote_ips": new_remote[:40]}
            })

        new_listen = sorted(set(listeners) - self.prev_listeners)
        if new_listen:
            sev = "warn" if any(p in {23, 2323, 445, 3389} for _, p in new_listen) else "info"
            events.append({
                "ts": ts,
                "severity": sev,
                "category": "listener",
                "message": f"New listening sockets observed: {len(new_listen)}",
                "evidence": {"new_listeners": [{"ip": ip, "port": port} for ip, port in new_listen[:40]]}
            })

        if dns_suspicious:
            events.append({
                "ts": ts,
                "severity": "warn",
                "category": "dns",
                "message": f"Suspicious-looking DNS cache entries: {len(dns_suspicious)}",
                "evidence": {"examples": dns_suspicious[:20]}
            })

        if hosts_hash_changed:
            events.append({
                "ts": ts,
                "severity": "warn",
                "category": "system",
                "message": "Hosts file changed since last loop",
                "evidence": {}
            })

        self.prev_remote_ips = set(remote_ips)
        self.prev_listeners = set(listeners)
        return events

    def snapshot(self):
        ts = now_iso()

        local_ips = self.get_local_ips()
        hosts_hash, hosts_preview = self.get_hosts_hash()
        hosts_hash_changed = (self.prev_hosts_hash is not None and self.prev_hosts_hash != hosts_hash)
        self.prev_hosts_hash = hosts_hash

        arp = self.get_arp_table()
        dns_all, dns_suspicious = self.get_dns_cache()
        conns = self.get_connections()

        remote_ips = sorted(set([c["remote_ip"] for c in conns if c["remote_ip"] and "." in c["remote_ip"]]))
        listeners = sorted(set([(c["local_ip"], c["local_port"]) for c in conns if c["status"] == "LISTEN"]))

        proc_counts = Counter()
        for c in conns:
            proc_counts[c["process"]] += 1
        top_procs = proc_counts.most_common(8)

        sus = self.classify_suspicious(conns, dns_suspicious, hosts_hash_changed)
        events = self.build_events(listeners, remote_ips, dns_suspicious, hosts_hash_changed)

        summary = {
            "ts": ts,
            "local_ips": local_ips,
            "connections_total": len(conns),
            "listening_total": sum(1 for c in conns if c["status"] == "LISTEN"),
            "unique_remote_ips": len(remote_ips),
            "top_processes_by_sockets": [{"process": p, "count": n} for p, n in top_procs],
            "arp_devices_seen": len(arp),
            "dns_cache_size": len(dns_all),
            "dns_suspicious_count": len(dns_suspicious),
            "suspicious_items_count": len(sus),
            "suspicious_samples": sus[:8],
            "hosts_hash": hosts_hash,
            "hosts_preview": hosts_preview,
        }

        return {
            "ts": ts,
            "local_ips": local_ips,
            "hosts_hash": hosts_hash,
            "hosts_hash_changed": hosts_hash_changed,
            "arp": arp[:120],
            "dns_suspicious": dns_suspicious[:120],
            "connections": conns[:2500],
            "listeners": listeners,
            "remote_ips": remote_ips,
            "suspicious": sus,
            "events": events,
            "summary": summary,
            "conn_count": len(conns),
            "listen_count": sum(1 for c in conns if c["status"] == "LISTEN"),
            "unique_remote_ips": len(remote_ips),
            "dns_suspicious_count": len(dns_suspicious),
        }

class OllamaAnalyst:
    def __init__(self, model=MODEL_NAME, url=OLLAMA_URL):
        self.model = model
        self.url = url

    def analyze(self, summary):
        prompt = f"""
You are a defensive cybersecurity analyst reviewing local workstation telemetry. This tool is for real monitoring, not a demo.
Be conservative and evidence-based: do not output 0 or 100 unless there is very strong evidence in the snapshot.

Rules:
- Risk 0-20: normal/expected background activity.
- Risk 21-50: minor concerns or unusual but explainable signals.
- Risk 51-75: multiple corroborating suspicious signals.
- Risk 76-90: strong evidence of malicious behavior (multiple indicators).
- Risk 91-100: only if you see direct signs of malware persistence or clear C2 behavior (rare in this snapshot).

Return STRICT JSON ONLY:
{{
  "overall_risk": <integer 0-100>,
  "summary": <1-3 sentences>,
  "top_findings": [{{"severity":"info|warn|high","finding":<string>,"evidence":<string>}}],
  "recommended_next_steps": [<string>],
  "nice_gui_stats": {{
     "risk_label": <string>,
     "connections_note": <string>,
     "dns_note": <string>
  }}
}}

Use only the snapshot below, do not invent.
SNAPSHOT:
{json.dumps(summary, ensure_ascii=False)}
""".strip()

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.15}
        }

        try:
            r = requests.post(self.url, json=payload, timeout=60)
            r.raise_for_status()
            data = r.json()
            raw = data.get("response", "") or ""
        except Exception as e:
            return {"ok": False, "error": str(e), "raw_text": ""}

        raw_stripped = raw.strip()
        parsed = None

        if raw_stripped.startswith("{") and raw_stripped.endswith("}"):
            try:
                parsed = json.loads(raw_stripped)
            except Exception:
                parsed = None

        if parsed is None:
            start = raw_stripped.find("{")
            end = raw_stripped.rfind("}")
            if start != -1 and end != -1 and end > start:
                chunk = raw_stripped[start:end+1]
                try:
                    parsed = json.loads(chunk)
                except Exception:
                    parsed = None

        if parsed is None:
            return {"ok": True, "report": {}, "raw_text": raw_stripped}

        return {"ok": True, "report": parsed, "raw_text": raw_stripped}

class UI:
    def __init__(self):
        pygame.init()
        pygame.display.set_caption(APP_NAME)
        self.screen = pygame.display.set_mode((WINDOW_W, WINDOW_H))
        self.clock = pygame.time.Clock()
        self.font = pygame.font.SysFont("consolas", 18)
        self.font_sm = pygame.font.SysFont("consolas", 15)
        self.font_lg = pygame.font.SysFont("consolas", 30)
        self.font_xl = pygame.font.SysFont("consolas", 42)

        self.events_feed = deque(maxlen=200)
        self.ai_lines = deque(maxlen=120)

        self.conn_history = deque(maxlen=180)
        self.risk_history = deque(maxlen=180)
        self.heur_history = deque(maxlen=180)
        self.ai_raw_history = deque(maxlen=180)

        self.running = True
        self.monitoring = True
        self.interval = DEFAULT_INTERVAL

        self.last_snapshot = None
        self.last_ai = None
        self.last_ai_raw = 0
        self.last_heur = 0
        self.last_stable = 0

    def push_event(self, ev):
        sev = ev.get("severity", "info").upper()
        cat = ev.get("category", "misc")
        msg = ev.get("message", "")
        ts = ev.get("ts", "")
        self.events_feed.appendleft(f"[{ts}] {sev:<4} {cat:<9} {msg}")

    def set_ai_report(self, report_obj, raw_text):
        self.ai_lines.clear()
        if report_obj:
            risk = report_obj.get("overall_risk", 0)
            summ = report_obj.get("summary", "")
            self.ai_lines.append(f"AI raw risk: {int(risk)}/100")
            if summ:
                for ln in wrap_text(self.font_sm, summ, 430):
                    self.ai_lines.append(ln)
            self.ai_lines.append("")
            findings = report_obj.get("top_findings", []) or []
            if findings:
                self.ai_lines.append("Findings:")
                for f in findings[:7]:
                    sev = (f.get("severity", "info") or "info").upper()
                    txt = f.get("finding", "")
                    ev = f.get("evidence", "")
                    line = f"- [{sev}] {txt}"
                    for ln in wrap_text(self.font_sm, line, 430):
                        self.ai_lines.append(ln)
                    if ev:
                        for ln in wrap_text(self.font_sm, f"  evidence: {ev}", 430):
                            self.ai_lines.append(ln)
            steps = report_obj.get("recommended_next_steps", []) or []
            if steps:
                self.ai_lines.append("")
                self.ai_lines.append("Next steps:")
                for s in steps[:7]:
                    for ln in wrap_text(self.font_sm, f"- {s}", 430):
                        self.ai_lines.append(ln)
        else:
            if raw_text:
                for ln in wrap_text(self.font_sm, raw_text[:2000], 430)[:90]:
                    self.ai_lines.append(ln)
            else:
                self.ai_lines.append("AI report unavailable.")

    def panel(self, x, y, w, h, title):
        pygame.draw.rect(self.screen, (22, 22, 26), (x, y, w, h), border_radius=16)
        pygame.draw.rect(self.screen, (70, 70, 80), (x, y, w, h), 2, border_radius=16)
        t = self.font.render(title, True, (240, 240, 245))
        self.screen.blit(t, (x + 14, y + 10))

    def draw_gauge(self, x, y, w, h, label, value, vmin, vmax):
        self.panel(x, y, w, h, label)
        frac = 0.0
        if vmax > vmin:
            frac = clamp((value - vmin) / (vmax - vmin), 0.0, 1.0)
        bx, by = x + 14, y + 44
        bw, bh = w - 28, 16
        pygame.draw.rect(self.screen, (45, 45, 55), (bx, by, bw, bh), border_radius=10)
        pygame.draw.rect(self.screen, (210, 210, 220), (bx, by, int(bw * frac), bh), border_radius=10)

        val_txt = self.font.render(str(value), True, (245, 245, 245))
        self.screen.blit(val_txt, (x + w - 14 - val_txt.get_width(), y + h - 28))

    def draw_graph(self, x, y, w, h, title, series, y_min=None, y_max=None, filled=True):
        self.panel(x, y, w, h, title)

        gx, gy = x + 14, y + 44
        gw, gh = w - 28, h - 58

        pygame.draw.rect(self.screen, (18, 18, 22), (gx, gy, gw, gh), border_radius=12)
        pygame.draw.rect(self.screen, (60, 60, 70), (gx, gy, gw, gh), 1, border_radius=12)

        if len(series) < 2:
            return

        mn = min(series) if y_min is None else y_min
        mx = max(series) if y_max is None else y_max
        if mx == mn:
            mx = mn + 1

        # grid
        for i in range(1, 5):
            yy = gy + int(gh * i / 5)
            pygame.draw.line(self.screen, (40, 40, 48), (gx + 8, yy), (gx + gw - 8, yy), 1)
        for i in range(1, 7):
            xx = gx + int(gw * i / 7)
            pygame.draw.line(self.screen, (34, 34, 42), (xx, gy + 8), (xx, gy + gh - 8), 1)

        pts = []
        n = len(series)
        for i, v in enumerate(series):
            px = gx + 8 + int((gw - 16) * (i / (n - 1)))
            frac = (v - mn) / (mx - mn)
            py = gy + gh - 8 - int((gh - 16) * frac)
            pts.append((px, py))

        if filled:
            poly = pts[:] + [(pts[-1][0], gy + gh - 8), (pts[0][0], gy + gh - 8)]
            pygame.draw.polygon(self.screen, (28, 28, 34), poly)

        pygame.draw.lines(self.screen, (230, 230, 240), False, pts, 2)

        # y labels
        top = self.font_sm.render(str(int(mx)), True, (180, 180, 190))
        bot = self.font_sm.render(str(int(mn)), True, (180, 180, 190))
        self.screen.blit(top, (gx + gw - 8 - top.get_width(), gy + 6))
        self.screen.blit(bot, (gx + gw - 8 - bot.get_width(), gy + gh - 18))

    def draw_text_panel(self, x, y, w, h, title, lines, max_lines=None):
        self.panel(x, y, w, h, title)
        yy = y + 44
        shown = list(lines)
        if max_lines is not None:
            shown = shown[:max_lines]
        for ln in shown[: int((h - 56) / 18)]:
            txt = self.font_sm.render(ln, True, (220, 220, 230))
            self.screen.blit(txt, (x + 14, yy))
            yy += 18

    def render(self):
        self.screen.fill((12, 12, 14))

        header = self.font_lg.render(APP_NAME, True, (245, 245, 248))
        self.screen.blit(header, (18, 12))

        status = "RUNNING" if self.monitoring else "PAUSED"
        subtitle = self.font.render(f"Status: {status}   Interval: {self.interval:.1f}s   Model: {MODEL_NAME}", True, (200, 200, 210))
        self.screen.blit(subtitle, (18, 46))

        if self.last_snapshot:
            s = self.last_snapshot

            self.draw_gauge(18, 78, 305, 84, "Connections", s["conn_count"], 0, 500)
            self.draw_gauge(335, 78, 305, 84, "Listening", s["listen_count"], 0, 80)
            self.draw_gauge(652, 78, 305, 84, "Unique Remote IPs", s["unique_remote_ips"], 0, 200)
            self.draw_gauge(969, 78, 293, 84, "Stable Risk", self.last_stable, 0, 100)

            self.draw_graph(18, 174, 620, 175, "Connections (history)", list(self.conn_history), y_min=0, y_max=max(60, max(self.conn_history) if self.conn_history else 60))
            self.draw_graph(652, 174, 610, 175, "Risk (stable vs raw)", list(self.risk_history), y_min=0, y_max=100)

            self.draw_graph(18, 362, 620, 175, "Risk components (heuristic)", list(self.heur_history), y_min=0, y_max=90, filled=False)
            self.draw_graph(652, 362, 610, 175, "Risk components (AI raw)", list(self.ai_raw_history), y_min=0, y_max=100, filled=False)

            self.draw_text_panel(18, 550, 820, 200, "Event Feed", list(self.events_feed))
            self.draw_text_panel(852, 550, 410, 200, "AI Commentary", list(self.ai_lines))
        else:
            msg = self.font.render("Waiting for first snapshot...", True, (220, 220, 220))
            self.screen.blit(msg, (18, 100))

        footer = self.font_sm.render("Keys: Space=Pause/Run  Up/Down=Interval  A=Force AI  Esc=Quit", True, (180, 180, 190))
        self.screen.blit(footer, (18, WINDOW_H - 26))

        pygame.display.flip()

    def handle_events(self):
        for e in pygame.event.get():
            if e.type == pygame.QUIT:
                self.running = False
            if e.type == pygame.KEYDOWN:
                if e.key == pygame.K_ESCAPE:
                    self.running = False
                elif e.key == pygame.K_SPACE:
                    self.monitoring = not self.monitoring
                elif e.key == pygame.K_UP:
                    self.interval = min(30.0, self.interval + 0.5)
                elif e.key == pygame.K_DOWN:
                    self.interval = max(1.0, self.interval - 0.5)
                elif e.key == pygame.K_a:
                    return "force_ai"
        return None

def write_jsonl(path, obj):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception:
        pass

def main():
    ensure_dirs()

    storage = Storage(DB_PATH)
    monitor = Monitor()
    analyst = OllamaAnalyst()
    risk_engine = RiskEngine()

    ui = UI()

    loop_n = 0
    next_run = time.time()

    while ui.running:
        ui.clock.tick(60)
        action = ui.handle_events()
        t = time.time()

        if action == "force_ai" and ui.last_snapshot:
            snap = ui.last_snapshot
            ai_res = analyst.analyze(snap["summary"])
            ts = now_iso()
            if ai_res.get("ok"):
                report = ai_res.get("report", {}) or {}
                raw = ai_res.get("raw_text", "") or ""
                ui.last_ai = report if report else {}
                ui.set_ai_report(report if report else {}, raw)

                ai_raw = int((report or {}).get("overall_risk", 0) or 0)
                heur = risk_engine.heuristic_risk(snap)
                stable = risk_engine.combine(heur, ai_raw)

                ui.last_ai_raw = ai_raw
                ui.last_heur = heur
                ui.last_stable = stable

                storage.insert_ai_report({"ts": ts, "model": MODEL_NAME, "overall_risk": ai_raw, "report": report or {}, "raw_text": raw})
                write_jsonl(os.path.join(LOG_DIR, "ai_reports.jsonl"), {"ts": ts, "model": MODEL_NAME, "report": report, "raw_text": raw[:4000]})
            else:
                ui.ai_lines.clear()
                ui.ai_lines.append(f"AI error: {ai_res.get('error','unknown')}")
                ui.ai_lines.append("Is Ollama running on localhost:11434?")
                ui.ai_lines.append("Try: ollama serve")

        if ui.monitoring and t >= next_run:
            loop_n += 1
            snap = monitor.snapshot()
            ui.last_snapshot = snap

            storage.insert_observation(snap)
            write_jsonl(os.path.join(LOG_DIR, "observations.jsonl"), {"ts": snap["ts"], "summary": snap["summary"]})

            for ev in snap["events"]:
                ui.push_event(ev)
                storage.insert_event(ev)
                write_jsonl(os.path.join(LOG_DIR, "events.jsonl"), ev)

            ui.conn_history.append(snap["conn_count"])

            heur = risk_engine.heuristic_risk(snap)
            ui.heur_history.append(heur)

            if loop_n % AI_EVERY_N_LOOPS == 0:
                ai_res = analyst.analyze(snap["summary"])
                ts = now_iso()
                if ai_res.get("ok"):
                    report = ai_res.get("report", {}) or {}
                    raw = ai_res.get("raw_text", "") or ""
                    ui.last_ai = report if report else {}
                    ui.set_ai_report(report if report else {}, raw)

                    ai_raw = int((report or {}).get("overall_risk", 0) or 0)
                    ui.ai_raw_history.append(ai_raw)

                    stable = risk_engine.combine(heur, ai_raw)
                    ui.last_ai_raw = ai_raw
                    ui.last_heur = heur
                    ui.last_stable = stable

                    ui.risk_history.append(stable)

                    storage.insert_ai_report({"ts": ts, "model": MODEL_NAME, "overall_risk": ai_raw, "report": report or {}, "raw_text": raw})
                    write_jsonl(os.path.join(LOG_DIR, "ai_reports.jsonl"), {"ts": ts, "model": MODEL_NAME, "report": report, "raw_text": raw[:4000]})
                else:
                    ui.ai_lines.clear()
                    ui.ai_lines.append(f"AI error: {ai_res.get('error','unknown')}")
                    ui.ai_lines.append("Is Ollama running on localhost:11434?")
                    ui.ai_lines.append("Try: ollama serve")
                    ui.ai_raw_history.append(0)
                    stable = risk_engine.combine(heur, 0)
                    ui.last_stable = stable
                    ui.risk_history.append(stable)

            next_run = t + ui.interval

        ui.render()

    pygame.quit()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print("Fatal error:", e)
        sys.exit(1)
