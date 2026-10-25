#!/usr/bin/env python3
"""Swarm Defense dashboard (Flask).

  python app.py --demo          # fake 6-node swarm, no agents needed
  python app.py                 # live: listen for agent broadcasts on UDP 9999
  python app.py --log ../logs/threats.jsonl   # also follow a local agent's threat log

Open http://localhost:5000  (no sudo needed)
"""
import argparse, json, os, queue, random, socket, threading, time
from flask import Flask, Response, jsonify, send_from_directory

HERE = os.path.dirname(os.path.abspath(__file__))
THREAT_LOG = os.path.join(HERE, "..", "logs", "threats.jsonl")
app = Flask(__name__)

lock = threading.Lock()
nodes = {}      # name -> {"last_seen": ts, "blocked": set()}
threats = {}    # ip -> {"ip","sig","origin","ts","adopted":[]}
clients = []    # one Queue per connected browser
history = []    # recent events, replayed to new browsers
ASSUME_ACK_DELAY = 1.5   # peers that never send "ack" are assumed to adopt a block
SIGS = ["ssh-bruteforce", "reverse-shell", "ssh-bruteforce", "port-scan"]


# ---------- state ----------
def snapshot():
    now = time.time()
    with lock:
        return {
            "nodes": [{"name": n, "age": round(now - v["last_seen"], 1),
                       "blocked": sorted(v["blocked"])} for n, v in nodes.items()],
            "threats": list(threats.values()),
            "history": history[-40:],
        }


def publish(ev):
    ev["ts"] = time.time()
    assume_for = None
    with lock:
        name, t, ip = ev.get("node"), ev.get("type"), ev.get("ip")
        if name:
            n = nodes.setdefault(name, {"last_seen": 0, "blocked": set()})
            n["last_seen"] = ev["ts"]
        if t == "block" and ip:
            th = threats.get(ip)
            if th and name in th["adopted"]:
                return                      # duplicate (e.g. UDP + log tail)
            th = threats.setdefault(ip, {"ip": ip, "sig": ev.get("sig", "unknown"),
                                         "origin": name, "ts": ev["ts"], "adopted": []})
            if name:
                th["adopted"].append(name)
                nodes[name]["blocked"].add(ip)
            assume_for = ip
        elif t == "ack" and ip and name:
            nodes[name]["blocked"].add(ip)
            th = threats.get(ip)
            if th and name not in th["adopted"]:
                th["adopted"].append(name)
        if t != "heartbeat":
            history.append(ev)
            del history[:-200]
        for q in clients:
            q.put(ev)
    if assume_for:
        threading.Timer(ASSUME_ACK_DELAY, assume_acks, (assume_for,)).start()


def assume_acks(ip):
    """Agents apply peer blocks automatically; mark them immune if no explicit ack came."""
    now = time.time()
    with lock:
        th = threats.get(ip)
        todo = [n for n, v in nodes.items()
                if th and n not in th["adopted"] and now - v["last_seen"] < 20]
    for n in todo:
        publish({"type": "ack", "node": n, "ip": ip, "assumed": True})


# ---------- sources ----------
def udp_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("", port))
    print(f"[udp] listening for agents on :{port}")
    while True:
        data, addr = s.recvfrom(4096)
        try:
            ev = json.loads(data.decode())
            if isinstance(ev, dict) and ev.get("node"):
                ev["src"] = addr[0]
                publish(ev)
        except (ValueError, UnicodeDecodeError):
            pass


def tail_log(path):
    """Follow an agent's threats.jsonl (new lines only) and turn them into events."""
    pos = os.path.getsize(path) if os.path.exists(path) else 0
    print(f"[log] following {os.path.abspath(path)}")
    while True:
        time.sleep(1)
        if not os.path.exists(path):
            continue
        if os.path.getsize(path) < pos:
            pos = 0
        with open(path) as f:
            f.seek(pos)
            while True:
                line = f.readline()
                if not line.endswith("\n"):
                    break
                pos = f.tell()
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("action") == "received_block" or e.get("type") not in ("ssh-bruteforce", "reverse-shell"):
                    continue
                ip = e.get("ip") or (e.get("conn") or {}).get("remote_ip")
                node = e.get("node")
                with lock:
                    th = threats.get(ip)
                    if not (ip and node) or (th and node in th["adopted"]):
                        continue
                publish({"type": "attack", "node": node, "ip": ip, "sig": e["type"]})
                threading.Timer(0.8, publish, ({"type": "block", "node": node, "ip": ip, "sig": e["type"]},)).start()


def simulate():
    now = time.time()
    with lock:
        live = [n for n, v in nodes.items() if now - v["last_seen"] < 20]
    if not live:
        return False
    node, ip, sig = random.choice(live), f"203.0.113.{random.randint(2, 250)}", random.choice(SIGS)
    publish({"type": "attack", "node": node, "ip": ip, "sig": sig})
    threading.Timer(0.9, publish, ({"type": "block", "node": node, "ip": ip, "sig": sig},)).start()
    return True


def demo_loop(count=6):
    names = [f"node-{i + 1}" for i in range(count)]
    last = 0
    while True:
        for n in names:
            publish({"type": "heartbeat", "node": n})
        if time.time() - last > 10:
            simulate()
            last = time.time()
        time.sleep(3)


# ---------- routes ----------
def sse(name, obj):
    return f"event: {name}\ndata: {json.dumps(obj)}\n\n"


@app.route("/")
def index():
    return send_from_directory(os.path.join(HERE, "templates"), "index.html")


@app.route("/events")
def events():
    q = queue.Queue()
    with lock:
        clients.append(q)

    def gen():
        try:
            yield sse("snapshot", snapshot())
            while True:
                try:
                    yield sse("event", q.get(timeout=15))
                except queue.Empty:
                    yield ": ping\n\n"
        finally:
            with lock:
                if q in clients:
                    clients.remove(q)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/state")
def state():
    return jsonify(snapshot())


@app.route("/api/threats")      # kept from the original dashboard: raw log, last 50
def api_threats():
    if not os.path.exists(THREAT_LOG):
        return jsonify([])
    out = []
    with open(THREAT_LOG) as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return jsonify(out[-50:])


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    ok = simulate()
    return jsonify(ok=ok), (200 if ok else 409)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--udp", type=int, default=9999)
    ap.add_argument("--log", help="path to a local agent's threats.jsonl to follow")
    ap.add_argument("--demo", action="store_true", help="run a fake swarm")
    a = ap.parse_args()
    if a.demo:
        threading.Thread(target=demo_loop, daemon=True).start()
    else:
        threading.Thread(target=udp_listener, args=(a.udp,), daemon=True).start()
        if a.log:
            threading.Thread(target=tail_log, args=(a.log,), daemon=True).start()
    app.run(host="0.0.0.0", port=a.port, debug=False, threaded=True)