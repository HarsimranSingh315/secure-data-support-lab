"""Packet captures: record on a lab device with tcpdump, decode with tshark, explain the findings.

Safety:
  * Capture points, filters and durations come from fixed allow-lists; filter words reach tcpdump
    as separate arguments, never through a shell.
  * Only the lab's own devices can capture (routers r1-r3 and the Site A toolbox).
  * Snap length 256 bytes and at most 5000 packets: enough for headers and handshakes, not for
    bulk payload. Files over 10 MB are refused.
  * Uploaded files are checked for pcap/pcapng magic bytes and size, then decoded by tshark inside
    the toolbox container, never by the workbench itself.
"""
from __future__ import annotations

import io
import json
import os
import re
import tarfile
import threading
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path

from .checks import evidence, now
from .models import CaptureAnalysis, CaptureConversation, CaptureFinding, CaptureMeta, CapturePacket, Fact
from .runner import ExecResult, Runner

MAX_FILE = 10 * 1024 * 1024
MAX_PACKETS = 5000
KEEP = 20
DATA_DIR = Path(os.environ.get("WB_DATA", "/tmp/wb-data")) / "captures"

POINTS = {
    "toolbox": ("Toolbox · Site A client", False),
    "r1": ("Router r1 · Site A edge", True),
    "r2": ("Router r2 · core", True),
    "r3": ("Router r3 · Site B edge + firewall", True),
}  # (label, is_router: capture inbound only so forwarded packets are not counted twice)

FILTERS = {
    "db": ("PostgreSQL (tcp 5432)", ["tcp", "port", "5432"]),
    "app": ("Cardholder app (tcp 8443)", ["tcp", "port", "8443"]),
    "kms": ("KMS API (tcp 8200)", ["tcp", "port", "8200"]),
    "ldap": ("LDAP (tcp 389 / 636)", ["tcp", "port", "389", "or", "tcp", "port", "636"]),
    "icmp": ("ICMP (ping, unreachable, TTL exceeded)", ["icmp"]),
    "ospf": ("OSPF routing protocol", ["ip", "proto", "89"]),
    "traceroute": ("Traceroute (UDP probes + ICMP replies)", ["udp", "portrange", "33434-33534", "or", "icmp"]),
}

TRAFFIC = {
    "none": "No test traffic (capture whatever happens)",
    "db": "Connect to the database (TCP + TLS) from the toolbox",
    "app": "Call the app health check from the toolbox",
    "ping_db": "Ping the database from the toolbox",
    "ldaps": "Connect to ldap:636 (nothing listening)",
    "trace_db": "Traceroute to the database",
}

TSHARK_FIELDS = ["frame.number", "frame.time_relative", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
                 "udp.srcport", "udp.dstport", "_ws.col.Protocol", "frame.len", "tcp.flags", "tcp.stream",
                 "_ws.col.Info"]
# Extra passes: display filter -> label. Each returns frame numbers (works on old and new tshark).
FLAG_PASSES = {
    "retransmission": "tcp.analysis.retransmission",
    "dup_ack": "tcp.analysis.duplicate_ack",
    "tls_alert": "tls.alert_message",
    "icmp_unreach": "icmp.type == 3",
    "icmp_ttl": "icmp.type == 11",
}


class CaptureError(ValueError):
    pass


_lock = threading.Lock()


def _store() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR


def is_pcap(data: bytes) -> bool:
    return data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")


# ------------------------------------------------------------------ parsing tshark output

def tcp_flag_names(hexflags: str) -> list[str]:
    try:
        v = int(hexflags, 16)
    except (TypeError, ValueError):
        return []
    names = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH")]
    return [n for bit, n in names if v & bit]


def parse_fields(out: str) -> list[CapturePacket]:
    pkts = []
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) < len(TSHARK_FIELDS) or not cols[0].isdigit():
            continue
        (num, t, src, dst, tsp, tdp, usp, udp_, proto, length, flags, stream, info) = cols[:13]
        pkts.append(CapturePacket(
            no=int(num), time=round(float(t or 0), 6), src=src, dst=dst,
            sport=int(tsp or usp or 0) or None, dport=int(tdp or udp_ or 0) or None,
            protocol=proto, length=int(length or 0), flags=tcp_flag_names(flags),
            stream=int(stream) if stream.isdigit() else None, info=info[:300], marks=[]))
    return pkts


def conversations(pkts: list[CapturePacket]) -> list[CaptureConversation]:
    streams: dict[int, list[CapturePacket]] = defaultdict(list)
    for p in pkts:
        if p.stream is not None:
            streams[p.stream].append(p)
    convs = []
    for sid, ps in sorted(streams.items()):
        first = ps[0]
        syn = [p for p in ps if p.flags == ["SYN"]]
        client, server = (first.src, first.sport), (first.dst, first.dport)
        if syn:
            client, server = (syn[0].src, syn[0].sport), (syn[0].dst, syn[0].dport)
        synack = any("SYN" in p.flags and "ACK" in p.flags for p in ps)
        rst_from_server = any("RST" in p.flags and p.src == server[0] for p in ps)
        retrans = sum(1 for p in ps if "retransmission" in p.marks)
        if syn and not synack and rst_from_server:
            state = "refused"
        elif syn and not synack:
            state = "no answer"
        elif synack and any("RST" in p.flags for p in ps):
            state = "reset"
        elif synack:
            state = "established"
        else:
            state = "mid-stream"
        convs.append(CaptureConversation(
            stream=sid, client=f"{client[0]}:{client[1]}", server=f"{server[0]}:{server[1]}",
            packets=len(ps), bytes=sum(p.length for p in ps), state=state, retransmissions=retrans,
            start=ps[0].time, duration=round(ps[-1].time - ps[0].time, 3),
            protocols=sorted({p.protocol for p in ps})))
    return convs


OWNER = {"10.10.10.10": "toolbox", "10.10.10.20": "ldap", "10.20.20.10": "db", "10.20.20.20": "kms",
         "10.20.20.30": "app", "10.10.10.2": "r1", "10.0.12.12": "r2", "10.0.23.22": "r2", "10.0.12.11": "r1",
         "10.0.13.11": "r1", "10.0.23.23": "r3", "10.0.13.13": "r3", "10.20.20.2": "r3"}


def who(addr: str) -> str:
    ip = addr.rsplit(":", 1)[0]
    return f"{OWNER[ip]} ({addr})" if ip in OWNER else addr


SEVERITY_ORDER = {"fail": 0, "warn": 1, "info": 2, "pass": 3}


def findings(pkts: list[CapturePacket], convs: list[CaptureConversation], ospf_mtu: list[tuple[str, int]],
             tls_alerts: list[tuple[int, str]], local_mtu: dict[str, tuple[str, int]] | None = None) -> list[CaptureFinding]:
    return sorted(_findings(pkts, convs, ospf_mtu, tls_alerts, local_mtu), key=lambda f: SEVERITY_ORDER[f.severity])


def _findings(pkts, convs, ospf_mtu, tls_alerts, local_mtu) -> list[CaptureFinding]:
    out: list[CaptureFinding] = []
    for c in convs:
        if c.state == "no answer":
            out.append(CaptureFinding(
                severity="fail", title=f"No reply to connection attempts: {who(c.client)} → {who(c.server)}",
                detail=f"{c.packets} SYN packet(s) over {c.duration:g} s and no SYN-ACK or reset came back. "
                       "The client kept retrying. Silence like this means the packets were dropped on the way "
                       "(firewall rule) or the reply could not route back. Where you captured matters: if the "
                       "SYNs arrive at r3 but never reach the server, r3 dropped them.",
                packets=[p.no for p in pkts if p.stream == c.stream][:20]))
        elif c.state == "refused":
            out.append(CaptureFinding(
                severity="fail", title=f"Connection refused: {who(c.server)} answered with a reset",
                detail="The server's host received the SYN and replied RST: the network path works, but nothing "
                       "listens on that port.", packets=[p.no for p in pkts if p.stream == c.stream][:20]))
        elif c.retransmissions:
            out.append(CaptureFinding(
                severity="warn", title=f"{c.retransmissions} retransmission(s) in {who(c.client)} → {who(c.server)}",
                detail="Some segments had to be sent again: packet loss or delay somewhere on the path.",
                packets=[p.no for p in pkts if p.stream == c.stream and "retransmission" in p.marks][:20]))
        elif c.state == "established":
            out.append(CaptureFinding(
                severity="pass", title=f"Handshake completed: {who(c.client)} → {who(c.server)}",
                detail="SYN, SYN-ACK and ACK were all seen, so this connection got through.",
                packets=[p.no for p in pkts if p.stream == c.stream][:3]))
    for no, desc in tls_alerts:
        out.append(CaptureFinding(
            severity="fail", title=f"TLS alert: {desc}",
            detail="One side aborted the TLS handshake. When the client sends 'bad certificate' or "
                   "'unknown CA' it did not accept the server's certificate (wrong name, untrusted issuer or "
                   "expired). TCP worked; the problem is the certificate.", packets=[no]))
    unreach = [p for p in pkts if "icmp_unreach" in p.marks]
    if unreach:
        out.append(CaptureFinding(
            severity="fail", title=f"{len(unreach)} ICMP destination unreachable message(s)",
            detail=f"First from {who(unreach[0].src)}: {unreach[0].info}. A router or host is telling the sender "
                   "it cannot deliver: no route, or the port/protocol is not available.",
            packets=[p.no for p in unreach][:20]))
    if ospf_mtu:
        seen = sorted(set(ospf_mtu))
        lines, mismatch = [], False
        for a, m in seen:
            mine = (local_mtu or {}).get(a)
            if mine:
                lines.append(f"{who(a)} advertises MTU {m}; the capturing router's interface on that link ({mine[0]}) "
                             f"has MTU {mine[1]}")
                mismatch |= mine[1] != m
            else:
                lines.append(f"{who(a)} advertises MTU {m}")
        dbd_count = sum(1 for p in pkts if "DB Description" in p.info)
        out.append(CaptureFinding(
            severity="fail" if mismatch else "info",
            title=("OSPF neighbours disagree on MTU: " if mismatch else "OSPF Database Description: ") + "; ".join(lines),
            detail=f"{dbd_count} DB Description packet(s) seen. Each router puts its interface MTU in its DBD packets; "
                   "if the neighbour's MTU is larger than the receiving interface's, the DBD is rejected, so both "
                   "keep resending and the adjacency never leaves ExStart/Exchange. Fix: make the MTU the same on both "
                   "ends of the link.",
            packets=[p.no for p in pkts if "DB Description" in p.info][:20]))
    hello = [p for p in pkts if p.protocol == "OSPF" and "Hello" in p.info]
    if hello and not ospf_mtu:
        out.append(CaptureFinding(severity="info", title=f"{len(hello)} OSPF Hello packet(s)",
                                  detail="Neighbours announce themselves every hello interval (2 s in this lab).",
                                  packets=[p.no for p in hello][:10]))
    echo = [p for p in pkts if p.protocol == "ICMP" and "Echo (ping) reply" in p.info]
    if echo:
        out.append(CaptureFinding(severity="pass", title=f"{len(echo)} ping repl{'y' if len(echo) == 1 else 'ies'}",
                                  detail="ICMP echo replies came back: the host is reachable at layer 3.",
                                  packets=[p.no for p in echo][:10]))
    if not pkts:
        out.append(CaptureFinding(severity="info", title="No packets matched",
                                  detail="Nothing matching the filter passed this capture point during the "
                                         "capture. Either no traffic was sent, or it never reached this device.",
                                  packets=[]))
    return out


# ------------------------------------------------------------------ running

def _exec(runner: Runner, svc: str, argv: list[str], timeout: int = 20) -> ExecResult:
    return runner.exec(svc, argv, timeout=timeout, limit=4_000_000)


def _decode(runner: Runner, pcap_path: str) -> tuple[list[CapturePacket], list, list[ExecResult]]:
    runs = []
    base = ["tshark", "-r", pcap_path, "-n"]
    fields = []
    for f in TSHARK_FIELDS:
        fields += ["-e", f]
    r = _exec(runner, "toolbox", base + ["-c", str(MAX_PACKETS), "-T", "fields", "-E", "separator=/t",
                                          "-E", "occurrence=f"] + fields)
    runs.append(r)
    if not r.ran:
        raise CaptureError("tshark could not run in the toolbox")
    if r.exit_code not in (0, 2):
        raise CaptureError("tshark could not read the file: " + r.output.strip()[:200])
    pkts = parse_fields(r.output)
    by_no = {p.no: p for p in pkts}
    for mark, flt in FLAG_PASSES.items():
        x = _exec(runner, "toolbox", base + ["-Y", flt, "-T", "fields", "-e", "frame.number"])
        runs.append(x)
        for line in x.output.split():
            if line.isdigit() and int(line) in by_no:
                by_no[int(line)].marks.append(mark)
    extra = _exec(runner, "toolbox", base + ["-Y", "ospf.msg.dbdesc or tls.alert_message", "-T", "fields",
                                              "-E", "separator=/t", "-e", "frame.number", "-e", "ip.src",
                                              "-e", "ospf.db.interface_mtu", "-e", "tls.alert_message.desc"])
    runs.append(extra)
    return pkts, extra.output.splitlines(), runs


ALERTS = {"10": "unexpected message", "20": "bad record MAC", "40": "handshake failure", "42": "bad certificate",
          "43": "unsupported certificate", "44": "certificate revoked", "45": "certificate expired",
          "46": "certificate unknown", "47": "illegal parameter", "48": "unknown CA", "49": "access denied",
          "50": "decode error", "51": "decrypt error", "70": "protocol version", "80": "internal error",
          "112": "unrecognized name"}


def local_mtus(runner: Runner, point: str, senders: list[str]) -> tuple[dict[str, tuple[str, int]], ExecResult | None]:
    """For each OSPF sender, the capturing router's own interface (name, MTU) on the same subnet."""
    import ipaddress
    if not POINTS.get(point, ("", False))[1] or not senders:
        return {}, None
    r = runner.exec(point, ["ip", "-j", "addr", "show"], limit=200_000)
    try:
        ifs = json.loads(r.output or "[]")
    except ValueError:
        return {}, r
    res = {}
    for s in senders:
        for i in ifs:
            for a in i.get("addr_info", []):
                if a.get("family") == "inet" and ipaddress.ip_address(s) in ipaddress.ip_network(
                        f'{a["local"]}/{a["prefixlen"]}', strict=False):
                    res[s] = (i.get("ifname", "?"), i.get("mtu"))
    return res, r


def analyse(runner: Runner, meta: CaptureMeta, remote_path: str, extra_runs: list[ExecResult]) -> CaptureAnalysis:
    pkts, extra_lines, runs = _decode(runner, remote_path)
    ospf_mtu: list[tuple[str, int]] = []
    tls_alerts: list[tuple[int, str]] = []
    for line in extra_lines:
        cols = line.split("\t") + ["", "", "", ""]
        if cols[2].isdigit():
            ospf_mtu.append((cols[1], int(cols[2])))
        if cols[3]:
            code = cols[3].split(",")[0]
            tls_alerts.append((int(cols[0]), f"{ALERTS.get(code, 'alert ' + code)} (sent by {who(cols[1])})"))
    local, addr_run = local_mtus(runner, meta.point, sorted({a for a, _ in ospf_mtu}))
    if addr_run:
        runs.append(addr_run)
    convs = conversations(pkts)
    protos = Counter(p.protocol for p in pkts)
    meta.packets = len(pkts)
    stats = [Fact(label="packets", value=str(len(pkts))),
             Fact(label="protocols", value=", ".join(f"{k} {v}" for k, v in protos.most_common()) or "-"),
             Fact(label="TCP conversations", value=str(len(convs))),
             Fact(label="duration", value=f"{pkts[-1].time:g} s" if pkts else "-")]
    return CaptureAnalysis(meta=meta, packets=pkts, conversations=convs,
                           findings=findings(pkts, convs, ospf_mtu, tls_alerts, local), stats=stats,
                           evidence=[evidence(r) for r in extra_runs + runs])


def _save(an: CaptureAnalysis, raw: bytes) -> None:
    d = _store()
    (d / f"{an.meta.id}.pcap").write_bytes(raw)
    (d / f"{an.meta.id}.json").write_text(an.model_dump_json())
    olds = sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime)[:-KEEP]
    for o in olds:
        o.unlink(missing_ok=True)
        (d / (o.stem + ".pcap")).unlink(missing_ok=True)


def _push_to_toolbox(runner: Runner, raw: bytes, name: str) -> str:
    path = f"/tmp/{name}"
    runner.put_file("toolbox", path, raw)
    return path


def generate(runner: Runner, traffic: str) -> list[ExecResult]:
    """Test traffic from the toolbox while a capture runs: the same commands Diagnostics uses."""
    from .diagnostics import TCP_SCRIPT, TLS_SCRIPT, TRACE_ARGV
    tb = "toolbox"
    if traffic == "db":
        return [runner.exec(tb, ["timeout", "3", "bash", "-c", TCP_SCRIPT, "db.site-b.lab", "5432"], timeout=6),
                runner.exec(tb, ["bash", "-c", TLS_SCRIPT, "db.site-b.lab", "5432", "-starttls postgres"], timeout=10)]
    if traffic == "app":
        return [runner.exec(tb, ["curl", "-s", "-S", "-m", "4", "--cacert", "/lab-certs/ca-chain.pem",
                                 "https://app.site-b.lab:8443/health"], timeout=8)]
    if traffic == "ping_db":
        return [runner.exec(tb, ["ping", "-c", "3", "-W", "1", "-i", "0.3", "db.site-b.lab"], timeout=8)]
    if traffic == "ldaps":
        return [runner.exec(tb, ["timeout", "3", "bash", "-c", TCP_SCRIPT, "ldap.site-a.lab", "636"], timeout=6)]
    if traffic == "trace_db":
        return [runner.exec(tb, TRACE_ARGV + ["db.site-b.lab"], timeout=15)]
    return []


def capture(runner: Runner, point: str, flt: str, seconds: int, traffic: str,
            traffic_fn=generate) -> CaptureAnalysis:
    if point not in POINTS:
        raise CaptureError(f"unknown capture point; choose one of: {', '.join(POINTS)}")
    if flt not in FILTERS:
        raise CaptureError(f"unknown filter; choose one of: {', '.join(FILTERS)}")
    if not 3 <= seconds <= 30:
        raise CaptureError("duration must be 3-30 seconds")
    if traffic not in TRAFFIC:
        raise CaptureError(f"unknown traffic option; choose one of: {', '.join(TRAFFIC)}")
    if not _lock.acquire(blocking=False):
        raise CaptureError("another capture is running; wait for it to finish")
    try:
        cid = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
        remote = f"/tmp/wb-cap-{cid}.pcap"
        label, is_router = POINTS[point]
        argv = ["timeout", "-s", "INT", str(seconds), "tcpdump", "-ni", "any"]
        if is_router:
            argv += ["-Q", "in"]
        argv += ["-U", "-s", "256", "-c", str(MAX_PACKETS), "-w", remote] + FILTERS[flt][1]
        traffic_runs: list[ExecResult] = []
        t = None
        if traffic != "none" and traffic_fn:
            def gen():
                time.sleep(1.0)
                traffic_runs.extend(traffic_fn(runner, traffic))
            t = threading.Thread(target=gen, daemon=True)
            t.start()
        r = runner.exec(point, argv, timeout=seconds + 8)
        if t:
            t.join(timeout=seconds + 10)
        if not r.ran and r.error != "timeout":
            raise CaptureError(f"could not capture on {point}: {r.error}")
        if "packets captured" not in r.output:
            raise CaptureError("tcpdump did not finish cleanly: " + r.output.strip()[:300])
        raw = runner.get_file(point, remote, MAX_FILE)
        runner.exec(point, ["rm", "-f", remote])
        meta = CaptureMeta(id=cid, source="capture", point=point, point_label=label, filter=flt,
                           filter_label=FILTERS[flt][0], seconds=seconds, traffic=traffic,
                           created=now(), size=len(raw), packets=0)
        local = _push_to_toolbox(runner, raw, f"wb-an-{cid}.pcap")
        try:
            an = analyse(runner, meta, local, [r] + traffic_runs)
        finally:
            runner.exec("toolbox", ["rm", "-f", local])
        _save(an, raw)
        return an
    finally:
        _lock.release()


def upload(runner: Runner, raw: bytes, filename: str) -> CaptureAnalysis:
    if len(raw) > MAX_FILE:
        raise CaptureError("file too large (max 10 MB)")
    if not is_pcap(raw):
        raise CaptureError("not a pcap or pcapng file")
    cid = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)[:80] or "upload.pcap"
    meta = CaptureMeta(id=cid, source="upload", point="upload", point_label=f"Uploaded: {safe_name}",
                       filter="", filter_label="as recorded", seconds=0, traffic="none", created=now(),
                       size=len(raw), packets=0)
    local = _push_to_toolbox(runner, raw, f"wb-an-{cid}.pcap")
    try:
        an = analyse(runner, meta, local, [])
    finally:
        runner.exec("toolbox", ["rm", "-f", local])
    _save(an, raw)
    return an


def list_captures() -> list[CaptureMeta]:
    d = _store()
    metas = []
    for p in sorted(d.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            metas.append(CaptureMeta(**json.loads(p.read_text())["meta"]))
        except (ValueError, KeyError):
            continue
    return metas


def _check_id(cid: str) -> None:
    if not re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{4}", cid):
        raise CaptureError("bad capture id")


def load(cid: str) -> CaptureAnalysis:
    _check_id(cid)
    p = _store() / f"{cid}.json"
    if not p.exists():
        raise FileNotFoundError(cid)
    return CaptureAnalysis.model_validate_json(p.read_text())


def pcap_bytes(cid: str) -> bytes:
    _check_id(cid)
    p = _store() / f"{cid}.pcap"
    if not p.exists():
        raise FileNotFoundError(cid)
    return p.read_bytes()


def packet_detail(runner: Runner, cid: str, no: int) -> dict:
    an = load(cid)
    if not 1 <= no <= max(an.meta.packets, 1):
        raise CaptureError("no such packet")
    local = _push_to_toolbox(runner, pcap_bytes(cid), f"wb-pk-{cid}.pcap")
    try:
        r = runner.exec("toolbox", ["tshark", "-r", local, "-n", "-V", "-x", "-Y", f"frame.number=={no}"])
    finally:
        runner.exec("toolbox", ["rm", "-f", local])
    # tshark warns on stderr when run as root (it is, inside the toolbox container); not part of the decode
    text = "\n".join(l for l in r.output.splitlines() if not l.startswith("Running as user"))
    tree, _, hexdump = text.partition("\n\n0000")
    return {"no": no, "tree": tree.strip()[:20000], "hex": ("0000" + hexdump).strip()[:8000] if hexdump else "",
            "evidence": evidence(r).model_dump()}


def tar_one(path: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name=os.path.basename(path))
        info.size = len(data)
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def untar_one(stream: bytes, limit: int) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(stream), mode="r") as tf:
        member = next((m for m in tf.getmembers() if m.isfile()), None)
        if member is None:
            raise CaptureError("capture file missing")
        if member.size > limit:
            raise CaptureError("capture file too large")
        f = tf.extractfile(member)
        return f.read() if f else b""
