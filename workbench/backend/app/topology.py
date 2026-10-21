"""Live network map: the lab's designed topology overlaid with what the routers report right now.

Static (from docker-compose.yml): which devices exist, which subnet each link uses.
Live (from the routers): interface state and MTU, OSPF adjacency per link, OSPF cost, routing
tables, and the path traffic from Site A to the database actually takes (traceroute).
"""
from __future__ import annotations

import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor

from .checks import evidence, now
from .diagnostics import ADDRESS_OWNER, asymmetric_hops, parse_trace, trace
from .models import (Evidence, Fact, MapEnd, MapInterface, MapLink, MapNeighbor, MapPath,
                     MapRoute, MapRouter, Topology)
from .runner import ExecResult, Runner

ROUTER_IDS = {"1.1.1.1": "r1", "2.2.2.2": "r2", "3.3.3.3": "r3"}

LINKS = [
    # id, label, subnet, kind, ends (router, address)
    ("lan_a", "Site A LAN", "10.10.10.0/24", "lan", [("r1", "10.10.10.2")]),
    ("r1_r2", "r1 – r2 core", "10.0.12.0/24", "transit", [("r1", "10.0.12.11"), ("r2", "10.0.12.12")]),
    ("r2_r3", "r2 – r3 core", "10.0.23.0/24", "transit", [("r2", "10.0.23.22"), ("r3", "10.0.23.23")]),
    ("r1_r3", "r1 – r3 backup", "10.0.13.0/24", "transit", [("r1", "10.0.13.11"), ("r3", "10.0.13.13")]),
    ("lan_b", "Site B LAN", "10.20.20.0/24", "lan", [("r3", "10.20.20.2")]),
]
HOSTS_NAMES = {"db": "db.site-b.lab"}
PAIR_LINK = {("toolbox", "r1"): "lan_a", ("r1", "r2"): "r1_r2", ("r2", "r3"): "r2_r3",
             ("r1", "r3"): "r1_r3", ("r3", "db"): "lan_b"}
HOSTS = {"toolbox": "10.10.10.10", "ldap": "10.10.10.20", "db": "10.20.20.10",
         "kms": "10.20.20.20", "app": "10.20.20.30"}


def link_for(ip: str) -> str | None:
    a = ipaddress.ip_address(ip)
    for lid, _, subnet, _, _ in LINKS:
        if a in ipaddress.ip_network(subnet):
            return lid
    return None


# ------------------------------------------------------------------ parsers (real FRR / iproute2 JSON)

def parse_addr(out: str) -> list[dict]:
    res = []
    for i in json.loads(out or "[]"):
        if i.get("ifname") == "lo":
            continue
        v4 = [a for a in i.get("addr_info", []) if a.get("family") == "inet"]
        res.append({"name": i.get("ifname", "?"), "state": i.get("operstate", "UNKNOWN"),
                    "mtu": i.get("mtu"),
                    "address": f'{v4[0]["local"]}/{v4[0]["prefixlen"]}' if v4 else None})
    return res


def parse_ospf_if(out: str) -> dict[str, dict]:
    data = json.loads(out or "{}")
    ifs = data.get("interfaces", data)
    return {name: {"cost": d.get("cost"), "role": d.get("state"), "mtu": d.get("mtuBytes"),
                   "nbr": d.get("nbrCount"), "adj": d.get("nbrAdjacentCount")}
            for name, d in ifs.items() if isinstance(d, dict)}


def parse_neighbors(out: str) -> list[dict]:
    from .checks import parse_ospf_neighbors
    return parse_ospf_neighbors(out)


def parse_routes(out: str) -> list[dict]:
    data = json.loads(out or "{}")
    res = []
    for prefix, entries in data.items():
        for e in entries:
            if not e.get("selected"):
                continue
            nh = (e.get("nexthops") or [{}])[0]
            res.append({"prefix": prefix, "protocol": e.get("protocol", "?"),
                        "next_hop": nh.get("ip") or "directly connected",
                        "interface": nh.get("interfaceName", ""),
                        "metric": e.get("metric"), "distance": e.get("distance")})
    return sorted(res, key=lambda r: ipaddress.ip_network(r["prefix"]))


# ------------------------------------------------------------------ collection

COMMANDS = {
    "addr": ["ip", "-j", "addr", "show"],
    "nbr": ["vtysh", "-c", "show ip ospf neighbor json"],
    "ospfif": ["vtysh", "-c", "show ip ospf interface json"],
    "routes": ["vtysh", "-c", "show ip route json"],
}


def _router(name: str, runs: dict[str, ExecResult]) -> MapRouter:
    ev = [evidence(r) for r in runs.values()]
    if any(not r.ran and r.error != "timeout" for r in runs.values()):
        err = next(r.error for r in runs.values() if not r.ran)
        return MapRouter(id=name, status="down" if err != "docker_unavailable" else "unknown",
                         summary="Container not running" if err != "docker_unavailable" else "Docker unreachable",
                         interfaces=[], neighbors=[], routes=[], evidence=ev)
    try:
        addrs = parse_addr(runs["addr"].output)
        ospf = parse_ospf_if(runs["ospfif"].output)
        nbrs = parse_neighbors(runs["nbr"].output)
        routes = parse_routes(runs["routes"].output)
    except (ValueError, KeyError, TypeError):
        return MapRouter(id=name, status="unknown", summary="Unreadable router output",
                         interfaces=[], neighbors=[], routes=[], evidence=ev)
    interfaces = []
    for a in addrs:
        o = ospf.get(a["name"], {})
        interfaces.append(MapInterface(
            name=a["name"], address=a["address"], state=a["state"], mtu=a["mtu"],
            link=link_for(a["address"].split("/")[0]) if a["address"] else None,
            ospf_cost=o.get("cost"), ospf_role=o.get("role"),
            ospf_neighbors=o.get("nbr"), ospf_adjacent=o.get("adj")))
    neighbors = [MapNeighbor(router_id=n["router_id"], name=ROUTER_IDS.get(n["router_id"], n["router_id"]),
                             state=n["state"], interface=n["iface"], address=n["address"],
                             link=link_for(n["address"]) if n["address"] else None) for n in nbrs]
    full = sum(1 for n in neighbors if n.state.startswith("Full"))
    status = "ok" if full >= 2 else ("degraded" if full else "down")
    summary = f"{full}/2 OSPF neighbours Full · {len(routes)} routes"
    return MapRouter(id=name, status=status, summary=summary, interfaces=interfaces, neighbors=neighbors,
                     routes=[MapRoute(**r) for r in routes], evidence=ev)


def _link(lid: str, label: str, subnet: str, kind: str, ends: list[tuple[str, str]],
          routers: dict[str, MapRouter]) -> MapLink:
    map_ends: list[MapEnd] = []
    problems: list[str] = []
    for rname, ip in ends:
        rt = routers[rname]
        iface = next((i for i in rt.interfaces if i.address and i.address.split("/")[0] == ip), None)
        nbr = next((n for n in rt.neighbors if n.link == lid), None)
        map_ends.append(MapEnd(router=rname, address=ip, interface=iface.name if iface else None,
                               state=iface.state if iface else None, mtu=iface.mtu if iface else None,
                               ospf_cost=iface.ospf_cost if iface else None,
                               neighbor_state=nbr.state if nbr else None))
        if rt.status in ("unknown",) or (rt.status == "down" and not rt.interfaces):
            problems.append(f"{rname} not reporting")
        elif iface is None:
            problems.append(f"{rname} has no interface on {subnet}")
        elif iface.state != "UP":
            problems.append(f"{rname} {iface.name} is {iface.state}")
    if any("not reporting" in p for p in problems):
        return MapLink(id=lid, label=label, subnet=subnet, kind=kind, status="unknown",
                       summary="; ".join(problems), ends=map_ends)
    if problems:
        return MapLink(id=lid, label=label, subnet=subnet, kind=kind, status="down",
                       summary="; ".join(problems), ends=map_ends)
    if kind == "lan":
        return MapLink(id=lid, label=label, subnet=subnet, kind=kind, status="ok",
                       summary="Router interface up", ends=map_ends)
    states = [e.neighbor_state for e in map_ends]
    if all(s and s.startswith("Full") for s in states):
        cost = map_ends[0].ospf_cost
        return MapLink(id=lid, label=label, subnet=subnet, kind=kind, status="ok",
                       summary=f"OSPF adjacency Full · cost {cost}", ends=map_ends)
    seen = [s for s in states if s]
    if seen:
        return MapLink(id=lid, label=label, subnet=subnet, kind=kind, status="degraded",
                       summary=f"Interfaces up, OSPF adjacency not Full ({' / '.join(seen)})", ends=map_ends)
    return MapLink(id=lid, label=label, subnet=subnet, kind=kind, status="down",
                   summary="Interfaces up, but no OSPF adjacency", ends=map_ends)


def _path(runs: list[ExecResult]) -> MapPath:
    r = runs[-1]
    ev = [evidence(x) for x in runs]
    if not r.ran and r.error != "timeout":
        return MapPath(source="toolbox", destination="db", hops=[], links=[], reached=False,
                       uses_backup=False, summary="Could not trace (toolbox not running)", evidence=ev, notes=[])
    hops = parse_trace(r.output)
    # Links from consecutive devices (not from reply addresses, which can mislead when routing
    # is asymmetric).
    seq = ["toolbox"] + [ADDRESS_OWNER.get(h, h) for h in hops if h]
    links = [PAIR_LINK[(a, b)] for a, b in zip(seq, seq[1:]) if (a, b) in PAIR_LINK]
    reached = bool(hops) and hops[-1] == HOSTS["db"]
    names = [ADDRESS_OWNER.get(h, h) if h else "*" for h in hops]
    backup = "r1_r3" in links
    notes = asymmetric_hops(hops)
    shown = names if reached else [n for n in names if n != "*"]
    summary = ("toolbox → " + " → ".join(shown)) if shown else "No hops answered"
    if not reached:
        summary += " → ? (db did not answer the trace)"
    return MapPath(source="toolbox", destination="db", hops=[Fact(label=h or "*", value=n) for h, n in zip(hops, names)],
                   links=links, reached=reached, uses_backup=backup, summary=summary, evidence=ev,
                   notes=notes)


def collect(runner: Runner) -> Topology:
    jobs = [(rt, key, argv) for rt in ("r1", "r2", "r3") for key, argv in COMMANDS.items()]
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {(rt, key): pool.submit(runner.exec, rt, argv) for rt, key, argv in jobs}
        path_runs = pool.submit(trace, runner, HOSTS_NAMES["db"], HOSTS["db"])
        results: dict[str, dict[str, ExecResult]] = {"r1": {}, "r2": {}, "r3": {}}
        for (rt, key), f in futs.items():
            results[rt][key] = f.result()
        trace_runs = path_runs.result()
    routers = {rt: _router(rt, runs) for rt, runs in results.items()}
    links = [_link(*spec, routers=routers) for spec in LINKS]
    return Topology(routers=list(routers.values()), links=links, path=_path(trace_runs),
                    hosts=[Fact(label=k, value=v) for k, v in HOSTS.items()], checked_at=now())


__all__ = ["collect", "Evidence"]
