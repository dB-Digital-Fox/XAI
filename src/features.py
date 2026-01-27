# src/features.py
from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
import os
import json

try:
    import yaml  # optional; only needed if you use a YAML feature map
except Exception:
    yaml = None

SENSITIVE_PORTS = {22, 3389, 5985, 5986, 445}
ADMIN_SERVICES  = {"SSH", "RDP", "WINRM", "WMI"}
WEB_PORTS       = {80, 443}

FEATURE_MAP_PATH = os.getenv("FEATURE_MAP_PATH", "./config/feature_map.yaml")  # or .json

# ---------- low-level helpers ----------
def _to_int(x, default=0) -> int:
    try:
        return int(str(x))
    except Exception:
        return default

def _to_float(x, default=0.0) -> float:
    try:
        return float(str(x))
    except Exception:
        return default

def _severity_to_ord(sev) -> int:
    """
    Accepts string severities ('low'|'medium'|'high'|'critical') or numeric rule.level.
    Returns ordinal 0..3.
    """
    try:
        if isinstance(sev, (int, float)) or (isinstance(sev, str) and str(sev).isdigit()):
            lvl = int(sev)
            if lvl >= 12: return 3
            if lvl >= 9:  return 2
            if lvl >= 6:  return 1
            return 0
    except Exception:
        pass
    s = str(sev or "").strip().lower()
    if s == "critical": return 3
    if s == "high":     return 2
    if s == "medium":   return 1
    return 0

def _norm_service(port: int, service: str) -> str:
    svc = (service or "").strip().upper()
    if port == 22 or svc == "SSH": return "SSH"
    if port == 3389 or svc == "RDP": return "RDP"
    if port in (5985, 5986) or svc in ("WINRM", "WMI"): return "WINRM"
    if port == 161 or svc == "SNMP": return "SNMP"
    if port in WEB_PORTS or svc in ("HTTP", "HTTPS"): return "HTTPS" if port == 443 else "HTTP"
    if port == 53 or svc == "DNS": return "DNS"
    if port == 25 or svc in ("SMTP", "SMTPS"): return "SMTP"
    return svc or "NA"

def _norm_features_spec(fmap: dict) -> list[dict]:
    """
    Normalize feature map into a flat list of dicts:
      [{name, path, default}, ...]
    Supports:
      A) list of dicts   (with name/path/default)
      B) list of strings (name==path)
      C) flat dict       {name: path | {path, default}}
      D) nested dict     {section: { name: path|list|dict|string }}
         For nested/doc maps we default to the KEY as the canonical path.
    """
    feats = fmap.get("features", None)
    if feats is None:
        raise RuntimeError("feature_map missing 'features' key")

    out: list[dict] = []

    # A/B: list
    if isinstance(feats, list):
        for item in feats:
            if isinstance(item, dict):
                name = item.get("name") or item.get("path")
                path = item.get("path") or item.get("name")
                default = item.get("default", 0)
                if not name or not path:
                    raise RuntimeError(f"Invalid feature entry (list/dict): {item}")
                out.append({"name": str(name), "path": str(path), "default": default})
            elif isinstance(item, str):
                out.append({"name": item, "path": item, "default": 0})
            else:
                raise RuntimeError(f"Invalid feature entry type in list: {type(item).__name__}")
        return out

    # C/D: dict
    if isinstance(feats, dict):
        # If values are plain specs with 'path', treat as flat
        if all(not isinstance(v, dict) or "path" in v for v in feats.values()):
            for name, spec in feats.items():
                if isinstance(spec, str):
                    out.append({"name": str(name), "path": spec, "default": 0})
                elif isinstance(spec, dict):
                    path = spec.get("path") or name
                    default = spec.get("default", 0)
                    out.append({"name": str(name), "path": str(path), "default": default})
                else:
                    raise RuntimeError(f"Invalid feature spec for '{name}': {type(spec).__name__}")
            return out

        # Nested sections
        for section, section_dict in feats.items():
            if not isinstance(section_dict, dict):
                continue
            for name, spec in section_dict.items():
                if isinstance(spec, dict):
                    path = spec.get("path") or name
                    default = spec.get("default", 0)
                    out.append({"name": str(name), "path": str(path), "default": default})
                else:
                    # list / string / prose → use canonical key as path
                    out.append({"name": str(name), "path": str(name), "default": 0})
        return out

    raise RuntimeError(f"Unsupported 'features' type: {type(feats).__name__}")

def _augment_canonical(canon: dict) -> dict:
    """
    Add derived booleans/buckets so feature_map paths resolve even when a map is used.
    Works for network + endpoint/server records.
    """
    out = dict(canon)  # shallow copy

    # ---- bytes/ports/proto ----
    bs = int(out.get("bytes_sent", 0) or 0)
    br = int(out.get("bytes_recv", 0) or 0)
    out["bytes_total"] = bs + br

    dst_port = int(out.get("dst_port", 0) or 0)
    out["port_bucket_low"]  = 1 if 0 < dst_port <= 1024 else 0
    out["port_bucket_mid"]  = 1 if 1025 <= dst_port <= 49151 else 0
    out["port_bucket_high"] = 1 if dst_port >= 49152 else 0

    # normalize proto to string token; accept numbers (1/6/17)
    raw_proto = str(out.get("proto", "")).strip().lower()
    if raw_proto.isdigit():
        code = int(raw_proto)
        if code == 6:
            token = "tcp"
        elif code == 17:
            token = "udp"
        elif code == 1:
            token = "icmp"
        else:
            token = "other"
    else:
        token = raw_proto

    out["proto_tcp"]  = 1 if token == "tcp"  else 0
    out["proto_udp"]  = 1 if token == "udp"  else 0
    out["proto_icmp"] = 1 if token == "icmp" else 0

    # ---- services (one-hot from service_label) ----
    svc = str(out.get("service_label", "") or "").upper()
    out["service_snmp"]  = 1 if svc == "SNMP"  else 0
    out["service_ssh"]   = 1 if svc == "SSH"   else 0
    out["service_rdp"]   = 1 if svc == "RDP"   else 0
    out["service_winrm"] = 1 if svc == "WINRM" else 0
    out["service_smtp"]  = 1 if svc == "SMTP"  else 0
    out["service_http"]  = 1 if svc == "HTTP"  else 0
    out["service_https"] = 1 if svc == "HTTPS" else 0

    # ---- severity already normalized to ordinal; ensure int ----
    out["severity_ord"] = int(out.get("severity_ord", 0) or 0)

    # dst_svc flags already set by your canonicalizer; ensure int
    out["dst_svc_sensitive"] = 1 if out.get("dst_svc_sensitive") else 0
    out["dst_svc_admin"]     = 1 if out.get("dst_svc_admin") else 0

    # auth result (ensure two one-hots exist even if not auth records)
    ar = int(out.get("auth_result", -1) if out.get("auth_result", -1) is not None else -1)
    out["auth_result_pos"] = 1 if ar == 1 else 0
    out["auth_result_neg"] = 1 if ar == 0 else 0

    # --- actions ---
    act = str(out.get("action", "") or "").lower()
    out["action_allowed"] = 1 if act in ("allow", "allowed", "accept", "permitted") else 0
    out["action_blocked"] = 1 if act in ("block", "blocked", "deny", "denied") else 0
    out["action_dropped"] = 1 if act in ("drop", "dropped") else 0

    # --- simple IP traits (no external DB needed) ---
    def _is_private(ip: str) -> int:
        try:
            import ipaddress
            return 1 if ip and ipaddress.ip_address(ip).is_private else 0
        except Exception:
            return 0

    src_ip = str(out.get("src_ip") or "")
    dst_ip = str(out.get("dst_ip") or "")
    out["src_is_private"] = _is_private(src_ip)
    out["dst_is_private"] = _is_private(dst_ip)

    # crude /24 matching if both are IPv4
    def _same24(a: str, b: str) -> int:
        try:
            a4 = a.split("."); b4 = b.split(".")
            return 1 if len(a4)==4 and len(b4)==4 and a4[:3]==b4[:3] else 0
        except Exception:
            return 0
    out["same_subnet_24"] = _same24(src_ip, dst_ip)

    # --- direction heuristic ---
    out["dir_ingress"] = 1 if act in ("allow","allowed","accept") and out.get("pf_nw")==1 and out.get("dst_is_private")==1 else 0
    out["dir_egress"]  = 1 if act in ("allow","allowed","accept") and out.get("pf_nw")==1 and out.get("src_is_private")==1 and out.get("dst_is_private")==0 else 0
    out["dir_internal"]= 1 if out.get("src_is_private")==1 and out.get("dst_is_private")==1 else 0

    return out

def _platform_flags(source: str) -> Dict[str, int]:
    src = (source or "").lower()
    return {
        "pf_win":   1 if ("windows" in src or "win" in src) else 0,
        "pf_lin":   1 if "linux" in src else 0,
        "pf_nw":    1 if any(k in src for k in ["fortigate", "cisco", "unifi", "firewall", "router", "switch"]) else 0,
        "pf_osks":  1 if "openstack" in src else 0,
    }

# ---------- source detection ----------
def _detect_source(alert: Dict[str, Any]) -> str:
    dec = (alert.get("decoder", {}) or {}).get("name", "").lower()
    groups = [g.lower() for g in (alert.get("rule", {}) or {}).get("groups", []) or []]
    agent  = (alert.get("agent", {}) or {}).get("name", "").lower()
    full   = " ".join([dec, " ".join(groups), agent])

    if any(k in full for k in ["fortigate", "cisco", "unifi", "asa", "firewall", "router", "switch"]):
        return "fortigate" if "fortigate" in full else ("cisco" if "cisco" in full or "asa" in full else "unifi")
    if "windows" in full or "win" in dec or "win" in agent or alert.get("win", {}).get("event"):
        return "windows"
    if "linux" in full:
        return "linux"
    if any(k in full for k in ["openstack", "nova", "keystone", "neutron"]):
        return "openstack"
    if (alert.get("data", {}) or {}).get("devid") or (alert.get("data", {}) or {}).get("subtype") == "ips":
        return "fortigate"
    return "generic"

# ---------- canonical mappers ----------
def _map_network_like(alert: Dict[str, Any]) -> Dict[str, Any]:
    d = alert.get("data", {}) or {}
    r = alert.get("rule", {}) or {}
    src_port = _to_int(d.get("srcport"))
    dst_port = _to_int(d.get("dstport"))
    svc = _norm_service(dst_port, d.get("service", ""))

    out = {
        "src_ip": d.get("srcip") or d.get("src"),
        "dst_ip": d.get("dstip") or d.get("dst"),
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": d.get("proto") or d.get("proto_name") or "na",

        "bytes_sent": _to_int(d.get("sentbyte"), 0),
        "bytes_recv": _to_int(d.get("rcvdbyte"), 0),
        "duration_sec": _to_int(d.get("duration"), 0),

        "rule_level": _to_int(r.get("level"), 0),
        "severity_ord": _severity_to_ord(d.get("severity") if d.get("severity") is not None else r.get("level")),
        "action": (d.get("action") or "").lower(),
        "threat_family": (d.get("subtype") or "na").lower(),
        "service_label": svc,

        "user": d.get("srcuser") or "",
        "host": d.get("devname") or (alert.get("agent", {}) or {}).get("name", ""),
        "platform_source": "network",
    }
    return out

def _map_windows(alert: Dict[str, Any]) -> Dict[str, Any]:
    win = (alert.get("win", {}) or {}).get("event", {}) or {}
    code = str(win.get("code") or "")
    auth_result = -1
    if code == "4624": auth_result = 1
    elif code == "4625": auth_result = 0
    logon_type = str(win.get("LogonType") or win.get("logon_type") or "")
    service_label = "RDP" if logon_type in ("10", "7") else "NA"
    r = alert.get("rule", {}) or {}
    return {
        "src_ip": win.get("IpAddress") or "",
        "dst_ip": "",
        "src_port": _to_int(win.get("IpPort"), 0),
        "dst_port": 3389 if service_label == "RDP" else 0,
        "proto": "tcp",
        "bytes_sent": 0,
        "bytes_recv": 0,
        "duration_sec": 0,
        "rule_level": _to_int(r.get("level"), 0),
        "severity_ord": 0,
        "action": "na",
        "threat_family": "auth",
        "service_label": service_label,
        "user": win.get("TargetUserName") or win.get("AccountName") or "",
        "host": (alert.get("agent", {}) or {}).get("name", ""),
        "platform_source": "windows",
        "auth_result": auth_result,
        "logon_type": logon_type or "na",
    }

def _map_linux(alert: Dict[str, Any]) -> Dict[str, Any]:
    msg = (alert.get("full_log") or "").lower()
    auth_result = 1 if "accepted password" in msg else (0 if "failed password" in msg else -1)
    return {
        "src_ip": "",
        "dst_ip": "",
        "src_port": 0,
        "dst_port": 22 if "sshd" in msg else 0,
        "proto": "tcp",
        "bytes_sent": 0,
        "bytes_recv": 0,
        "duration_sec": 0,
        "rule_level": _to_int((alert.get("rule", {}) or {}).get("level"), 0),
        "severity_ord": 0,
        "action": "na",
        "threat_family": "auth" if "sshd" in msg else "na",
        "service_label": "SSH" if "sshd" in msg else "NA",
        "user": "",
        "host": (alert.get("agent", {}) or {}).get("name", ""),
        "platform_source": "linux",
        "auth_result": auth_result,
        "logon_type": "na",
    }

def _map_openstack(alert: Dict[str, Any]) -> Dict[str, Any]:
    d = alert.get("data", {}) or {}
    outcome = str(d.get("outcome") or d.get("status") or "").lower()
    auth_result = 1 if outcome == "success" else (0 if outcome == "failure" else -1)
    return {
        "src_ip": d.get("remote_address") or "",
        "dst_ip": "",
        "src_port": 0,
        "dst_port": 0,
        "proto": "tcp",
        "bytes_sent": _to_int(d.get("bytes_sent"), 0),
        "bytes_recv": _to_int(d.get("bytes_received"), 0),
        "duration_sec": _to_int(d.get("duration"), 0),
        "rule_level": _to_int((alert.get("rule", {}) or {}).get("level"), 0),
        "severity_ord": 0,
        "action": "na",
        "threat_family": "auth" if auth_result != -1 else "na",
        "service_label": "API",
        "user": d.get("username") or "",
        "host": d.get("service") or "openstack",
        "platform_source": "openstack",
        "auth_result": auth_result,
        "logon_type": "api",
    }

def _map_generic(alert: Dict[str, Any]) -> Dict[str, Any]:
    d = alert.get("data", {}) or {}
    r = alert.get("rule", {}) or {}
    return {
        "src_ip": d.get("srcip") or "",
        "dst_ip": d.get("dstip") or "",
        "src_port": _to_int(d.get("srcport"), 0),
        "dst_port": _to_int(d.get("dstport"), 0),
        "proto": d.get("proto") or "na",
        "bytes_sent": _to_int(d.get("sentbyte"), 0),
        "bytes_recv": _to_int(d.get("rcvdbyte"), 0),
        "duration_sec": _to_int(d.get("duration"), 0),
        "rule_level": _to_int(r.get("level"), 0),
        "severity_ord": _severity_to_ord(d.get("severity") if d.get("severity") is not None else r.get("level")),
        "action": (d.get("action") or "na").lower(),
        "threat_family": (d.get("subtype") or "na").lower(),
        "service_label": _norm_service(_to_int(d.get("dstport"), 0), d.get("service", "")),
        "user": d.get("user") or "",
        "host": (alert.get("agent", {}) or {}).get("name", ""),
        "platform_source": "generic",
    }

def _canonicalize(alert: Dict[str, Any]) -> Dict[str, Any]:
    src = _detect_source(alert)
    if src in ("fortigate", "cisco", "unifi"):
        base = _map_network_like(alert)
    elif src == "windows":
        base = _map_windows(alert)
    elif src == "linux":
        base = _map_linux(alert)
    elif src == "openstack":
        base = _map_openstack(alert)
    else:
        base = _map_generic(alert)

    base.update(_platform_flags(src))
    base["bytes_total"] = _to_int(base.get("bytes_sent"), 0) + _to_int(base.get("bytes_recv"), 0)
    port = _to_int(base.get("dst_port"), 0)
    base["dst_svc_sensitive"] = 1 if port in SENSITIVE_PORTS else 0
    base["dst_svc_admin"] = 1 if (base.get("service_label") in ADMIN_SERVICES) else 0
    base["hour"] = 0  # placeholder; parse timestamp if you want hour-of-day
    return base

# ---------- feature map support ----------
def _load_feature_map(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        return None
    if path.endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    # yaml
    if path.endswith(".yaml") or path.endswith(".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is not installed but a YAML feature map was provided.")
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    raise RuntimeError(f"Unsupported feature map extension: {path}")

def _apply_feature_map(canon: Dict[str, Any], fmap: Dict[str, Any]) -> Dict[str, float]:
    """
    fmap schema:
      schema_version: 1
      features:
        - { name: rule_level,        path: rule_level,        default: 0 }
        - { name: severity_ord,      path: severity_ord,      default: 0 }
        - { name: bytes_sent,        path: bytes_sent,        default: 0 }
        ...
    """
    out: Dict[str, float] = {}
    flist = _norm_features_spec(fmap)
    for item in flist:
        name = item["name"]
        path = item["path"]  # for nested/doc maps this will usually equal 'name'
        default = item.get("default", 0)
        val = canon.get(path, default)  # we read from canonical dict
        try:
            out[name] = float(val)
        except Exception:
            out[name] = float(default)
    return out


# ---------- public API ----------
def extract_features(alert: dict) -> dict:
    """
    Returns a dict of numeric/boolean features in a stable order.
    If FEATURE_MAP_PATH exists, uses it to decide feature names + order.
    Otherwise returns the default compact vector.
    """
    canon = _canonicalize(alert)
    canon = _augment_canonical(canon)

    fmap = _load_feature_map(FEATURE_MAP_PATH)
    if fmap:
        feats = _apply_feature_map(canon, fmap)
        return feats

    # default compact vector (keep order stable!)
    feats = {
        "rule_level": _to_int(canon.get("rule_level"), 0),
        "severity_ord": _to_int(canon.get("severity_ord"), 0),

        "bytes_sent": _to_int(canon.get("bytes_sent"), 0),
        "bytes_recv": _to_int(canon.get("bytes_recv"), 0),
        "bytes_total": _to_int(canon.get("bytes_total"), 0),
        "duration_sec": _to_int(canon.get("duration_sec"), 0),

        "dst_port": _to_int(canon.get("dst_port"), 0),
        "dst_svc_sensitive": 1 if canon.get("dst_svc_sensitive") else 0,
        "dst_svc_admin": 1 if canon.get("dst_svc_admin") else 0,

        "pf_win": _to_int(canon.get("pf_win"), 0),
        "pf_lin": _to_int(canon.get("pf_lin"), 0),
        "pf_nw":  _to_int(canon.get("pf_nw"), 0),
        "pf_osks":_to_int(canon.get("pf_osks"), 0),

        "auth_result_pos": 1 if canon.get("auth_result", -1) == 1 else 0,
        "auth_result_neg": 1 if canon.get("auth_result", -1) == 0 else 0,

        "service_snmp": 1 if (canon.get("service_label") == "SNMP") else 0,
        "service_ssh":  1 if (canon.get("service_label") == "SSH") else 0,
        "service_rdp":  1 if (canon.get("service_label") == "RDP") else 0,
        "service_winrm":1 if (canon.get("service_label") == "WINRM") else 0,

        "hour": _to_int(canon.get("hour"), 0),
    }
    return feats

def get_feature_names() -> list[str]:
    """
    Returns the feature names in the exact order:
    - If a feature map exists, the 'name' fields in that order
    - Else, the default compact vector order (keys returned by extract_features on an empty canonical)
    """
    fmap = _load_feature_map(FEATURE_MAP_PATH)
    if fmap:
        return [it["name"] for it in _norm_features_spec(fmap)]
    # fallback to default compact vector order
    return [
        "rule_level","severity_ord",
        "bytes_sent","bytes_recv","bytes_total","duration_sec",
        "dst_port","dst_svc_sensitive","dst_svc_admin",
        "pf_win","pf_lin","pf_nw","pf_osks",
        "auth_result_pos","auth_result_neg",
        "service_snmp","service_ssh","service_rdp","service_winrm",
        "hour",
    ]