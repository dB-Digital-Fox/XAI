# src/features.py
from typing import Dict, Any

SENSITIVE_PORTS = {22, 3389, 5985, 5986, 445}
ADMIN_SERVICES  = {"SSH","RDP","WINRM","WMI"}
WEB_PORTS       = {80, 443}

def _to_int(x, default=0):
    try: return int(str(x))
    except: return default

def _to_float(x, default=0.0):
    try: return float(str(x))
    except: return default

def _norm_service(port: int, service: str) -> str:
    svc = (service or "").strip().upper()
    if port == 22 or svc == "SSH": return "SSH"
    if port in (3389,) or svc == "RDP": return "RDP"
    if port in (5985,5986) or svc in ("WINRM","WMI"): return "WINRM"
    if port == 161 or svc == "SNMP": return "SNMP"
    if port in WEB_PORTS or svc in ("HTTP","HTTPS"): return "HTTP" if port == 80 else "HTTPS"
    if port == 53 or svc == "DNS": return "DNS"
    if port == 25 or svc in ("SMTP","SMTPS"): return "SMTP"
    return svc or "NA"

def _severity_to_ord(sev) -> int:
    """
    Accepts:
      - string severities: 'low'|'medium'|'high'|'critical'
      - numeric severities (e.g., Wazuh rule.level int)
    Returns an ordinal 0..3.
    """
    # If it's numeric (or numeric-looking), map rule levels to ordinal buckets
    try:
        if isinstance(sev, (int, float)) or (isinstance(sev, str) and sev.isdigit()):
            lvl = int(sev)
            # rough buckets; tune if you want different cutoffs
            if lvl >= 12:
                return 3  # critical
            if lvl >= 9:
                return 2  # high
            if lvl >= 6:
                return 1  # medium
            return 0      # low / info
    except Exception:
        pass

    # Otherwise treat as string severity
    s = str(sev or "").strip().lower()
    if s == "critical":
        return 3
    if s == "high":
        return 2
    if s == "medium":
        return 1
    # default (includes 'low', '', unknown)
    return 0

def _platform_flags(source: str) -> Dict[str,int]:
    # mutually non-exclusive tiny hints
    src = (source or "").lower()
    return {
        "pf_win":   1 if "windows" in src or "win" in src else 0,
        "pf_lin":   1 if "linux" in src else 0,
        "pf_nw":    1 if any(k in src for k in ["fortigate","cisco","unifi","firewall","router","switch"]) else 0,
        "pf_osks":  1 if "openstack" in src else 0,
    }

def _detect_source(alert: Dict[str,Any]) -> str:
    # heuristic using decoder/groups/platformish fields
    dec = (alert.get("decoder",{}) or {}).get("name","")
    groups = alert.get("rule",{}).get("groups",[]) or []
    if "fortigate" in groups or "fortigate" in dec: return "fortigate"
    if "cisco" in groups or "asa" in dec: return "cisco"
    if "unifi" in groups or "unifi" in dec: return "unifi"
    if "windows" in groups or "win" in dec or "win" in str(alert.get("agent",{}).get("name","")).lower(): return "windows"
    if "linux" in groups or "linux" in dec: return "linux"
    if "openstack" in groups or "openstack" in dec: return "openstack"
    # default: try to infer by fields
    if alert.get("win",{}).get("event"): return "windows"
    if alert.get("data",{}).get("devid") or alert.get("data",{}).get("subtype") == "ips": return "fortigate"
    return "generic"

def _map_network_like(alert: Dict[str,Any]) -> Dict[str,Any]:
    d = alert.get("data",{}) or {}
    r = alert.get("rule",{}) or {}
    src_port = _to_int(d.get("srcport"))
    dst_port = _to_int(d.get("dstport"))
    svc = _norm_service(dst_port, d.get("service",""))
    return {
        "src_ip": d.get("srcip") or d.get("src"),
        "dst_ip": d.get("dstip") or d.get("dst"),
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": d.get("proto") or d.get("proto_name"),
        "bytes_sent": _to_int(d.get("sentbyte"),0),
        "bytes_recv": _to_int(d.get("rcvdbyte"),0),
        "duration_sec": _to_int(d.get("duration"),0),
        "rule_level": _to_int(r.get("level"),0),
        "severity_ord": _severity_to_ord(d.get("severity") or r.get("level")),
        "action": (d.get("action") or "").lower(),
        "threat_family": (d.get("subtype") or "na").lower(),
        "service_label": svc,
        "user": d.get("srcuser") or "",
        "host": d.get("devname") or alert.get("agent",{}).get("name",""),
        "platform_source": "network",
    }

def _map_windows(alert: Dict[str,Any]) -> Dict[str,Any]:
    win = (alert.get("win",{}) or {}).get("event",{}) or {}
    code = str(win.get("code") or "")
    # rough auth mapping
    auth_result = -1
    if code == "4624": auth_result = 1
    elif code == "4625": auth_result = 0
    logon_type = str(win.get("LogonType") or win.get("logon_type") or "")
    # service guess
    service_label = "RDP" if logon_type in ("10","7") else "NA"
    r = alert.get("rule",{}) or {}
    return {
        "src_ip": win.get("IpAddress") or "",
        "dst_ip": "",
        "src_port": _to_int(win.get("IpPort"),0),
        "dst_port": 3389 if service_label=="RDP" else 0,
        "proto": "tcp",
        "bytes_sent": 0, "bytes_recv": 0,
        "duration_sec": 0,
        "rule_level": _to_int(r.get("level"),0),
        "severity_ord": 0,
        "action": "na",
        "threat_family": "auth",
        "service_label": service_label,
        "user": win.get("TargetUserName") or win.get("AccountName") or "",
        "host": alert.get("agent",{}).get("name",""),
        "platform_source": "windows",
        "auth_result": auth_result,
        "logon_type": logon_type or "na"
    }

def _map_linux(alert: Dict[str,Any]) -> Dict[str,Any]:
    # very light; extend as needed
    msg = (alert.get("full_log") or "").lower()
    auth_result = 1 if "accepted password" in msg else (0 if "failed password" in msg else -1)
    return {
        "src_ip": "",
        "dst_ip": "",
        "src_port": 0, "dst_port": 22 if "sshd" in msg else 0,
        "proto": "tcp",
        "bytes_sent": 0, "bytes_recv": 0,
        "duration_sec": 0,
        "rule_level": _to_int(alert.get("rule",{}).get("level"),0),
        "severity_ord": 0,
        "action": "na",
        "threat_family": "auth" if "sshd" in msg else "na",
        "service_label": "SSH" if "sshd" in msg else "NA",
        "user": "", "host": alert.get("agent",{}).get("name",""),
        "platform_source": "linux",
        "auth_result": auth_result,
        "logon_type": "na"
    }

def _map_openstack(alert: Dict[str,Any]) -> Dict[str,Any]:
    d = alert.get("data",{}) or {}
    # keystone auth logs often have outcome/status + username/tenant
    auth_result = -1
    outcome = str(d.get("outcome") or d.get("status") or "").lower()
    if outcome == "success": auth_result = 1
    elif outcome == "failure": auth_result = 0
    return {
        "src_ip": d.get("remote_address") or "",
        "dst_ip": "",
        "src_port": 0, "dst_port": 0,
        "proto": "tcp",
        "bytes_sent": _to_int(d.get("bytes_sent"),0),
        "bytes_recv": _to_int(d.get("bytes_received"),0),
        "duration_sec": _to_int(d.get("duration"),0),
        "rule_level": _to_int(alert.get("rule",{}).get("level"),0),
        "severity_ord": 0,
        "action": "na",
        "threat_family": "auth" if auth_result != -1 else "na",
        "service_label": "API",
        "user": d.get("username") or "",
        "host": d.get("service") or "openstack",
        "platform_source": "openstack",
        "auth_result": auth_result,
        "logon_type": "api"
    }

def _map_generic(alert: Dict[str,Any]) -> Dict[str,Any]:
    d = alert.get("data",{}) or {}
    r = alert.get("rule",{}) or {}
    return {
        "src_ip": d.get("srcip") or "",
        "dst_ip": d.get("dstip") or "",
        "src_port": _to_int(d.get("srcport"),0),
        "dst_port": _to_int(d.get("dstport"),0),
        "proto": d.get("proto") or "na",
        "bytes_sent": _to_int(d.get("sentbyte"),0),
        "bytes_recv": _to_int(d.get("rcvdbyte"),0),
        "duration_sec": _to_int(d.get("duration"),0),
        "rule_level": _to_int(r.get("level"),0),
        "severity_ord": 0,
        "action": (d.get("action") or "na").lower(),
        "threat_family": (d.get("subtype") or "na").lower(),
        "service_label": _norm_service(_to_int(d.get("dstport"),0), d.get("service","")),
        "user": d.get("user") or "",
        "host": alert.get("agent",{}).get("name",""),
        "platform_source": "generic"
    }

def _canonicalize(alert: Dict[str,Any]) -> Dict[str,Any]:
    src = _detect_source(alert)
    if src in ("fortigate","cisco","unifi"): base = _map_network_like(alert)
    elif src == "windows": base = _map_windows(alert)
    elif src == "linux": base = _map_linux(alert)
    elif src == "openstack": base = _map_openstack(alert)
    else: base = _map_generic(alert)
    base.update(_platform_flags(src))
    # small post-derivations
    base["bytes_total"] = _to_int(base.get("bytes_sent"),0) + _to_int(base.get("bytes_recv"),0)
    port = _to_int(base.get("dst_port"),0)
    base["dst_svc_sensitive"] = 1 if port in SENSITIVE_PORTS else 0
    base["dst_svc_admin"] = 1 if (base.get("service_label") in ADMIN_SERVICES) else 0
    # placeholder hour
    base["hour"] = 0
    return base

def extract_features(alert: dict) -> dict:
    c = _canonicalize(alert)

    # final numeric/boolean feature vector (fixed order!)
    feats = {
        "rule_level": _to_int(c.get("rule_level"),0),
        "severity_ord": _to_int(c.get("severity_ord"),0),

        "bytes_sent": _to_int(c.get("bytes_sent"),0),
        "bytes_recv": _to_int(c.get("bytes_recv"),0),
        "bytes_total": _to_int(c.get("bytes_total"),0),
        "duration_sec": _to_int(c.get("duration_sec"),0),

        "dst_port": _to_int(c.get("dst_port"),0),
        "dst_svc_sensitive": 1 if c.get("dst_svc_sensitive") else 0,
        "dst_svc_admin": 1 if c.get("dst_svc_admin") else 0,

        "pf_win": _to_int(c.get("pf_win"),0),
        "pf_lin": _to_int(c.get("pf_lin"),0),
        "pf_nw":  _to_int(c.get("pf_nw"),0),
        "pf_osks":_to_int(c.get("pf_osks"),0),

        # auth signals (common)
        "auth_result_pos": 1 if c.get("auth_result", -1) == 1 else 0,
        "auth_result_neg": 1 if c.get("auth_result", -1) == 0 else 0,

        # service hints
        "service_snmp": 1 if (c.get("service_label") == "SNMP") else 0,
        "service_ssh":  1 if (c.get("service_label") == "SSH") else 0,
        "service_rdp":  1 if (c.get("service_label") == "RDP") else 0,
        "service_winrm":1 if (c.get("service_label") == "WINRM") else 0,

        "hour": _to_int(c.get("hour"),0),
    }
    return feats
