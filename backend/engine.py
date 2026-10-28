"""Firewall rule engine: pure logic, no I/O. First matching rule wins; default is BLOCK."""
import ipaddress

PROTOCOLS = {"TCP", "UDP", "ICMP"}
ACTIONS = {"ALLOW", "BLOCK"}
DEFAULT_ACTION = "BLOCK"


class ValidationError(ValueError):
    pass


def normalize_network(value, field="IP"):
    """Return 'Any' or a normalized CIDR string (single IP -> /32 or /128)."""
    value = (value or "Any").strip()
    if value.lower() == "any":
        return "Any"
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise ValidationError(f"Invalid {field}: '{value}'. Use an IP like 10.0.0.5, a subnet like 10.0.0.0/24, or Any.")


def normalize_port(value):
    """Return 'Any', a single port ('443') or a range ('1000-2000')."""
    text = "Any" if value is None or str(value).strip() == "" else str(value).strip()
    if text.lower() == "any":
        return "Any"
    low, _, high = text.partition("-")
    try:
        lo = int(low)
        hi = int(high) if high else lo
    except ValueError:
        raise ValidationError(f"Invalid port: '{text}'. Use 0-65535, a range like 1000-2000, or Any.")
    if not 0 <= lo <= hi <= 65535:
        raise ValidationError(f"Port out of range: '{text}'. Ports are 0-65535 and ranges must be low-high.")
    return str(lo) if lo == hi else f"{lo}-{hi}"


def normalize_protocol(value):
    text = (value or "Any").strip().upper()
    if text == "ANY":
        return "Any"
    if text not in PROTOCOLS:
        raise ValidationError(f"Invalid protocol: '{value}'. Use TCP, UDP, ICMP, or Any.")
    return text


def validate_rule(data):
    action = str(data.get("action", "")).strip().upper()
    if action not in ACTIONS:
        raise ValidationError("Action must be ALLOW or BLOCK.")
    try:
        priority = int(data.get("priority"))
    except (TypeError, ValueError):
        raise ValidationError("Priority must be a whole number (1 is checked first).")
    if priority < 1:
        raise ValidationError("Priority must be 1 or higher.")
    return {
        "priority": priority,
        "src_ip": normalize_network(data.get("src_ip"), "source IP"),
        "dst_ip": normalize_network(data.get("dst_ip"), "destination IP"),
        "port": normalize_port(data.get("port")),
        "protocol": normalize_protocol(data.get("protocol")),
        "action": action,
        "description": str(data.get("description") or "").strip()[:200],
    }


def validate_packet(data):
    try:
        src = str(ipaddress.ip_address(str(data.get("src_ip", "")).strip()))
        dst = str(ipaddress.ip_address(str(data.get("dst_ip", "")).strip()))
    except ValueError:
        raise ValidationError("Source and destination must be valid IPv4 or IPv6 addresses, e.g. 192.168.1.10.")
    protocol = normalize_protocol(data.get("protocol"))
    if protocol == "Any":
        raise ValidationError("A packet needs a specific protocol: TCP, UDP, or ICMP.")
    port = None
    if protocol != "ICMP":  # ICMP has no ports
        port = normalize_port(data.get("port"))
        if port == "Any" or "-" in port:
            raise ValidationError("A packet needs one destination port between 0 and 65535.")
        port = int(port)
    return {"src_ip": src, "dst_ip": dst, "port": port, "protocol": protocol}


def _ip_matches(rule_value, ip):
    return rule_value == "Any" or ipaddress.ip_address(ip) in ipaddress.ip_network(rule_value)


def _port_matches(rule_value, port):
    if rule_value == "Any":
        return True
    if port is None:  # ICMP never matches a specific port
        return False
    low, _, high = rule_value.partition("-")
    return int(low) <= port <= int(high or low)


def rule_matches(rule, packet):
    return (
        _ip_matches(rule["src_ip"], packet["src_ip"])
        and _ip_matches(rule["dst_ip"], packet["dst_ip"])
        and _port_matches(rule["port"], packet["port"])
        and (rule["protocol"] == "Any" or rule["protocol"] == packet["protocol"])
    )


def evaluate(packet, rules):
    """Return {'action', 'rule_id', 'reason'} using first match in priority order."""
    for rule in sorted(rules, key=lambda r: (r["priority"], r["id"])):
        if rule_matches(rule, packet):
            return {"action": rule["action"], "rule_id": rule["id"],
                    "reason": f"Matched rule priority {rule['priority']} ({rule['action']})"}
    return {"action": DEFAULT_ACTION, "rule_id": None,
            "reason": "No rule matched: default policy is BLOCK"}
