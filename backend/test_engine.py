import pytest
from engine import evaluate, validate_packet, validate_rule, ValidationError
from database import DEFAULT_RULES

RULES = [dict(id=i + 1, priority=p, src_ip=s, dst_ip=d, port=po, protocol=pr, action=a)
         for i, (p, s, d, po, pr, a, _) in enumerate(DEFAULT_RULES)]


def pkt(src="8.8.8.8", port=443, proto="TCP", dst="10.0.0.5"):
    return validate_packet({"src_ip": src, "dst_ip": dst, "port": port, "protocol": proto})


def test_https_allowed():
    assert evaluate(pkt(), RULES)["action"] == "ALLOW"

def test_http_allowed():
    assert evaluate(pkt(port=80), RULES)["action"] == "ALLOW"

def test_ssh_blocked():
    assert evaluate(pkt(port=22), RULES)["action"] == "BLOCK"

def test_blocked_ip_beats_allowed_port():
    r = evaluate(pkt(src="192.168.1.10", port=443), RULES)
    assert r["action"] == "BLOCK" and r["rule_id"] == 1

def test_default_deny():
    r = evaluate(pkt(port=3306), RULES)
    assert r["action"] == "BLOCK" and r["rule_id"] is None

def test_udp_not_matched_by_tcp_rule():
    assert evaluate(pkt(port=443, proto="UDP"), RULES)["rule_id"] is None

def test_icmp_default_deny():
    assert evaluate(pkt(proto="ICMP", port=None), RULES)["action"] == "BLOCK"

def test_subnet_and_range():
    rule = validate_rule({"priority": 1, "src_ip": "10.1.0.0/16", "port": "8000-8100", "protocol": "TCP", "action": "allow"})
    rules = [{"id": 1, **rule}]
    assert evaluate(pkt(src="10.1.4.4", port=8080), rules)["action"] == "ALLOW"
    assert evaluate(pkt(src="10.2.4.4", port=8080), rules)["rule_id"] is None

def test_priority_order_conflict():
    rules = [dict(id=1, priority=2, src_ip="Any", dst_ip="Any", port="80", protocol="TCP", action="ALLOW"),
             dict(id=2, priority=1, src_ip="Any", dst_ip="Any", port="80", protocol="TCP", action="BLOCK")]
    assert evaluate(pkt(port=80), rules)["rule_id"] == 2

@pytest.mark.parametrize("bad", [{"src_ip": "999.1.1.1"}, {"src_ip": "abc"}, {"port": 70000}, {"protocol": "FTP"}])
def test_invalid_packet(bad):
    data = {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "port": 80, "protocol": "TCP", **bad}
    with pytest.raises(ValidationError):
        validate_packet(data)

def test_invalid_rule():
    with pytest.raises(ValidationError):
        validate_rule({"priority": 1, "src_ip": "1.2.3", "action": "ALLOW"})
