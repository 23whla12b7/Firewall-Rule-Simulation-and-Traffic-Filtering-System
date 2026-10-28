import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent / "firewall.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, priority INTEGER NOT NULL,
  src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, port TEXT NOT NULL,
  protocol TEXT NOT NULL, action TEXT NOT NULL, description TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT DEFAULT CURRENT_TIMESTAMP,
  src_ip TEXT, dst_ip TEXT, port INTEGER, protocol TEXT,
  action TEXT, rule_id INTEGER, reason TEXT);
"""

DEFAULT_RULES = [
    (1, "192.168.1.10", "Any", "Any", "Any", "BLOCK", "Block a specific host"),
    (2, "Any", "Any", "443", "TCP", "ALLOW", "Allow HTTPS"),
    (3, "Any", "Any", "80", "TCP", "ALLOW", "Allow HTTP"),
    (4, "Any", "Any", "22", "TCP", "BLOCK", "Block SSH"),
]


@contextmanager
def connect(path=None):
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(path=None):
    with connect(path) as c:
        c.executescript(SCHEMA)
        if c.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0:
            c.executemany(
                "INSERT INTO rules (priority,src_ip,dst_ip,port,protocol,action,description) VALUES (?,?,?,?,?,?,?)",
                DEFAULT_RULES)
