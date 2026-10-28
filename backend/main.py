from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import engine
from database import connect, init_db

app = FastAPI(title="Firewall Rule Simulator")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"])
init_db()

RULE_COLS = "priority,src_ip,dst_ip,port,protocol,action,description"


def clean(data):
    try:
        return engine.validate_rule(data)
    except engine.ValidationError as e:
        raise HTTPException(422, str(e))


@app.get("/api/rules")
def list_rules():
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM rules ORDER BY priority, id")]


@app.post("/api/rules", status_code=201)
def add_rule(data: dict):
    r = clean(data)
    with connect() as c:
        cur = c.execute(f"INSERT INTO rules ({RULE_COLS}) VALUES (?,?,?,?,?,?,?)", tuple(r.values()))
        return {"id": cur.lastrowid, **r}


@app.put("/api/rules/{rule_id}")
def update_rule(rule_id: int, data: dict):
    r = clean(data)
    with connect() as c:
        cur = c.execute("UPDATE rules SET priority=?,src_ip=?,dst_ip=?,port=?,protocol=?,action=?,description=? WHERE id=?",
                        (*r.values(), rule_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Rule not found.")
    return {"id": rule_id, **r}


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: int):
    with connect() as c:
        if c.execute("DELETE FROM rules WHERE id=?", (rule_id,)).rowcount == 0:
            raise HTTPException(404, "Rule not found.")
    return {"deleted": rule_id}


@app.post("/api/simulate")
def simulate(data: dict):
    try:
        packet = engine.validate_packet(data)
    except engine.ValidationError as e:
        raise HTTPException(422, str(e))
    with connect() as c:
        rules = [dict(r) for r in c.execute("SELECT * FROM rules")]
        result = engine.evaluate(packet, rules)
        c.execute("INSERT INTO logs (src_ip,dst_ip,port,protocol,action,rule_id,reason) VALUES (?,?,?,?,?,?,?)",
                  (packet["src_ip"], packet["dst_ip"], packet["port"], packet["protocol"],
                   result["action"], result["rule_id"], result["reason"]))
    return {"packet": packet, **result}


@app.get("/api/logs")
def logs(limit: int = 100):
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))]


@app.delete("/api/logs")
def clear_logs():
    with connect() as c:
        c.execute("DELETE FROM logs")
    return {"cleared": True}


@app.get("/api/stats")
def stats():
    with connect() as c:
        rows = dict(c.execute("SELECT action, COUNT(*) FROM logs GROUP BY action").fetchall())
    allowed, blocked = rows.get("ALLOW", 0), rows.get("BLOCK", 0)
    return {"allowed": allowed, "blocked": blocked, "total": allowed + blocked}
