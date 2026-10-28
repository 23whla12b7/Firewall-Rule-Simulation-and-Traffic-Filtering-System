import { useEffect, useState, useCallback } from "react";

const api = async (path, opts = {}) => {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || "Request failed");
  return data;
};

const EMPTY_RULE = { priority: 5, src_ip: "Any", dst_ip: "Any", port: "Any", protocol: "Any", action: "BLOCK", description: "" };
const EMPTY_PACKET = { src_ip: "203.0.113.7", dst_ip: "10.0.0.5", port: "443", protocol: "TCP" };
const PROTOCOLS = ["TCP", "UDP", "ICMP"];

function Field({ label, children }) {
  return <label className="field"><span>{label}</span>{children}</label>;
}

function Verdict({ action }) {
  return <span className={`verdict ${action.toLowerCase()}`}>{action}</span>;
}

export default function App() {
  const [rules, setRules] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ allowed: 0, blocked: 0, total: 0 });
  const [packet, setPacket] = useState(EMPTY_PACKET);
  const [result, setResult] = useState(null);
  const [rule, setRule] = useState(EMPTY_RULE);
  const [editing, setEditing] = useState(null);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    const [r, l, s] = await Promise.all([api("/rules"), api("/logs"), api("/stats")]);
    setRules(r); setLogs(l); setStats(s);
  }, []);

  useEffect(() => { refresh().catch((e) => setError(e.message)); }, [refresh]);

  const run = async (fn) => {
    setError("");
    try { await fn(); await refresh(); } catch (e) { setError(e.message); }
  };

  const simulate = (e) => { e.preventDefault(); run(async () => setResult(await api("/simulate", { method: "POST", body: packet }))); };
  const saveRule = (e) => {
    e.preventDefault();
    run(async () => {
      await api(editing ? `/rules/${editing}` : "/rules", { method: editing ? "PUT" : "POST", body: rule });
      setRule(EMPTY_RULE); setEditing(null);
    });
  };
  const edit = (r) => { setEditing(r.id); setRule({ ...r }); };
  const ruleLabel = (id) => (id ? `Rule #${rules.find((r) => r.id === id)?.priority ?? id}` : "Default policy");

  return (
    <main>
      <header>
        <h1>Firewall rule simulator</h1>
        <p>Packets are checked against your rules from priority 1 upward. The first match decides; anything unmatched is blocked.</p>
      </header>

      {error && <div className="error" role="alert">{error}</div>}

      <section className="stats" aria-label="Traffic totals">
        <div><b>{stats.total}</b> packets tested</div>
        <div className="allow"><b>{stats.allowed}</b> allowed</div>
        <div className="block"><b>{stats.blocked}</b> blocked</div>
      </section>

      <div className="grid">
        <section>
          <h2>Test a packet</h2>
          <form onSubmit={simulate}>
            <Field label="Source IP"><input value={packet.src_ip} onChange={(e) => setPacket({ ...packet, src_ip: e.target.value })} /></Field>
            <Field label="Destination IP"><input value={packet.dst_ip} onChange={(e) => setPacket({ ...packet, dst_ip: e.target.value })} /></Field>
            <Field label="Protocol">
              <select value={packet.protocol} onChange={(e) => setPacket({ ...packet, protocol: e.target.value })}>
                {PROTOCOLS.map((p) => <option key={p}>{p}</option>)}
              </select>
            </Field>
            <Field label="Destination port">
              <input value={packet.protocol === "ICMP" ? "" : packet.port} disabled={packet.protocol === "ICMP"}
                placeholder={packet.protocol === "ICMP" ? "Not used by ICMP" : ""}
                onChange={(e) => setPacket({ ...packet, port: e.target.value })} />
            </Field>
            <button className="primary">Test packet</button>
          </form>
          {result && (
            <div className={`result ${result.action.toLowerCase()}`} aria-live="polite">
              <Verdict action={result.action} />
              <p>{result.reason}</p>
            </div>
          )}
        </section>

        <section>
          <h2>{editing ? "Edit rule" : "Add rule"}</h2>
          <form onSubmit={saveRule}>
            <Field label="Priority"><input type="number" min="1" value={rule.priority} onChange={(e) => setRule({ ...rule, priority: e.target.value })} /></Field>
            <Field label="Action">
              <select value={rule.action} onChange={(e) => setRule({ ...rule, action: e.target.value })}><option>ALLOW</option><option>BLOCK</option></select>
            </Field>
            <Field label="Source IP or subnet"><input value={rule.src_ip} onChange={(e) => setRule({ ...rule, src_ip: e.target.value })} /></Field>
            <Field label="Destination IP or subnet"><input value={rule.dst_ip} onChange={(e) => setRule({ ...rule, dst_ip: e.target.value })} /></Field>
            <Field label="Port or range"><input value={rule.port} onChange={(e) => setRule({ ...rule, port: e.target.value })} /></Field>
            <Field label="Protocol">
              <select value={rule.protocol} onChange={(e) => setRule({ ...rule, protocol: e.target.value })}>
                {["Any", ...PROTOCOLS].map((p) => <option key={p}>{p}</option>)}
              </select>
            </Field>
            <Field label="Note"><input value={rule.description} onChange={(e) => setRule({ ...rule, description: e.target.value })} /></Field>
            <div className="row">
              <button className="primary">{editing ? "Save changes" : "Add rule"}</button>
              {editing && <button type="button" onClick={() => { setEditing(null); setRule(EMPTY_RULE); }}>Cancel</button>}
            </div>
          </form>
        </section>
      </div>

      <section>
        <h2>Rules</h2>
        <div className="scroll">
          <table>
            <thead><tr><th>Priority</th><th>Source</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Action</th><th>Note</th><th /></tr></thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td>{r.priority}</td><td>{r.src_ip}</td><td>{r.dst_ip}</td><td>{r.port}</td><td>{r.protocol}</td>
                  <td><Verdict action={r.action} /></td><td>{r.description}</td>
                  <td className="actions">
                    <button onClick={() => edit(r)}>Edit</button>
                    <button onClick={() => run(() => api(`/rules/${r.id}`, { method: "DELETE" }))}>Delete</button>
                  </td>
                </tr>
              ))}
              <tr className="default"><td>Default</td><td>Any</td><td>Any</td><td>Any</td><td>Any</td><td><Verdict action="BLOCK" /></td><td>Unmatched traffic</td><td /></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <div className="row spread">
          <h2>Traffic log</h2>
          <button onClick={() => run(() => api("/logs", { method: "DELETE" }))}>Clear log</button>
        </div>
        {logs.length === 0 ? <p className="muted">No packets tested yet. Send one from the form above.</p> : (
          <div className="scroll">
            <table>
              <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Decision</th><th>Decided by</th></tr></thead>
              <tbody>
                {logs.map((l) => (
                  <tr key={l.id}>
                    <td>{l.ts}</td><td>{l.src_ip}</td><td>{l.dst_ip}</td><td>{l.port ?? "n/a"}</td><td>{l.protocol}</td>
                    <td><Verdict action={l.action} /></td><td>{ruleLabel(l.rule_id)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
