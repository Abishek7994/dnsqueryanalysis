import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, AlertOctagon, AlertTriangle, ArrowDown, Check, CircleHelp, Database,
  Globe2, Pause, Play, Radio, RefreshCw, Shield, ShieldAlert, Siren, Wifi, WifiOff,
} from "lucide-react";
import {
  Area, AreaChart, Bar, CartesianGrid, ComposedChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";

const API = "http://localhost:8000";
const WS = "ws://localhost:8000/ws/dns";
type Status = "NORMAL" | "SUSPICIOUS" | "MALFORMED" | "CRITICAL";
type Event = {
  timestamp: string; client_ip: string; domain: string; record_type: string;
  entropy: number; status: Status; anomaly_reason: string; is_valid: boolean;
};
type Transition = { char: string; from_state: string; to_state: string };
type Validation = {
  regex: { is_valid: boolean; error_reason: string | null };
  dfa: { is_valid: boolean; transitions: Transition[]; error_index: number | null; error_reason: string | null };
  engines_agree: boolean;
};
type Stats = {
  total_queries: number; valid_percent: number; blocked_malformed: number;
  active_threat_alerts: number; threat_counts: Record<Status, number>;
  record_counts: Record<string, number>;
};

const initialStats: Stats = {
  total_queries: 0, valid_percent: 0, blocked_malformed: 0, active_threat_alerts: 0,
  threat_counts: { NORMAL: 0, SUSPICIOUS: 0, MALFORMED: 0, CRITICAL: 0 }, record_counts: {},
};

function App() {
  const [connected, setConnected] = useState(false);
  const [running, setRunning] = useState(true);
  const [events, setEvents] = useState<Event[]>([]);
  const [stats, setStats] = useState<Stats>(initialStats);
  const [domain, setDomain] = useState("api.example.com");
  const [validation, setValidation] = useState<Validation | null>(null);
  const [validationError, setValidationError] = useState("");
  const [controlBusy, setControlBusy] = useState(false);
  const [notice, setNotice] = useState("");

  const loadStats = useCallback(async () => {
    try {
      const response = await fetch(`${API}/api/stats`);
      if (!response.ok) throw new Error(`Stats request failed (${response.status})`);
      const data = await response.json();
      setStats(data);
      setEvents((current) => current.length ? current : (data.recent_events ?? []).slice().reverse());
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to load API data.");
    }
  }, []);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retryTimer: number;
    let stopped = false;
    const connect = () => {
      socket = new WebSocket(WS);
      socket.onopen = () => { setConnected(true); setNotice(""); };
      socket.onclose = () => {
        setConnected(false);
        if (!stopped) retryTimer = window.setTimeout(connect, 1600);
      };
      socket.onerror = () => setConnected(false);
      socket.onmessage = (message) => {
        const packet = JSON.parse(message.data);
        if (packet.type === "dns_event") setEvents((current) => [packet.data, ...current].slice(0, 200));
      };
    };
    connect();
    void loadStats();
    const poll = window.setInterval(() => { void loadStats(); }, 5000);
    return () => { stopped = true; window.clearInterval(poll); window.clearTimeout(retryTimer); socket?.close(); };
  }, [loadStats]);

  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(async () => {
      try {
        const response = await fetch(`${API}/api/validate`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain }),
        });
        if (!response.ok) throw new Error(`Validation failed (${response.status})`);
        const result: Validation = await response.json();
        if (active) {
          setValidation(result);
          setValidationError("");
        }
      } catch (error) {
        if (active) {
          setValidation(null);
          setValidationError(error instanceof Error ? error.message : "Unable to validate domain.");
        }
      }
    }, 220);
    return () => { active = false; window.clearTimeout(timer); };
  }, [domain]);

  const sendControl = async (action: "start" | "pause" | "burst") => {
    setControlBusy(true);
    try {
      const response = await fetch(`${API}/api/stream/control`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action }),
      });
      if (!response.ok) throw new Error(`Control request failed (${response.status})`);
      const result = await response.json();
      if (action !== "burst") setRunning(action === "start");
      setNotice(result.message);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Stream control failed.");
    } finally { setControlBusy(false); }
  };

  const qpsData = useMemo(() => {
    const now = Date.now();
    return Array.from({ length: 20 }, (_, i) => {
      const start = now - (19 - i) * 3000;
      const count = events.filter((event) => {
        const stamp = new Date(event.timestamp).getTime();
        return stamp >= start && stamp < start + 3000;
      }).length;
      return { time: new Date(start).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" }), qps: +(count / 3).toFixed(2) };
    });
  }, [events]);
  const recordData = useMemo(() => {
    const types = ["A", "AAAA", "MX", "TXT", "CNAME", "PTR"];
    return types.map((type) => {
      const typedEvents = events.filter((event) => event.record_type === type);
      return {
        type,
        queries: stats.record_counts[type] ?? 0,
        normal: typedEvents.filter((event) => event.status === "NORMAL").length,
        suspicious: typedEvents.filter((event) => event.status === "SUSPICIOUS").length,
        malformed: typedEvents.filter((event) => event.status === "MALFORMED").length,
        critical: typedEvents.filter((event) => event.status === "CRITICAL").length,
      };
    });
  }, [events, stats.record_counts]);

  const kpis = [
    { label: "Total Queries", value: stats.total_queries.toLocaleString(), detail: "All observed DNS requests", icon: Activity, color: "text-cyan-400", accent: "bg-cyan-400/10" },
    { label: "Valid Domains", value: `${stats.valid_percent}%`, detail: "Passing syntax validation", icon: Shield, color: "text-emerald-400", accent: "bg-emerald-400/10" },
    { label: "Malformed Blocked", value: stats.blocked_malformed.toLocaleString(), detail: "Rejected by validator", icon: AlertOctagon, color: "text-amber-400", accent: "bg-amber-400/10" },
    { label: "Active Threat Alerts", value: stats.active_threat_alerts.toLocaleString(), detail: "Suspicious + critical", icon: Siren, color: "text-rose-400", accent: "bg-rose-400/10" },
  ];

  return (
    <main className="min-h-screen bg-[#090d14] text-slate-100">
      <header className="sticky top-0 z-10 border-b border-[#202938] bg-[#090d14]/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-4 px-5 py-4 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-400/10 text-cyan-300"><ShieldAlert size={22} /></div>
            <div><h1 className="text-lg font-semibold tracking-tight">DNS Sentinel</h1><p className="text-xs text-slate-500">REAL-TIME THREAT ANALYSIS</p></div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs ${connected ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-rose-500/30 bg-rose-500/10 text-rose-300"}`}>
              {connected ? <Wifi size={14} /> : <WifiOff size={14} />} {connected ? "WebSocket live" : "Reconnecting"}
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? "animate-pulse bg-emerald-400" : "bg-rose-400"}`} />
            </div>
            <button disabled={controlBusy} onClick={() => void sendControl(running ? "pause" : "start")} className="inline-flex items-center gap-2 rounded-lg border border-[#2b3747] bg-[#151e2b] px-3 py-2 text-sm hover:border-cyan-500/50 disabled:opacity-50">
              {running ? <Pause size={15} /> : <Play size={15} />}{running ? "Pause Stream" : "Start Stream"}
            </button>
            <button disabled={controlBusy} onClick={() => void sendControl("burst")} className="inline-flex items-center gap-2 rounded-lg bg-rose-500 px-3 py-2 text-sm font-medium text-white hover:bg-rose-400 disabled:opacity-50">
              <Siren size={15} /> Inject Attack Burst
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-[1600px] space-y-5 px-5 py-6 lg:px-8">
        {notice && <div className="flex items-center justify-between rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-4 py-2 text-sm text-cyan-100"><span>{notice}</span><button aria-label="Dismiss message" onClick={() => setNotice("")}>×</button></div>}
        <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {kpis.map(({ label, value, detail, icon: Icon, color, accent }) => (
            <article key={label} className="panel flex items-start justify-between p-5">
              <div><p className="text-sm text-slate-400">{label}</p><p className="mt-2 text-3xl font-semibold tracking-tight">{value}</p><p className="mt-2 text-xs text-slate-500">{detail}</p></div>
              <div className={`rounded-lg p-2.5 ${accent} ${color}`}><Icon size={20} /></div>
            </article>
          ))}
        </section>

        <section className="grid gap-5 xl:grid-cols-[1.05fr_0.95fr]">
          <article className="panel min-w-0 p-5">
            <div className="mb-4 flex items-start justify-between"><div><h2 className="font-semibold">Automata & Regex Playground</h2><p className="mt-1 text-xs text-slate-500">Validate a hostname with independent engines</p></div><CircleHelp size={17} className="text-slate-500" /></div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wide text-slate-500" htmlFor="domain-input">Domain name</label>
            <div className="flex gap-2">
              <input id="domain-input" value={domain} onChange={(event) => setDomain(event.target.value)} className="min-w-0 flex-1 rounded-lg border border-[#2b3747] bg-[#090d14] px-3 py-2.5 text-sm outline-none transition focus:border-cyan-500/70 mono" placeholder="subdomain.example.com" />
              <div className={`flex items-center gap-1.5 rounded-lg border px-3 text-xs ${validation?.regex.is_valid ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-300" : "border-rose-500/20 bg-rose-500/10 text-rose-300"}`}>
                {validation?.regex.is_valid ? <Check size={14} /> : <AlertTriangle size={14} />} Regex {validation?.regex.is_valid ? "PASS" : "FAIL"}
              </div>
            </div>
            {validation && <p className={`mt-2 text-xs ${validation.regex.is_valid ? "text-slate-500" : "text-rose-300"}`}>{validation.regex.error_reason ?? "Hostname syntax is valid."}</p>}
            {validationError && <p className="mt-2 text-xs text-rose-300">{validationError}</p>}
            <div className="mt-5">
              <div className="mb-3 flex items-center justify-between"><h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">DFA transition trace</h3><span className={`text-xs font-semibold ${validation?.dfa.is_valid ? "text-emerald-400" : "text-rose-400"}`}>DFA {validation?.dfa.is_valid ? "ACCEPT" : "REJECT"}</span></div>
              <div className="scrollbar flex items-center gap-2 overflow-x-auto pb-2">
                {(validation?.dfa.transitions ?? []).map((step, index) => (
                  <div key={`${index}-${step.char}`} className="flex shrink-0 items-center gap-2">
                    <div title={`Character: ${step.char || "end"}`} className={`rounded-md border px-2.5 py-2 text-center ${step.to_state === "REJECT" ? "border-rose-500/40 bg-rose-500/10" : step.to_state === "ACCEPT" ? "border-emerald-500/40 bg-emerald-500/10" : "border-[#2b3747] bg-[#0b1119]"}`}>
                      <span className="block text-[10px] text-slate-500">{step.char ? JSON.stringify(step.char) : "END"}</span>
                      <span className="mono mt-1 block text-[11px] text-slate-200">{step.from_state}</span>
                      <ArrowDown className="mx-auto my-0.5 text-slate-600" size={12} />
                      <span className={`mono block text-[11px] ${step.to_state === "REJECT" ? "text-rose-300" : step.to_state === "ACCEPT" ? "text-emerald-300" : "text-cyan-300"}`}>{step.to_state}</span>
                    </div>
                    {index < (validation?.dfa.transitions.length ?? 0) - 1 && <span className="text-slate-700">→</span>}
                  </div>
                ))}
                {!validation?.dfa.transitions.length && <span className="text-xs text-slate-500">Enter a domain to view its character-by-character state transitions.</span>}
              </div>
            </div>
            {validation?.dfa.error_reason && <p className="mt-2 text-xs text-rose-300">DFA: {validation.dfa.error_reason}</p>}
          </article>

          <article className="panel min-w-0 p-5">
            <div className="mb-3 flex items-center justify-between"><div><h2 className="font-semibold">Queries Per Second</h2><p className="mt-1 text-xs text-slate-500">Rolling view · derived from live event feed</p></div><div className="flex items-center gap-1.5 text-xs text-cyan-300"><Activity size={14} /> LIVE</div></div>
            <div className="h-[210px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={qpsData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                  <defs><linearGradient id="qpsFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.28} /><stop offset="100%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient></defs>
                  <CartesianGrid stroke="#202938" strokeDasharray="3 4" vertical={false} />
                  <XAxis dataKey="time" tick={{ fill: "#718096", fontSize: 10 }} axisLine={false} tickLine={false} minTickGap={30} />
                  <YAxis tick={{ fill: "#718096", fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: "#111824", border: "1px solid #2b3747", borderRadius: 8, fontSize: 12 }} />
                  <Area type="monotone" dataKey="qps" name="Queries/sec" stroke="#22d3ee" strokeWidth={2} fill="url(#qpsFill)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </article>
        </section>

        <section className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
          <article className="panel min-w-0 p-5">
            <div className="mb-3"><h2 className="font-semibold">Query Status Distribution</h2><p className="mt-1 text-xs text-slate-500">Observed record types and flagged events</p></div>
            <div className="h-[220px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={recordData} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
                  <CartesianGrid stroke="#202938" strokeDasharray="3 4" vertical={false} />
                  <XAxis dataKey="type" tick={{ fill: "#9aa7b8", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "#718096", fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: "#111824", border: "1px solid #2b3747", borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="normal" name="Normal" stackId="status" fill="#22c55e" />
                  <Bar dataKey="suspicious" name="Suspicious" stackId="status" fill="#f59e0b" />
                  <Bar dataKey="malformed" name="Malformed" stackId="status" fill="#f97316" />
                  <Bar dataKey="critical" name="Critical" stackId="status" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                </ComposedChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-1 flex flex-wrap gap-3 text-[11px] text-slate-500">{["NORMAL", "SUSPICIOUS", "MALFORMED", "CRITICAL"].map((item, index) => <span key={item} className="inline-flex items-center gap-1.5"><i className={`h-2 w-2 rounded-full ${["bg-emerald-400", "bg-amber-400", "bg-orange-400", "bg-rose-400"][index]}`} />{item} {stats.threat_counts[item as Status]}</span>)}</div>
          </article>

          <article className="panel min-w-0 overflow-hidden">
            <div className="flex items-center justify-between border-b border-[#202938] px-5 py-4"><div><h2 className="font-semibold">Live DNS Traffic</h2><p className="mt-1 text-xs text-slate-500">Most recent events first · {events.length} displayed</p></div><div className="flex items-center gap-2 text-xs text-slate-500"><Radio size={14} className={connected ? "text-emerald-400" : ""} /> {connected ? "Streaming" : "Offline"}</div></div>
            <div className="scrollbar max-h-[260px] overflow-auto">
              <table className="w-full min-w-[790px] border-collapse text-left text-xs">
                <thead className="sticky top-0 bg-[#111824] text-[10px] uppercase tracking-wider text-slate-500"><tr>{["Timestamp", "Client IP", "Domain", "Type", "Entropy", "Status", "Anomaly"].map((header) => <th key={header} className="px-3 py-3 font-medium first:pl-5">{header}</th>)}</tr></thead>
                <tbody>
                  {events.length === 0 && <tr><td colSpan={7} className="px-5 py-10 text-center text-slate-500"><Database size={18} className="mx-auto mb-2 opacity-50" />Waiting for DNS events…</td></tr>}
                  {events.map((event, index) => <tr key={`${event.timestamp}-${event.domain}-${index}`} className="border-t border-[#1b2431] hover:bg-white/[0.02]">
                    <td className="whitespace-nowrap px-3 py-3 pl-5 text-slate-500">{new Date(event.timestamp).toLocaleTimeString()}</td>
                    <td className="mono whitespace-nowrap px-3 py-3 text-slate-400">{event.client_ip}</td>
                    <td title={event.domain} className={`max-w-[200px] truncate px-3 py-3 mono ${event.status === "CRITICAL" || event.status === "MALFORMED" ? "text-rose-300" : "text-slate-200"}`}>{event.domain}</td>
                    <td className="px-3 py-3"><span className="rounded bg-[#1a2533] px-1.5 py-1 text-slate-400">{event.record_type}</span></td>
                    <td className={`px-3 py-3 mono ${event.entropy > 3.8 ? "text-amber-300" : "text-slate-400"}`}>{event.entropy.toFixed(2)}</td>
                    <td className="px-3 py-3"><StatusBadge status={event.status} /></td>
                    <td title={event.anomaly_reason} className="max-w-[220px] truncate px-3 py-3 text-slate-500">{event.anomaly_reason}</td>
                  </tr>)}
                </tbody>
              </table>
            </div>
          </article>
        </section>
        <footer className="flex flex-wrap items-center justify-between gap-2 pb-3 text-[11px] text-slate-600"><span className="flex items-center gap-1.5"><Globe2 size={12} /> DNS Sentinel · simulated traffic analysis</span><span className="flex items-center gap-1.5"><RefreshCw size={11} /> Stats refresh every 5 seconds</span></footer>
      </div>
    </main>
  );
}

function StatusBadge({ status }: { status: Status }) {
  const style: Record<Status, string> = {
    NORMAL: "bg-emerald-500/10 text-emerald-300 border-emerald-500/20",
    SUSPICIOUS: "bg-amber-500/10 text-amber-300 border-amber-500/20",
    MALFORMED: "bg-orange-500/10 text-orange-300 border-orange-500/20",
    CRITICAL: "bg-rose-500/10 text-rose-300 border-rose-500/20",
  };
  return <span className={`rounded border px-1.5 py-1 text-[10px] font-semibold ${style[status]}`}>{status}</span>;
}

export default App;
