import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, Globe, Loader2, Play, Server, Settings, Shield,
  StopCircle, Trash2, Download, RefreshCw, Terminal, Wifi,
  AlertTriangle, CheckCircle, Clock, XCircle, ChevronRight,
  Lock, Eye, Filter, Search
} from "lucide-react";

// ─── Constants ────────────────────────────────────────────────────────────────

const SCAN_PROFILES = {
  quick:       { label: "Quick Scan",            args: "-T4 -F",                          desc: "Fast scan of top 100 ports", rootRequired: false },
  intense:     { label: "Intense Scan",          args: "-T4 -A -v",                       desc: "OS, version, scripts, traceroute", rootRequired: false },
  full_tcp:    { label: "Full TCP Port Scan",    args: "-p- -T4 -sV",                     desc: "All 65,535 TCP ports + service detection", rootRequired: false },
  service:     { label: "Service Version Scan",  args: "-sV -T4",                         desc: "Detect service versions on top ports", rootRequired: false },
  udp:         { label: "UDP Scan",              args: "-sU --top-ports 200 -T4",         desc: "Top 200 UDP ports (root required)", rootRequired: true },
  syn_stealth: { label: "SYN Stealth Scan",      args: "-sS -T4",                         desc: "Half-open SYN scan (root required)", rootRequired: true },
  os_detect:   { label: "OS Detection",          args: "-O -T4",                          desc: "Fingerprint operating system (root required)", rootRequired: true },
  vuln:        { label: "Vulnerability Scripts", args: "-sV --script vuln -T4",           desc: "Run NSE vulnerability category scripts", rootRequired: false },
  ping:        { label: "Ping Sweep",            args: "-sn",                             desc: "Host discovery only", rootRequired: false },
  aggressive:  { label: "Aggressive Full",       args: "-A -T4 -p- -sV --script default", desc: "Everything — slow but thorough", rootRequired: false },
  custom:      { label: "Custom Arguments",      args: "",                                 desc: "Provide your own nmap flags", rootRequired: false },
};

const LS_BACKEND = "nmap_backend_url";
const LS_TOKEN   = "nmap_backend_token";

// ─── Utilities ────────────────────────────────────────────────────────────────

function useBackend() {
  const [url, setUrl] = useState(() =>
    typeof window !== "undefined" ? localStorage.getItem(LS_BACKEND) || "http://localhost:8765" : ""
  );
  const [token, setToken] = useState(() =>
    typeof window !== "undefined" ? localStorage.getItem(LS_TOKEN) || "" : ""
  );
  const save = (u, t) => {
    setUrl(u); setToken(t);
    localStorage.setItem(LS_BACKEND, u);
    localStorage.setItem(LS_TOKEN, t);
  };
  return { url, token, save };
}

async function apiFetch(base, token, path, init = {}) {
  const res = await fetch(base.replace(/\/$/, "") + path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "X-Auth-Token": token } : {}),
      ...(init.headers || {}),
    },
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${txt ? " — " + txt : ""}`);
  }
  return res.json();
}

function stateColors(state) {
  if (state === "open")            return { bg: "#0d2b4e", text: "#4ade80", border: "#166534" };
  if (state === "closed")          return { bg: "#2d1a1a", text: "#f87171", border: "#7f1d1d" };
  if (state.includes("filtered"))  return { bg: "#2d2212", text: "#fb923c", border: "#92400e" };
  return { bg: "#1a1f2e", text: "#94a3b8", border: "#334155" };
}

function fmtTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function fmtDuration(start, end) {
  if (!start || !end) return null;
  const ms = new Date(end) - new Date(start);
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

// ─── Toast ────────────────────────────────────────────────────────────────────

let toastId = 0;
function useToasts() {
  const [toasts, setToasts] = useState([]);
  const add = (msg, type = "info") => {
    const id = ++toastId;
    setToasts(p => [...p, { id, msg, type }]);
    setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), 3500);
  };
  return { toasts, toast: { success: m => add(m, "success"), error: m => add(m, "error"), info: m => add(m, "info") } };
}

function ToastContainer({ toasts }) {
  return (
    <div style={{ position: "fixed", top: 20, right: 20, zIndex: 9999, display: "flex", flexDirection: "column", gap: 8 }}>
      {toasts.map(t => (
        <div key={t.id} style={{
          padding: "10px 16px", borderRadius: 8, fontSize: 13, fontWeight: 500,
          background: t.type === "success" ? "#052e16" : t.type === "error" ? "#2d1a1a" : "#0f172a",
          color:      t.type === "success" ? "#4ade80" : t.type === "error" ? "#f87171" : "#94a3b8",
          border:     `1px solid ${t.type === "success" ? "#166534" : t.type === "error" ? "#7f1d1d" : "#334155"}`,
          boxShadow: "0 4px 12px rgba(0,0,0,0.5)",
          display: "flex", alignItems: "center", gap: 8, minWidth: 260,
          animation: "slideIn 0.2s ease",
        }}>
          {t.type === "success" && <CheckCircle size={14} />}
          {t.type === "error" && <XCircle size={14} />}
          {t.type === "info" && <Activity size={14} />}
          {t.msg}
        </div>
      ))}
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export default function Dashboard() {
  const { url, token, save } = useBackend();
  const { toasts, toast } = useToasts();

  const [target, setTarget]       = useState("scanme.nmap.org");
  const [profile, setProfile]     = useState("quick");
  const [ports, setPorts]         = useState("");
  const [customArgs, setCustomArgs] = useState("");
  const [scans, setScans]         = useState([]);
  const [activeScanId, setActiveScanId] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [tmpUrl, setTmpUrl]       = useState(url);
  const [tmpToken, setTmpToken]   = useState(token);
  const [activeTab, setActiveTab] = useState("ports");
  const [portFilter, setPortFilter] = useState("");
  const pollRef = useRef(null);

  const activeScan = useMemo(() => scans.find(s => s.id === activeScanId) || null, [scans, activeScanId]);

  const allPorts = useMemo(() => {
    const rows = [];
    activeScan?.hosts?.forEach(h => h.ports?.forEach(p => rows.push({ ...p, host: h.address })));
    return rows;
  }, [activeScan]);

  const filteredPorts = useMemo(() => {
    if (!portFilter.trim()) return allPorts;
    const q = portFilter.toLowerCase();
    return allPorts.filter(p =>
      String(p.port).includes(q) ||
      p.host.toLowerCase().includes(q) ||
      p.service?.toLowerCase().includes(q) ||
      p.state?.toLowerCase().includes(q) ||
      p.product?.toLowerCase().includes(q)
    );
  }, [allPorts, portFilter]);

  const stats = useMemo(() => {
    const hosts = activeScan?.hosts ?? [];
    const up       = hosts.filter(h => h.status === "up").length;
    const open     = allPorts.filter(p => p.state === "open").length;
    const filtered = allPorts.filter(p => p.state?.includes("filtered")).length;
    const closed   = allPorts.filter(p => p.state === "closed").length;
    return { hostsUp: up, hostsTotal: hosts.length, open, filtered, closed, total: allPorts.length };
  }, [activeScan, allPorts]);

  const loadScans = async () => {
    if (!url) return;
    try {
      const data = await apiFetch(url, token, "/scans");
      setScans(data);
      if (!activeScanId && data[0]) setActiveScanId(data[0].id);
    } catch (e) {
      console.error("Failed to load scans:", e.message);
    }
  };

  useEffect(() => { loadScans(); }, [url, token]);

  useEffect(() => {
    if (pollRef.current) clearInterval(pollRef.current);
    if (!activeScan || activeScan.status === "completed" || activeScan.status === "failed") return;
    pollRef.current = setInterval(async () => {
      try {
        const s = await apiFetch(url, token, `/scans/${activeScan.id}`);
        setScans(prev => prev.map(x => x.id === s.id ? s : x));
      } catch { /* ignore poll errors */ }
    }, 2000);
    return () => clearInterval(pollRef.current);
  }, [activeScan?.id, activeScan?.status, url, token]);

  const startScan = async () => {
    if (!target.trim()) { toast.error("Enter a target host or CIDR"); return; }
    if (!url) { toast.error("Configure backend URL first"); setSettingsOpen(true); return; }
    setSubmitting(true);
    try {
      const baseArgs = profile === "custom" ? customArgs : SCAN_PROFILES[profile].args;
      const finalArgs = ports.trim() && !baseArgs.includes("-p") ? `${baseArgs} -p ${ports.trim()}` : baseArgs;
      const scan = await apiFetch(url, token, "/scans", {
        method: "POST",
        body: JSON.stringify({ target: target.trim(), args: finalArgs }),
      });
      setScans(prev => [scan, ...prev]);
      setActiveScanId(scan.id);
      setActiveTab("ports");
      toast.success(`Scan started → ${scan.target}`);
    } catch (e) {
      toast.error(e.message || "Failed to start scan");
    } finally {
      setSubmitting(false);
    }
  };

  const cancelScan = async (id) => {
    try {
      await apiFetch(url, token, `/scans/${id}/cancel`, { method: "POST" });
      toast.success("Scan cancelled");
      loadScans();
    } catch (e) { toast.error(e.message); }
  };

  const deleteScan = async (id) => {
    try {
      await apiFetch(url, token, `/scans/${id}`, { method: "DELETE" });
      setScans(prev => prev.filter(s => s.id !== id));
      if (activeScanId === id) setActiveScanId(scans.find(s => s.id !== id)?.id || null);
      toast.success("Scan deleted");
    } catch (e) { toast.error(e.message); }
  };

  const exportJson = () => {
    if (!activeScan) return;
    const blob = new Blob([JSON.stringify(activeScan, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `nmap-scan-${activeScan.target}-${activeScan.id.slice(0, 8)}.json`;
    a.click();
    toast.success("Exported JSON");
  };

  return (
    <div style={styles.app}>
      <style>{globalStyles}</style>
      <ToastContainer toasts={toasts} />

      {/* ── HEADER ─────────────────────────────────────────────────── */}
      <header style={styles.header}>
        <div style={styles.headerInner}>
          <div style={styles.brand}>
            <div style={styles.brandIcon}>
              <Shield size={18} color="#4ade80" />
            </div>
            <div>
              <div style={styles.brandName}>Nmap Web Dashboard</div>
              <div style={styles.brandSub}>Network Intelligence Platform</div>
            </div>
          </div>
          <div style={styles.headerActions}>
            <div style={styles.backendPill}>
              <div style={{ width: 7, height: 7, borderRadius: "50%", background: url ? "#4ade80" : "#f87171" }} />
              <span style={{ fontSize: 11, color: "#94a3b8" }}>{url ? url.replace(/^https?:\/\//, "") : "No backend"}</span>
            </div>
            <button style={styles.btnIcon} onClick={loadScans} title="Refresh scans">
              <RefreshCw size={14} />
            </button>
            <button style={styles.btnSecondary} onClick={() => { setTmpUrl(url); setTmpToken(token); setSettingsOpen(true); }}>
              <Settings size={13} /> Backend
            </button>
          </div>
        </div>
      </header>

      <main style={styles.main}>
        {/* ── SCAN CONTROLS ──────────────────────────────────────── */}
        <div style={styles.scanCard}>
          <div style={styles.scanCardHeader}>
            <Terminal size={14} color="#4ade80" />
            <span style={{ fontSize: 13, fontWeight: 600, color: "#e2e8f0" }}>New Scan</span>
            {SCAN_PROFILES[profile]?.rootRequired && (
              <div style={styles.rootBadge}><Lock size={10} /> Root Required</div>
            )}
          </div>
          <div style={styles.scanGrid}>
            <div style={styles.field}>
              <label style={styles.label}>Target Host / CIDR</label>
              <input
                style={styles.input}
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === "Enter" && startScan()}
                placeholder="192.168.1.0/24 · host.example.com · 10.0.0.5"
              />
            </div>
            <div style={styles.field}>
              <label style={styles.label}>Scan Profile</label>
              <select style={styles.select} value={profile} onChange={e => setProfile(e.target.value)}>
                {Object.entries(SCAN_PROFILES).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
              <div style={styles.profileDesc}>{SCAN_PROFILES[profile].desc}</div>
            </div>
            <div style={styles.field}>
              <label style={styles.label}>Port Range (optional)</label>
              <input
                style={styles.input}
                value={ports}
                onChange={e => setPorts(e.target.value)}
                placeholder="22,80,443 · 1-1024"
              />
            </div>
            <div style={{ ...styles.field, justifyContent: "flex-end" }}>
              <button style={submitting ? styles.btnPrimaryDisabled : styles.btnPrimary} onClick={startScan} disabled={submitting}>
                {submitting ? <Loader2 size={13} className="spin" /> : <Play size={13} />}
                {submitting ? "Starting…" : "Run Scan"}
              </button>
            </div>
          </div>
          {profile === "custom" && (
            <div style={{ marginTop: 12 }}>
              <label style={styles.label}>Custom nmap Arguments</label>
              <input
                style={{ ...styles.input, fontFamily: "monospace" }}
                value={customArgs}
                onChange={e => setCustomArgs(e.target.value)}
                placeholder="-sV -p 1-1000 --script default -T4"
              />
            </div>
          )}
        </div>

        <div style={styles.bodyGrid}>
          {/* ── SCAN HISTORY ─────────────────────────────────────── */}
          <div style={styles.sidebar}>
            <div style={styles.sidebarHeader}>
              <span style={{ fontSize: 11, fontWeight: 600, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Scan History
              </span>
              <span style={styles.countBadge}>{scans.length}</span>
            </div>
            <div style={styles.scanList}>
              {scans.length === 0 && (
                <div style={styles.emptyState}>
                  <Terminal size={20} color="#334155" />
                  <div style={{ fontSize: 12, color: "#475569" }}>No scans yet</div>
                </div>
              )}
              {scans.map(s => (
                <ScanListItem
                  key={s.id}
                  scan={s}
                  active={activeScanId === s.id}
                  onClick={() => setActiveScanId(s.id)}
                  onCancel={() => cancelScan(s.id)}
                  onDelete={() => deleteScan(s.id)}
                />
              ))}
            </div>
          </div>

          {/* ── RESULTS PANEL ─────────────────────────────────────── */}
          <div style={styles.results}>
            {/* Stats row */}
            <div style={styles.statsRow}>
              <StatCard icon={<Server size={13} />} label="Hosts Up" value={`${stats.hostsUp} / ${stats.hostsTotal}`} color="#4ade80" />
              <StatCard icon={<CheckCircle size={13} />} label="Open" value={stats.open} color="#4ade80" />
              <StatCard icon={<Filter size={13} />} label="Filtered" value={stats.filtered} color="#fb923c" />
              <StatCard icon={<XCircle size={13} />} label="Closed" value={stats.closed} color="#f87171" />
              <StatCard icon={<Globe size={13} />} label="Total Ports" value={stats.total} color="#818cf8" />
            </div>

            {!activeScan ? (
              <div style={styles.emptyResults}>
                <Shield size={32} color="#1e3a5f" />
                <div style={{ fontSize: 14, color: "#475569", marginTop: 12 }}>Select a scan or run a new one</div>
                <div style={{ fontSize: 12, color: "#334155", marginTop: 4 }}>Results will appear here</div>
              </div>
            ) : (
              <div style={styles.resultCard}>
                {/* Result header */}
                <div style={styles.resultHeader}>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <span style={styles.resultTarget}>{activeScan.target}</span>
                      <StatusPill status={activeScan.status} />
                    </div>
                    <div style={styles.resultCmd}>{activeScan.command || `nmap ${activeScan.args} ${activeScan.target}`}</div>
                    <div style={styles.resultMeta}>
                      <Clock size={11} color="#475569" />
                      Started {fmtTime(activeScan.started_at)}
                      {activeScan.finished_at && (
                        <> · {fmtDuration(activeScan.started_at, activeScan.finished_at)} elapsed</>
                      )}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
                    <button style={styles.btnIcon} onClick={exportJson} title="Export JSON">
                      <Download size={13} />
                    </button>
                    {activeScan.status === "running" && (
                      <button style={styles.btnDanger} onClick={() => cancelScan(activeScan.id)}>
                        <StopCircle size={13} /> Stop
                      </button>
                    )}
                  </div>
                </div>

                {/* Error banner */}
                {activeScan.error && (
                  <div style={styles.errorBanner}>
                    <AlertTriangle size={13} />
                    {activeScan.error}
                  </div>
                )}

                {/* Tabs */}
                <div style={styles.tabs}>
                  {["ports", "hosts", "raw"].map(tab => (
                    <button
                      key={tab}
                      style={{ ...styles.tab, ...(activeTab === tab ? styles.tabActive : {}) }}
                      onClick={() => setActiveTab(tab)}
                    >
                      {tab === "ports" && `Ports & Services (${allPorts.length})`}
                      {tab === "hosts" && `Hosts (${activeScan.hosts?.length || 0})`}
                      {tab === "raw" && "Raw Output"}
                    </button>
                  ))}
                </div>

                {/* Tab content */}
                {activeTab === "ports" && (
                  <div>
                    <div style={styles.filterBar}>
                      <Search size={12} color="#475569" />
                      <input
                        style={styles.filterInput}
                        placeholder="Filter by port, host, service, state…"
                        value={portFilter}
                        onChange={e => setPortFilter(e.target.value)}
                      />
                    </div>
                    {filteredPorts.length === 0 ? (
                      <div style={styles.emptyTab}>
                        {activeScan.status === "running"
                          ? <><Loader2 size={16} className="spin" color="#4ade80" /><span>Scanning in progress…</span></>
                          : <><Activity size={16} color="#334155" /><span>No ports match your filter</span></>
                        }
                      </div>
                    ) : (
                      <div style={styles.tableWrap}>
                        <table style={styles.table}>
                          <thead>
                            <tr>
                              {["Host", "Port", "Proto", "State", "Service", "Product / Version", "CPE"].map(h => (
                                <th key={h} style={styles.th}>{h}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {filteredPorts.map((p, i) => {
                              const c = stateColors(p.state);
                              return (
                                <tr key={i} style={styles.tr} className="table-row-hover">
                                  <td style={{ ...styles.td, fontFamily: "monospace", fontSize: 11 }}>{p.host}</td>
                                  <td style={{ ...styles.td, fontFamily: "monospace", fontWeight: 700, color: "#e2e8f0" }}>{p.port}</td>
                                  <td style={styles.td}>
                                    <span style={{ ...styles.protoBadge }}>{p.protocol?.toUpperCase()}</span>
                                  </td>
                                  <td style={styles.td}>
                                    <span style={{
                                      ...styles.stateBadge,
                                      background: c.bg,
                                      color: c.text,
                                      border: `1px solid ${c.border}`,
                                    }}>{p.state}</span>
                                  </td>
                                  <td style={{ ...styles.td, color: "#94a3b8" }}>{p.service || "—"}</td>
                                  <td style={{ ...styles.td, fontSize: 11, color: "#94a3b8" }}>
                                    {[p.product, p.version, p.extrainfo].filter(Boolean).join(" ") || "—"}
                                  </td>
                                  <td style={{ ...styles.td, fontFamily: "monospace", fontSize: 10, color: "#475569" }}>
                                    {p.cpe || "—"}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === "hosts" && (
                  <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 10 }}>
                    {(activeScan.hosts || []).map(h => (
                      <div key={h.address} style={styles.hostCard}>
                        <div style={styles.hostCardHeader}>
                          <div>
                            <div style={{ fontFamily: "monospace", fontSize: 13, fontWeight: 700, color: "#e2e8f0" }}>
                              {h.address}
                              {h.hostname && <span style={{ fontSize: 11, color: "#4ade80", marginLeft: 8 }}>({h.hostname})</span>}
                            </div>
                            {h.os && <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>OS: {h.os}</div>}
                          </div>
                          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                            <span style={{
                              ...styles.stateBadge,
                              ...(h.status === "up" ? { background: "#052e16", color: "#4ade80", border: "1px solid #166534" } : { background: "#1a1f2e", color: "#94a3b8", border: "1px solid #334155" })
                            }}>{h.status}</span>
                            <span style={{ fontSize: 11, color: "#475569" }}>{h.ports?.length || 0} ports</span>
                          </div>
                        </div>
                        {h.ports?.length > 0 && (
                          <div style={styles.hostPortList}>
                            {h.ports.filter(p => p.state === "open").map((p, i) => (
                              <span key={i} style={styles.portChip}>
                                {p.port}/{p.protocol}
                                {p.service && <span style={{ color: "#4ade80", marginLeft: 4 }}>{p.service}</span>}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {activeTab === "raw" && (
                  <div style={styles.rawArea}>
                    <pre style={styles.rawPre}>{activeScan.raw || "(no raw output yet)"}</pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </main>

      {/* ── SETTINGS MODAL ─────────────────────────────────────────── */}
      {settingsOpen && (
        <div style={styles.modalOverlay} onClick={() => setSettingsOpen(false)}>
          <div style={styles.modal} onClick={e => e.stopPropagation()}>
            <div style={styles.modalHeader}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <Server size={15} color="#4ade80" />
                <span style={{ fontWeight: 700, fontSize: 15, color: "#e2e8f0" }}>Backend Connection</span>
              </div>
              <button style={styles.modalClose} onClick={() => setSettingsOpen(false)}>✕</button>
            </div>
            <p style={{ fontSize: 12, color: "#64748b", marginBottom: 20, lineHeight: 1.5 }}>
              Connect to your self-hosted FastAPI nmap backend. Run <code style={styles.inlineCode}>python nmap_backend.py</code> on
              any machine with nmap installed.
            </p>
            <div style={styles.field}>
              <label style={styles.label}>Backend URL</label>
              <input style={styles.input} value={tmpUrl} onChange={e => setTmpUrl(e.target.value)} placeholder="http://localhost:8765" />
            </div>
            <div style={{ ...styles.field, marginTop: 12 }}>
              <label style={styles.label}>Auth Token <span style={{ color: "#475569" }}>(optional)</span></label>
              <input
                type="password"
                style={styles.input}
                value={tmpToken}
                onChange={e => setTmpToken(e.target.value)}
                placeholder="NMAP_AUTH_TOKEN value"
              />
            </div>
            <div style={styles.modalFooter}>
              <button style={styles.btnSecondary} onClick={() => setSettingsOpen(false)}>Cancel</button>
              <button style={styles.btnPrimary} onClick={() => {
                save(tmpUrl, tmpToken);
                setSettingsOpen(false);
                toast.success("Backend configuration saved");
              }}>
                <CheckCircle size={13} /> Save
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function ScanListItem({ scan, active, onClick, onCancel, onDelete }) {
  const statusColor = { queued: "#64748b", running: "#818cf8", completed: "#4ade80", failed: "#f87171" };

  return (
    <div style={{ ...styles.scanItem, ...(active ? styles.scanItemActive : {}) }} onClick={onClick}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ fontWeight: 600, fontSize: 12, color: "#e2e8f0", fontFamily: "monospace", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginRight: 6 }}>
          {scan.target}
        </div>
        <span style={{ width: 7, height: 7, borderRadius: "50%", background: statusColor[scan.status] || "#64748b", flexShrink: 0, marginTop: 3, boxShadow: scan.status === "running" ? `0 0 6px ${statusColor.running}` : "none" }} />
      </div>
      <div style={{ fontSize: 10, color: "#475569", marginTop: 3, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {scan.args || "(default)"}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 6 }}>
        <span style={{ fontSize: 10, color: "#334155" }}>{fmtTime(scan.started_at)}</span>
        <div style={{ display: "flex", gap: 6 }} onClick={e => e.stopPropagation()}>
          {scan.status === "running" && (
            <button style={styles.inlineBtn} onClick={onCancel} title="Cancel">
              <StopCircle size={10} color="#fb923c" />
            </button>
          )}
          <button style={styles.inlineBtn} onClick={onDelete} title="Delete">
            <Trash2 size={10} color="#f87171" />
          </button>
        </div>
      </div>
    </div>
  );
}

function StatusPill({ status }) {
  const map = {
    queued:    { bg: "#1a1f2e", color: "#64748b", border: "#334155" },
    running:   { bg: "#1e1b4b", color: "#818cf8", border: "#4338ca" },
    completed: { bg: "#052e16", color: "#4ade80", border: "#166534" },
    failed:    { bg: "#2d1a1a", color: "#f87171", border: "#7f1d1d" },
  };
  const s = map[status] || map.queued;
  return (
    <span style={{ ...styles.stateBadge, background: s.bg, color: s.color, border: `1px solid ${s.border}`, display: "inline-flex", alignItems: "center", gap: 4 }}>
      {status === "running" && <Loader2 size={9} className="spin" />}
      {status}
    </span>
  );
}

function StatCard({ icon, label, value, color }) {
  return (
    <div style={styles.statCard}>
      <div style={{ fontSize: 10, color: "#475569", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6, display: "flex", alignItems: "center", gap: 5 }}>
        <span style={{ color }}>{icon}</span>
        {label}
      </div>
      <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: "monospace", letterSpacing: "-0.02em" }}>{value}</div>
    </div>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const C = {
  bg:         "#070c18",
  surface:    "#0d1526",
  surface2:   "#111827",
  border:     "#1e2d45",
  borderHi:   "#1e3a5f",
  text:       "#e2e8f0",
  textMuted:  "#94a3b8",
  textDim:    "#475569",
  green:      "#4ade80",
  greenDim:   "#166534",
  accent:     "#818cf8",
};

const styles = {
  app: {
    minHeight: "100vh",
    background: C.bg,
    color: C.text,
    fontFamily: "'IBM Plex Mono', 'Fira Code', 'Cascadia Code', monospace",
    fontSize: 13,
  },
  header: {
    borderBottom: `1px solid ${C.border}`,
    background: "rgba(13, 21, 38, 0.95)",
    backdropFilter: "blur(12px)",
    position: "sticky",
    top: 0,
    zIndex: 100,
  },
  headerInner: {
    maxWidth: 1400,
    margin: "0 auto",
    padding: "12px 24px",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
  },
  brand: { display: "flex", alignItems: "center", gap: 12 },
  brandIcon: {
    width: 36, height: 36,
    background: "linear-gradient(135deg, #0d2b4e 0%, #0a1f6b 100%)",
    borderRadius: 8,
    border: `1px solid ${C.borderHi}`,
    display: "flex", alignItems: "center", justifyContent: "center",
  },
  brandName: { fontSize: 14, fontWeight: 700, color: C.text, letterSpacing: "-0.01em" },
  brandSub: { fontSize: 10, color: C.textDim, marginTop: 1, letterSpacing: "0.05em" },
  headerActions: { display: "flex", alignItems: "center", gap: 10 },
  backendPill: {
    display: "flex", alignItems: "center", gap: 6,
    padding: "4px 10px", borderRadius: 20,
    background: C.surface2, border: `1px solid ${C.border}`,
    maxWidth: 220, overflow: "hidden",
  },
  btnIcon: {
    width: 30, height: 30, borderRadius: 6, border: `1px solid ${C.border}`,
    background: C.surface2, color: C.textMuted, cursor: "pointer",
    display: "flex", alignItems: "center", justifyContent: "center",
    transition: "all 0.15s",
  },
  btnSecondary: {
    height: 30, padding: "0 12px", borderRadius: 6,
    border: `1px solid ${C.border}`, background: C.surface2,
    color: C.textMuted, cursor: "pointer", fontSize: 12, fontWeight: 500,
    display: "inline-flex", alignItems: "center", gap: 6, transition: "all 0.15s",
    fontFamily: "inherit",
  },
  btnPrimary: {
    height: 34, padding: "0 16px", borderRadius: 6,
    border: "1px solid #166534", background: "linear-gradient(135deg, #052e16 0%, #0d4e28 100%)",
    color: C.green, cursor: "pointer", fontSize: 12, fontWeight: 600,
    display: "inline-flex", alignItems: "center", gap: 6, transition: "all 0.15s",
    fontFamily: "inherit",
  },
  btnPrimaryDisabled: {
    height: 34, padding: "0 16px", borderRadius: 6,
    border: `1px solid ${C.border}`, background: C.surface2,
    color: C.textDim, cursor: "not-allowed", fontSize: 12, fontWeight: 600,
    display: "inline-flex", alignItems: "center", gap: 6,
    fontFamily: "inherit",
  },
  btnDanger: {
    height: 30, padding: "0 12px", borderRadius: 6,
    border: "1px solid #7f1d1d", background: "#2d1a1a",
    color: "#f87171", cursor: "pointer", fontSize: 11, fontWeight: 600,
    display: "inline-flex", alignItems: "center", gap: 5, fontFamily: "inherit",
  },
  main: { maxWidth: 1400, margin: "0 auto", padding: "20px 24px" },
  scanCard: {
    background: C.surface,
    border: `1px solid ${C.border}`,
    borderRadius: 10,
    padding: "16px 20px",
    marginBottom: 20,
  },
  scanCardHeader: {
    display: "flex", alignItems: "center", gap: 8, marginBottom: 14,
    paddingBottom: 14, borderBottom: `1px solid ${C.border}`,
  },
  rootBadge: {
    marginLeft: "auto", display: "flex", alignItems: "center", gap: 4,
    background: "#1a1205", border: "1px solid #78350f", borderRadius: 4,
    color: "#fb923c", fontSize: 10, fontWeight: 600, padding: "2px 7px",
  },
  scanGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr 180px auto",
    gap: 12,
    alignItems: "end",
  },
  field: { display: "flex", flexDirection: "column", gap: 5 },
  label: { fontSize: 10, color: C.textDim, letterSpacing: "0.07em", textTransform: "uppercase", fontWeight: 600 },
  input: {
    height: 34, padding: "0 10px", borderRadius: 6,
    border: `1px solid ${C.border}`, background: C.surface2,
    color: C.text, fontSize: 12, outline: "none",
    fontFamily: "inherit", transition: "border-color 0.15s",
  },
  select: {
    height: 34, padding: "0 10px", borderRadius: 6,
    border: `1px solid ${C.border}`, background: C.surface2,
    color: C.text, fontSize: 12, outline: "none",
    fontFamily: "inherit", cursor: "pointer",
  },
  profileDesc: { fontSize: 10, color: C.textDim, marginTop: 2 },
  bodyGrid: { display: "grid", gridTemplateColumns: "260px 1fr", gap: 16 },
  sidebar: {
    background: C.surface,
    border: `1px solid ${C.border}`,
    borderRadius: 10,
    overflow: "hidden",
    display: "flex",
    flexDirection: "column",
    maxHeight: "calc(100vh - 200px)",
  },
  sidebarHeader: {
    padding: "10px 14px",
    borderBottom: `1px solid ${C.border}`,
    display: "flex", alignItems: "center", justifyContent: "space-between",
  },
  countBadge: {
    fontSize: 10, background: C.surface2, border: `1px solid ${C.border}`,
    borderRadius: 10, padding: "1px 7px", color: C.textDim,
  },
  scanList: { overflow: "auto", flex: 1 },
  scanItem: {
    padding: "10px 14px", borderBottom: `1px solid ${C.border}`,
    cursor: "pointer", transition: "background 0.1s",
  },
  scanItemActive: { background: "#0a1626", borderLeft: `2px solid ${C.green}` },
  inlineBtn: {
    background: "none", border: "none", cursor: "pointer",
    padding: 3, borderRadius: 4, display: "flex", alignItems: "center",
  },
  emptyState: {
    display: "flex", flexDirection: "column", alignItems: "center",
    gap: 8, padding: "40px 20px", color: C.textDim,
  },
  results: { display: "flex", flexDirection: "column", gap: 14 },
  statsRow: { display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10 },
  statCard: {
    background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 8, padding: "12px 16px",
  },
  emptyResults: {
    background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 10, padding: "60px 20px",
    display: "flex", flexDirection: "column", alignItems: "center",
  },
  resultCard: {
    background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 10, overflow: "hidden",
  },
  resultHeader: {
    padding: "14px 20px", borderBottom: `1px solid ${C.border}`,
    display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16,
  },
  resultTarget: { fontSize: 15, fontWeight: 700, color: C.text, fontFamily: "monospace" },
  resultCmd: { fontSize: 10, color: C.textDim, fontFamily: "monospace", marginTop: 4 },
  resultMeta: { fontSize: 10, color: C.textDim, marginTop: 5, display: "flex", alignItems: "center", gap: 5 },
  errorBanner: {
    margin: "0 20px 0 20px", marginTop: 12,
    background: "#2d1a1a", border: "1px solid #7f1d1d", borderRadius: 6,
    color: "#f87171", fontSize: 11, padding: "8px 12px",
    display: "flex", alignItems: "center", gap: 7,
  },
  tabs: {
    display: "flex", padding: "0 20px", borderBottom: `1px solid ${C.border}`, gap: 0,
  },
  tab: {
    background: "none", border: "none", borderBottom: "2px solid transparent",
    color: C.textDim, padding: "10px 14px", cursor: "pointer", fontSize: 11,
    fontFamily: "inherit", fontWeight: 500, transition: "all 0.15s",
  },
  tabActive: { color: C.green, borderBottom: `2px solid ${C.green}` },
  filterBar: {
    display: "flex", alignItems: "center", gap: 8,
    padding: "10px 20px", borderBottom: `1px solid ${C.border}`,
    background: C.surface2,
  },
  filterInput: {
    flex: 1, background: "none", border: "none", outline: "none",
    color: C.text, fontSize: 11, fontFamily: "inherit",
  },
  emptyTab: {
    padding: "40px 20px", display: "flex", alignItems: "center",
    justifyContent: "center", gap: 10, color: C.textDim, fontSize: 12,
  },
  tableWrap: { overflowX: "auto" },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: {
    padding: "8px 12px", textAlign: "left",
    fontSize: 9, color: C.textDim, fontWeight: 700,
    textTransform: "uppercase", letterSpacing: "0.07em",
    borderBottom: `1px solid ${C.border}`, background: C.surface2,
    position: "sticky", top: 0,
  },
  tr: { borderBottom: `1px solid rgba(30,45,69,0.5)`, transition: "background 0.1s" },
  td: { padding: "7px 12px", color: C.textMuted },
  stateBadge: {
    display: "inline-block", padding: "2px 7px", borderRadius: 4,
    fontSize: 10, fontWeight: 700, letterSpacing: "0.04em",
  },
  protoBadge: {
    display: "inline-block", padding: "1px 5px", borderRadius: 3,
    fontSize: 9, fontWeight: 700, letterSpacing: "0.06em",
    background: "#0d1f3c", color: C.accent, border: "1px solid #1e3a5f",
  },
  hostCard: {
    background: C.surface2, border: `1px solid ${C.border}`,
    borderRadius: 8, overflow: "hidden",
  },
  hostCardHeader: {
    padding: "10px 14px", borderBottom: `1px solid ${C.border}`,
    display: "flex", justifyContent: "space-between", alignItems: "center",
  },
  hostPortList: {
    padding: "8px 14px", display: "flex", flexWrap: "wrap", gap: 5,
  },
  portChip: {
    background: "#0a1626", border: `1px solid ${C.border}`,
    borderRadius: 4, padding: "2px 7px", fontSize: 10, fontFamily: "monospace", color: C.textMuted,
  },
  rawArea: { maxHeight: 420, overflow: "auto", background: C.surface2 },
  rawPre: {
    padding: 16, margin: 0, fontSize: 11, fontFamily: "monospace",
    color: "#94a3b8", lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-word",
  },
  modalOverlay: {
    position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)",
    backdropFilter: "blur(4px)", zIndex: 200,
    display: "flex", alignItems: "center", justifyContent: "center",
  },
  modal: {
    background: C.surface, border: `1px solid ${C.borderHi}`,
    borderRadius: 12, padding: "24px", width: "100%", maxWidth: 440,
    boxShadow: "0 25px 60px rgba(0,0,0,0.7)",
  },
  modalHeader: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    marginBottom: 12,
  },
  modalClose: {
    background: "none", border: "none", color: C.textDim,
    cursor: "pointer", fontSize: 14, padding: "2px 6px", borderRadius: 4,
  },
  modalFooter: {
    display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 20,
  },
  inlineCode: {
    fontFamily: "monospace", fontSize: 11,
    background: C.surface2, border: `1px solid ${C.border}`,
    borderRadius: 3, padding: "1px 5px", color: C.green,
  },
};

const globalStyles = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #070c18; }
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&display=swap');

  @keyframes slideIn {
    from { opacity: 0; transform: translateX(20px); }
    to   { opacity: 1; transform: translateX(0); }
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
  .spin { animation: spin 0.8s linear infinite; display: inline-block; }

  .table-row-hover:hover { background: rgba(30, 58, 95, 0.3) !important; }

  input::placeholder { color: #334155; }
  input:focus { border-color: #1e3a5f !important; }
  select option { background: #111827; }

  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: #1e2d45; border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: #1e3a5f; }
`;
