import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, Globe, Loader2, Play, Server, Settings, Shield, StopCircle, Trash2, Download, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast, Toaster } from "sonner";

export const Route = createFileRoute("/")({
  component: Dashboard,
  head: () => ({
    meta: [
      { title: "Nmap Web Dashboard — Run scans & visualize ports, services, versions" },
      { name: "description", content: "Self-hosted nmap web tool. Launch TCP/UDP scans, see open/closed/filtered ports, services and versions in a live dashboard." },
    ],
  }),
});

type PortRow = {
  host: string;
  port: number;
  protocol: "tcp" | "udp";
  state: "open" | "closed" | "filtered" | "open|filtered" | "closed|filtered" | string;
  service: string;
  product?: string;
  version?: string;
  extrainfo?: string;
  cpe?: string;
};

type HostRow = {
  address: string;
  hostname?: string;
  status: "up" | "down" | string;
  os?: string;
  ports: PortRow[];
};

type ScanStatus = "queued" | "running" | "completed" | "failed";

type Scan = {
  id: string;
  target: string;
  args: string;
  status: ScanStatus;
  started_at: string;
  finished_at?: string;
  command?: string;
  error?: string;
  hosts: HostRow[];
  raw?: string;
};

const SCAN_PROFILES: Record<string, { label: string; args: string; desc: string }> = {
  quick:      { label: "Quick Scan",            args: "-T4 -F",                     desc: "Fast scan of top 100 ports" },
  intense:    { label: "Intense Scan",          args: "-T4 -A -v",                  desc: "OS, version, script, traceroute" },
  full_tcp:   { label: "Full TCP Port Scan",    args: "-p- -T4 -sV",                desc: "All 65535 TCP ports + service detection" },
  service:    { label: "Service Version Scan",  args: "-sV -T4",                    desc: "Detect service versions on top ports" },
  udp:        { label: "UDP Scan (top 200)",    args: "-sU --top-ports 200 -T4",    desc: "UDP scan — requires root on backend" },
  syn_stealth:{ label: "SYN Stealth Scan",      args: "-sS -T4",                    desc: "Half-open SYN scan (root required)" },
  os_detect:  { label: "OS Detection",          args: "-O -T4",                     desc: "Fingerprint operating system (root required)" },
  vuln:       { label: "Vulnerability Scripts", args: "-sV --script vuln -T4",      desc: "Run NSE vuln category scripts" },
  ping:       { label: "Ping Sweep",            args: "-sn",                        desc: "Discover live hosts only" },
  aggressive: { label: "Aggressive Full",       args: "-A -T4 -p- -sV --script default", desc: "Everything (slow)" },
  custom:     { label: "Custom Arguments",      args: "",                            desc: "Provide your own nmap flags" },
};

const LS_BACKEND = "nmap_backend_url";
const LS_TOKEN = "nmap_backend_token";

function useBackend() {
  const [url, setUrl] = useState<string>(() =>
    typeof window === "undefined" ? "" : localStorage.getItem(LS_BACKEND) || "http://localhost:8765"
  );
  const [token, setToken] = useState<string>(() =>
    typeof window === "undefined" ? "" : localStorage.getItem(LS_TOKEN) || ""
  );
  const save = (u: string, t: string) => {
    setUrl(u); setToken(t);
    localStorage.setItem(LS_BACKEND, u);
    localStorage.setItem(LS_TOKEN, t);
  };
  return { url, token, save };
}

async function api<T>(base: string, token: string, path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(base.replace(/\/$/, "") + path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "X-Auth-Token": token } : {}),
      ...(init?.headers || {}),
    },
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText} — ${txt || "request failed"}`);
  }
  return res.json() as Promise<T>;
}

function stateColor(state: string) {
  if (state === "open") return "bg-emerald-500/15 text-emerald-600 border-emerald-500/30";
  if (state === "closed") return "bg-rose-500/15 text-rose-600 border-rose-500/30";
  if (state.includes("filtered")) return "bg-amber-500/15 text-amber-600 border-amber-500/30";
  return "bg-muted text-muted-foreground border-border";
}

function Dashboard() {
  const { url, token, save } = useBackend();
  const [target, setTarget] = useState("scanme.nmap.org");
  const [profile, setProfile] = useState<keyof typeof SCAN_PROFILES>("quick");
  const [ports, setPorts] = useState("");
  const [customArgs, setCustomArgs] = useState("");
  const [scans, setScans] = useState<Scan[]>([]);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [tmpUrl, setTmpUrl] = useState(url);
  const [tmpToken, setTmpToken] = useState(token);
  const pollRef = useRef<number | null>(null);

  const activeScan = useMemo(() => scans.find(s => s.id === activeScanId) || null, [scans, activeScanId]);

  const allPorts = useMemo(() => {
    const rows: (PortRow & { host: string })[] = [];
    activeScan?.hosts.forEach(h => h.ports.forEach(p => rows.push({ ...p, host: h.address })));
    return rows;
  }, [activeScan]);

  const stats = useMemo(() => {
    const hosts = activeScan?.hosts ?? [];
    const up = hosts.filter(h => h.status === "up").length;
    const open = allPorts.filter(p => p.state === "open").length;
    const filtered = allPorts.filter(p => p.state.includes("filtered")).length;
    const closed = allPorts.filter(p => p.state === "closed").length;
    return { hostsUp: up, hostsTotal: hosts.length, open, filtered, closed, totalPorts: allPorts.length };
  }, [activeScan, allPorts]);

  // Load existing scans
  const loadScans = async () => {
    if (!url) return;
    try {
      const data = await api<Scan[]>(url, token, "/scans");
      setScans(data);
      if (!activeScanId && data[0]) setActiveScanId(data[0].id);
    } catch (e: any) {
      console.error(e);
    }
  };

  useEffect(() => { loadScans(); /* eslint-disable-next-line */ }, [url, token]);

  // Poll active scan while running
  useEffect(() => {
    if (pollRef.current) window.clearInterval(pollRef.current);
    if (!activeScan || activeScan.status === "completed" || activeScan.status === "failed") return;
    pollRef.current = window.setInterval(async () => {
      try {
        const s = await api<Scan>(url, token, `/scans/${activeScan.id}`);
        setScans(prev => prev.map(x => x.id === s.id ? s : x));
      } catch (e) { /* ignore */ }
    }, 2000);
    return () => { if (pollRef.current) window.clearInterval(pollRef.current); };
  }, [activeScan?.id, activeScan?.status, url, token]);

  const startScan = async () => {
    if (!target.trim()) { toast.error("Enter a target host or CIDR"); return; }
    if (!url) { toast.error("Configure backend URL first"); setSettingsOpen(true); return; }
    setSubmitting(true);
    try {
      const args = profile === "custom" ? customArgs : SCAN_PROFILES[profile].args;
      const finalArgs = ports.trim() && !args.includes("-p") ? `${args} -p ${ports.trim()}` : args;
      const scan = await api<Scan>(url, token, "/scans", {
        method: "POST",
        body: JSON.stringify({ target: target.trim(), args: finalArgs }),
      });
      setScans(prev => [scan, ...prev]);
      setActiveScanId(scan.id);
      toast.success("Scan started");
    } catch (e: any) {
      toast.error(e.message || "Failed to start scan");
    } finally {
      setSubmitting(false);
    }
  };

  const cancelScan = async (id: string) => {
    try { await api(url, token, `/scans/${id}/cancel`, { method: "POST" }); toast.success("Cancel requested"); }
    catch (e: any) { toast.error(e.message); }
  };
  const deleteScan = async (id: string) => {
    try {
      await api(url, token, `/scans/${id}`, { method: "DELETE" });
      setScans(prev => prev.filter(s => s.id !== id));
      if (activeScanId === id) setActiveScanId(null);
    } catch (e: any) { toast.error(e.message); }
  };

  const exportJson = () => {
    if (!activeScan) return;
    const blob = new Blob([JSON.stringify(activeScan, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `nmap-${activeScan.id}.json`;
    a.click();
  };

  return (
    <div className="min-h-screen bg-background">
      <Toaster richColors position="top-right" />
      {/* Header */}
      <header className="border-b bg-card">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="grid h-9 w-9 place-items-center rounded-md bg-primary text-primary-foreground">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight">Nmap Web Dashboard</h1>
              <p className="text-xs text-muted-foreground">Run scans on your self-hosted backend</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={loadScans}>
              <RefreshCw className="mr-2 h-4 w-4" /> Refresh
            </Button>
            <Dialog open={settingsOpen} onOpenChange={setSettingsOpen}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm"><Settings className="mr-2 h-4 w-4" />Backend</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Backend connection</DialogTitle>
                  <DialogDescription>
                    Point this UI at your self-hosted nmap backend (FastAPI). Default: <code>http://localhost:8765</code>
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-3">
                  <div>
                    <Label htmlFor="burl">Backend URL</Label>
                    <Input id="burl" value={tmpUrl} onChange={e => setTmpUrl(e.target.value)} placeholder="http://localhost:8765" />
                  </div>
                  <div>
                    <Label htmlFor="btok">Auth Token (optional)</Label>
                    <Input id="btok" value={tmpToken} onChange={e => setTmpToken(e.target.value)} placeholder="X-Auth-Token value" />
                  </div>
                </div>
                <DialogFooter>
                  <Button onClick={() => { save(tmpUrl, tmpToken); setSettingsOpen(false); toast.success("Saved"); }}>Save</Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-6">
        {/* Scan controls */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Play className="h-4 w-4" /> New Scan</CardTitle>
            <CardDescription>Run nmap in the background on your backend host. Results stream into the dashboard below.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
              <div className="md:col-span-4">
                <Label htmlFor="target">Target</Label>
                <Input id="target" value={target} onChange={e => setTarget(e.target.value)} placeholder="192.168.1.0/24, host.com, 10.0.0.5" />
              </div>
              <div className="md:col-span-3">
                <Label>Scan profile</Label>
                <Select value={profile} onValueChange={v => setProfile(v as any)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Object.entries(SCAN_PROFILES).map(([k, v]) => (
                      <SelectItem key={k} value={k}>{v.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="mt-1 text-xs text-muted-foreground">{SCAN_PROFILES[profile].desc}</p>
              </div>
              <div className="md:col-span-2">
                <Label htmlFor="ports">Ports (optional)</Label>
                <Input id="ports" value={ports} onChange={e => setPorts(e.target.value)} placeholder="22,80,443 or 1-1000" />
              </div>
              <div className="md:col-span-3 flex items-end">
                <Button className="w-full" onClick={startScan} disabled={submitting}>
                  {submitting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}
                  Start Scan
                </Button>
              </div>
              {profile === "custom" && (
                <div className="md:col-span-12">
                  <Label htmlFor="ca">Custom nmap arguments</Label>
                  <Input id="ca" value={customArgs} onChange={e => setCustomArgs(e.target.value)} placeholder="-sV -p 1-1000 --script default -T4" />
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[280px_1fr]">
          {/* Scan list */}
          <Card>
            <CardHeader className="pb-3"><CardTitle className="text-sm">Scan history</CardTitle></CardHeader>
            <CardContent className="p-0">
              <ScrollArea className="h-[600px]">
                {scans.length === 0 && (
                  <p className="px-4 pb-4 text-sm text-muted-foreground">No scans yet.</p>
                )}
                <ul className="divide-y">
                  {scans.map(s => (
                    <li
                      key={s.id}
                      onClick={() => setActiveScanId(s.id)}
                      className={`cursor-pointer px-4 py-3 hover:bg-accent ${activeScanId === s.id ? "bg-accent" : ""}`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-sm font-medium">{s.target}</span>
                        <StatusBadge status={s.status} />
                      </div>
                      <div className="mt-1 truncate text-xs text-muted-foreground">{s.args || "(default)"}</div>
                      <div className="mt-1 flex items-center justify-between text-[11px] text-muted-foreground">
                        <span>{new Date(s.started_at).toLocaleString()}</span>
                        <div className="flex gap-1">
                          {s.status === "running" && (
                            <button onClick={(e) => { e.stopPropagation(); cancelScan(s.id); }} className="text-amber-600 hover:underline">cancel</button>
                          )}
                          <button onClick={(e) => { e.stopPropagation(); deleteScan(s.id); }} className="text-rose-600 hover:underline">delete</button>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              </ScrollArea>
            </CardContent>
          </Card>

          {/* Results */}
          <div className="space-y-6">
            {/* Stats */}
            <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
              <StatCard icon={<Server className="h-4 w-4" />} label="Hosts up" value={`${stats.hostsUp}/${stats.hostsTotal}`} />
              <StatCard icon={<Activity className="h-4 w-4" />} label="Open" value={stats.open} tone="emerald" />
              <StatCard icon={<Activity className="h-4 w-4" />} label="Filtered" value={stats.filtered} tone="amber" />
              <StatCard icon={<Activity className="h-4 w-4" />} label="Closed" value={stats.closed} tone="rose" />
              <StatCard icon={<Globe className="h-4 w-4" />} label="Total ports" value={stats.totalPorts} />
            </div>

            {!activeScan ? (
              <Card><CardContent className="py-16 text-center text-sm text-muted-foreground">Select or start a scan to see results.</CardContent></Card>
            ) : (
              <Card>
                <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
                  <div>
                    <CardTitle className="text-base">{activeScan.target}</CardTitle>
                    <CardDescription className="mt-1 font-mono text-xs">{activeScan.command || `nmap ${activeScan.args} ${activeScan.target}`}</CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <StatusBadge status={activeScan.status} />
                    <Button size="sm" variant="outline" onClick={exportJson}><Download className="mr-2 h-4 w-4" />Export JSON</Button>
                    {activeScan.status === "running" && (
                      <Button size="sm" variant="outline" onClick={() => cancelScan(activeScan.id)}>
                        <StopCircle className="mr-2 h-4 w-4" />Stop
                      </Button>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  <Tabs defaultValue="ports">
                    <TabsList>
                      <TabsTrigger value="ports">Ports & Services</TabsTrigger>
                      <TabsTrigger value="hosts">Hosts</TabsTrigger>
                      <TabsTrigger value="raw">Raw Output</TabsTrigger>
                    </TabsList>

                    <TabsContent value="ports" className="mt-4">
                      {allPorts.length === 0 ? (
                        <p className="py-10 text-center text-sm text-muted-foreground">
                          {activeScan.status === "running" ? "Scanning…" : "No ports reported."}
                        </p>
                      ) : (
                        <div className="overflow-x-auto rounded-md border">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Host</TableHead>
                                <TableHead>Port</TableHead>
                                <TableHead>Proto</TableHead>
                                <TableHead>State</TableHead>
                                <TableHead>Service</TableHead>
                                <TableHead>Product / Version</TableHead>
                                <TableHead>CPE</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {allPorts.map((p, i) => (
                                <TableRow key={i}>
                                  <TableCell className="font-mono text-xs">{p.host}</TableCell>
                                  <TableCell className="font-mono">{p.port}</TableCell>
                                  <TableCell><Badge variant="outline" className="uppercase">{p.protocol}</Badge></TableCell>
                                  <TableCell><span className={`rounded border px-2 py-0.5 text-xs ${stateColor(p.state)}`}>{p.state}</span></TableCell>
                                  <TableCell>{p.service || "—"}</TableCell>
                                  <TableCell className="text-sm">
                                    {[p.product, p.version, p.extrainfo].filter(Boolean).join(" ") || "—"}
                                  </TableCell>
                                  <TableCell className="font-mono text-xs text-muted-foreground">{p.cpe || "—"}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      )}
                    </TabsContent>

                    <TabsContent value="hosts" className="mt-4 space-y-3">
                      {activeScan.hosts.map(h => (
                        <div key={h.address} className="rounded-md border p-3">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div>
                              <div className="font-mono text-sm font-medium">{h.address}{h.hostname ? ` (${h.hostname})` : ""}</div>
                              {h.os && <div className="text-xs text-muted-foreground">OS: {h.os}</div>}
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge variant={h.status === "up" ? "default" : "secondary"}>{h.status}</Badge>
                              <span className="text-xs text-muted-foreground">{h.ports.length} ports</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </TabsContent>

                    <TabsContent value="raw" className="mt-4">
                      <Textarea readOnly className="h-[420px] font-mono text-xs" value={activeScan.raw || "(no raw output yet)"} />
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </Card>
            )}

            <BackendHelp />
          </div>
        </div>
      </main>
    </div>
  );
}

function StatusBadge({ status }: { status: ScanStatus | string }) {
  const map: Record<string, string> = {
    queued: "bg-muted text-muted-foreground",
    running: "bg-blue-500/15 text-blue-600 border border-blue-500/30",
    completed: "bg-emerald-500/15 text-emerald-600 border border-emerald-500/30",
    failed: "bg-rose-500/15 text-rose-600 border border-rose-500/30",
  };
  return (
    <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium ${map[status] || "bg-muted"}`}>
      {status === "running" && <Loader2 className="h-3 w-3 animate-spin" />}
      {status}
    </span>
  );
}

function StatCard({ icon, label, value, tone }: { icon: React.ReactNode; label: string; value: React.ReactNode; tone?: "emerald" | "amber" | "rose" }) {
  const toneCls = tone === "emerald" ? "text-emerald-600"
                : tone === "amber" ? "text-amber-600"
                : tone === "rose" ? "text-rose-600"
                : "text-foreground";
  return (
    <Card>
      <CardContent className="flex items-center justify-between py-4">
        <div>
          <div className="text-xs text-muted-foreground">{label}</div>
          <div className={`text-xl font-semibold ${toneCls}`}>{value}</div>
        </div>
        <div className="text-muted-foreground">{icon}</div>
      </CardContent>
    </Card>
  );
}

function BackendHelp() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Backend setup</CardTitle>
        <CardDescription>
          This UI needs a small FastAPI service running on a host where <code>nmap</code> is installed.
          Save the script below as <code>nmap_backend.py</code> and run it.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ol className="mb-3 list-decimal space-y-1 pl-5 text-sm text-muted-foreground">
          <li><code>sudo apt install nmap</code> (or <code>brew install nmap</code>)</li>
          <li><code>pip install fastapi uvicorn python-nmap</code></li>
          <li><code>sudo python nmap_backend.py</code> (sudo needed for SYN/UDP/OS scans)</li>
          <li>Open the Backend dialog above and set URL to <code>http://your-host:8765</code></li>
        </ol>
        <p className="text-xs text-muted-foreground">
          ⚠️ Only scan hosts you own or have explicit permission to test.
        </p>
      </CardContent>
    </Card>
  );
}
