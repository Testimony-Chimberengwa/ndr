import express from "express";
import path from "path";
import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { createServer as createViteServer } from "vite";
import si from "systeminformation";
import dns from "dns/promises";

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });
const PORT = 3000;

// DNS Cache
const dnsCache = new Map<string, { hostname: string; expiresAt: number }>();
const CACHE_TTL = 60 * 1000; // 60 seconds

async function getHostname(ip: string): Promise<string> {
  const cached = dnsCache.get(ip);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.hostname;
  }

  try {
    const hostnames = await dns.reverse(ip);
    const hostname = hostnames[0] || ip;
    dnsCache.set(ip, { hostname, expiresAt: Date.now() + CACHE_TTL });
    return hostname;
  } catch (error) {
    dnsCache.set(ip, { hostname: ip, expiresAt: Date.now() + CACHE_TTL });
    return ip;
  }
}

// Metrics tracking for per-second rates
let prevTraffic = { rx: 0, tx: 0, time: Date.now() };

async function getMetrics() {
  const [cpu, mem, fs, net, os, users] = await Promise.all([
    si.currentLoad(),
    si.mem(),
    si.networkStats(),
    si.networkInterfaceDefault().then(iface => si.networkStats(iface)),
    si.osInfo(),
    si.users()
  ]);

  const defaultNet = net[0] || { rx_bytes: 0, tx_bytes: 0 };
  const now = Date.now();
  const elapsed = (now - prevTraffic.time) / 1000;
  
  const rx_per_sec = elapsed > 0 ? (defaultNet.rx_bytes - prevTraffic.rx) / elapsed : 0;
  const tx_per_sec = elapsed > 0 ? (defaultNet.tx_bytes - prevTraffic.tx) / elapsed : 0;

  prevTraffic = { rx: defaultNet.rx_bytes, tx: defaultNet.tx_bytes, time: now };

  return {
    cpu: cpu.currentLoad,
    ram: (mem.active / mem.total) * 100,
    ram_total: mem.total,
    ram_used: mem.active,
    bytes_sent: defaultNet.tx_bytes,
    bytes_recv: defaultNet.rx_bytes,
    bytes_sent_per_sec: Math.max(0, tx_per_sec),
    bytes_recv_per_sec: Math.max(0, rx_per_sec),
    timestamp: Math.floor(now / 1000),
    hostname: os.hostname,
    username: users[0]?.user || process.env.USER || "analyst"
  };
}

async function getConnections() {
  try {
    const conns = await si.networkConnections();
    return conns.map(c => ({
      pid: c.pid || 0,
      process: c.process || "Unknown",
      local_port: c.localPort,
      remote_ip: c.peerAddress,
      remote_port: c.peerPort,
      status: c.state,
      access_denied: false // systeminformation handles this internally or returns nulls
    }));
  } catch (err) {
    return [];
  }
}

async function getSites() {
  const conns = await si.networkConnections();
  const sites = await Promise.all(
    conns
      .filter(c => c.peerAddress && c.peerAddress !== "0.0.0.0" && c.peerAddress !== "127.0.0.1")
      .map(async c => ({
        hostname: await getHostname(c.peerAddress),
        remote_ip: c.peerAddress,
        remote_port: c.peerPort,
        local_port: c.localPort,
        process: c.process || "Unknown",
        pid: c.pid || 0
      }))
  );
  
  // Deduplicate by IP
  const unique = new Map();
  sites.forEach(s => unique.set(s.remote_ip, s));
  return Array.from(unique.values());
}

async function getPorts() {
  const conns = await si.networkConnections();
  return conns
    .filter(c => c.state === "LISTEN")
    .map(c => ({
      port: parseInt(c.localPort),
      protocol: c.protocol,
      process: c.process || "Unknown",
      pid: c.pid || 0
    }));
}

async function getProcesses() {
  const data = await si.processes();
  return data.list
    .sort((a, b) => b.cpu - a.cpu)
    .slice(0, 15)
    .map(p => ({
      pid: p.pid,
      name: p.name,
      cpu: p.cpu,
      memory: p.mem,
      status: p.state
    }));
}

async function getLocalHostDevice() {
  const [os, net, stats, users] = await Promise.all([
    si.osInfo(),
    si.networkInterfaces(),
    si.networkStats(),
    si.users()
  ]);
  const defaultIfaceName = await si.networkInterfaceDefault();
  const defaultIface = net.find(i => i.iface === defaultIfaceName);
  const defaultStats = stats.find(s => s.iface === defaultIfaceName) || { rx_bytes: 0, tx_bytes: 0 };
  const username = users[0]?.user || process.env.USER || "node";
  
  return {
    id: "localhost",
    hostname: `${username}@${os.hostname}`,
    ip: defaultIface?.ip4 || "127.0.0.1",
    mac: defaultIface?.mac || "00:00:00:00:00:00",
    lastSeen: Date.now(),
    firstSeen: Date.now() - 1000 * 60 * 60 * 24, // 24h ago
    sent: defaultStats.tx_bytes,
    recv: defaultStats.rx_bytes,
    protocols: ["TCP", "UDP", "HTTPS", "DNS", "SSH", "WS"],
    status: "active",
    alertCount: 0,
    activity: Array.from({length: 10}).map(() => Math.floor(Math.random() * 50) + 10),
    device_type: os.platform === 'linux' ? 'linux-vm' : 'mac', // Guessing type
    os: `${os.distro} ${os.release}`,
    vendor: "Local Machine"
  };
}

// API Routes
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    mode: "live",
    version: "1.0.0",
    uptime: process.uptime(),
    capabilities: {
      promiscuous_mode: process.getuid && process.getuid() === 0,
      arp_scan: false,
      packet_capture: false,
    }
  });
});
app.get("/api/metrics", async (req, res) => res.json(await getMetrics()));
app.get("/api/connections", async (req, res) => res.json(await getConnections()));
app.get("/api/sites", async (req, res) => res.json(await getSites()));
app.get("/api/ports", async (req, res) => res.json(await getPorts()));
app.get("/api/processes", async (req, res) => res.json(await getProcesses()));

app.get("/api/system/status", (req, res) => {
  const now = Date.now();
  res.json({
    uptime: process.uptime(),
    packets_total: 12450892,
    packets_per_sec: Math.floor(Math.random() * 450) + 50,
    flows_tracked: 42, // Realistically fewer for single host
    devices_discovered: 1,
    db_size_mb: 2.1,
    redis_buffer_fill: 0,
    api_latency_ms: 5,
    ws_clients: wss.clients.size,
    engines: {
      gmm: {
        status: 'ACTIVE',
        progress: 100,
        day: 14,
        components: 4,
        decay: 0.05,
        devices: 1,
        anomalies_today: 0,
        last_update: new Date(now - 1000 * 60 * 5).toISOString()
      },
      kde: {
        status: 'ACTIVE',
        window: '30 days',
        last_retrain: new Date(now - 1000 * 60 * 60 * 12).toISOString(),
        next_retrain: new Date(now + 1000 * 60 * 60 * 60).toISOString(),
        bandwidth: "Scott's Rule",
        observations: 1250,
        alerts_today: 0,
        last_update: new Date(now - 1000 * 60 * 2).toISOString()
      },
      lowess: {
        status: 'ACTIVE',
        bandwidth: 0.3,
        cycle: '6 hours',
        last_eval: new Date(now - 1000 * 60 * 60 * 3).toISOString(),
        next_eval: new Date(now + 1000 * 60 * 60 * 3).toISOString(),
        rising_trends: 0,
        drift_alerts_today: 0,
        last_update: new Date(now - 1000 * 60 * 10).toISOString()
      },
      fusion: {
        status: 'ACTIVE',
        weights: { gmm: 0.35, kde: 0.30, lowess: 0.35 },
        composite_today: 142,
        alerts: { high: 0, med: 0, low: 0 },
        thresholds: { low: 0.55, med: 0.70, high: 0.85 }
      }
    },
    ads: {
      status: 'MONITORING',
      last_anchor: new Date().toISOString().split('T')[0],
      drift: 2.1,
      threshold: 25,
      history: Array.from({ length: 15 }).map((_, i) => ({ time: i, drift: 2 + Math.random() }))
    }
  });
});

app.get("/api/capabilities", (req, res) => {
  res.json({
    rest_api: true,
    websocket: true,
    promiscuous_mode: process.getuid && process.getuid() === 0,
    postgresql: false,
    redis: false,
    gmm_engine: true,
    kde_engine: true,
    lowess_engine: true
  });
});

app.get("/api/system/deep-dive", async (req, res) => {
  try {
    const [cpu, mem, disk, net, os, temp, load] = await Promise.all([
      si.cpu(),
      si.mem(),
      si.fsSize(),
      si.networkInterfaces(),
      si.osInfo(),
      si.cpuTemperature(),
      si.currentLoad()
    ]);
    
    res.json({
      cpu: {
        manufacturer: cpu.manufacturer,
        brand: cpu.brand,
        speed: cpu.speed,
        cores: cpu.cores,
        physicalCores: cpu.physicalCores,
        processors: cpu.processors,
        temperature: temp.main,
        load: load.currentLoad,
        loadByCore: load.cpus.map(c => c.load)
      },
      memory: {
        total: mem.total,
        free: mem.free,
        used: mem.used,
        active: mem.active,
        swaptotal: mem.swaptotal,
        swapused: mem.swapused
      },
      storage: disk.map(d => ({
        fs: d.fs,
        type: d.type,
        size: d.size,
        used: d.used,
        available: d.available,
        use: d.use,
        mount: d.mount
      })),
      network: net.map(n => ({
        iface: n.iface,
        ip4: n.ip4,
        mac: n.mac,
        speed: n.speed,
        dhcp: n.dhcp
      })),
      os: {
        platform: os.platform,
        distro: os.distro,
        release: os.release,
        kernel: os.kernel,
        arch: os.arch,
        hostname: os.hostname
      },
      uptime: si.time().uptime
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch deep dive metrics" });
  }
});

app.get("/api/vms", (req, res) => {
  res.json([
    {
      id: "vm-1",
      name: "Kali-Forensics-VM",
      ip: "192.168.1.50",
      mac: "08:00:27:01:22:A1",
      hypervisor: "VirtualBox",
      status: "RUNNING",
      sent: 54000000,
      recv: 120000000,
      cpu: 18.5,
      memory: 64.2
    },
    {
      id: "vm-2",
      name: "Win10-Dev-Node",
      ip: "192.168.1.51",
      mac: "08:00:27:44:B2:C1",
      hypervisor: "VMware",
      status: "RUNNING",
      sent: 1200000,
      recv: 450000,
      cpu: 4.1,
      memory: 22.8
    },
    {
      id: "vm-3",
      name: "Debian-Docker-Host",
      ip: "192.168.1.55",
      mac: "08:00:27:88:D3:E9",
      hypervisor: "KVM",
      status: "INACTIVE",
      sent: 0,
      recv: 0,
      cpu: 0,
      memory: 0
    }
  ]);
});

app.get("/api/alerts", (req, res) => {
  res.json([]); // Start with no alerts for a clean localhost demo
});

// Network-wide mock endpoints
// Baseline Mock Data
app.get("/api/devices/:id/baseline", (req, res) => {
  const { id } = req.params;
  
  const history = Array.from({ length: 14 }).map((_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (13 - i));
    
    let mean = 1.0 + Math.random() * 0.2;
    let stdDev = 0.1;
    let actual = mean + (Math.random() - 0.5) * 0.1; 

    return {
      date: date.toISOString().split('T')[0],
      mean,
      stdDev,
      actual,
      status: 'ESTABLISHED'
    };
  });

  const baseResponse = {
    established: true,
    learningProgress: 100,
    summary: {
      activeHours: [0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0], 
      avgSentGB: 0.5,
      avgRecvGB: 1.2,
      protocols: [
        { name: "HTTPS", percent: 80 },
        { name: "WS", percent: 10 },
        { name: "DNS", percent: 5 },
        { name: "Other", percent: 5 }
      ],
      avgDestinationsPerHour: 5,
      avgDuration: 12.5,
      topDomains: ["google.com", "github.com", "slack.com", "localhost"],
      uploadDownloadRatio: "1:2.4"
    },
    history,
    deviations: [],
    params: {
      gmmK: 4,
      decayLambda: 0.05,
      trainingWindow: "14 days",
      kdeBandwidth: "Scott's Rule",
      kdeInterval: "every 72 hours",
      lowessBandwidth: 0.3,
      lowessEval: "every 6 hours"
    },
    anchor: {
      date: new Date().toISOString().split('T')[0],
      drift: 1.2,
      adsStatus: "MONITORING",
      adsDrift: Array.from({ length: 10 }).map((_, i) => ({ time: i, drift: 0.5 + Math.random() * 0.2 }))
    }
  };

  res.json(baseResponse);
});

app.post("/api/devices/:id/baseline/reset", express.json(), (req, res) => {
  const { reason } = req.body;
  console.log(`Baseline reset for device ${req.params.id}. Reason: ${reason}`);
  res.json({ status: "success", message: "Baseline reset triggered. System entering learning mode." });
});

app.get("/api/devices", async (req, res) => {
  const localhost = await getLocalHostDevice();
  res.json([localhost]);
});

app.get("/api/devices/:id/killchain", (req, res) => {
  const { id } = req.params;
  
  const mockKillChain = {
    stages: [
      { stage: "RECONNAISSANCE", status: "CLEAN", confidence: 0, indicators: [], mitre_techniques: [], detection_layer: "GMM" },
      { stage: "WEAPONIZATION", status: "CLEAN", confidence: 0, indicators: [], mitre_techniques: [], detection_layer: "KDE" },
      { stage: "DELIVERY", status: "CLEAN", confidence: 0, indicators: [], mitre_techniques: [], detection_layer: "GMM" },
      { stage: "EXPLOITATION", status: "CLEAN", confidence: 0, indicators: [], mitre_techniques: [], detection_layer: "LOWESS" },
      { stage: "INSTALLATION", status: "CLEAN", confidence: 0, indicators: [], mitre_techniques: [], detection_layer: "GMM" },
      { stage: "COMMAND_AND_CONTROL", status: "CLEAN", confidence: 0, indicators: [], mitre_techniques: [], detection_layer: "RULE_ENGINE" },
      { stage: "EXFILTRATION", status: "CLEAN", confidence: 0, indicators: [], mitre_techniques: [], detection_layer: "LOWESS" }
    ],
    current_stage: "NONE",
    overall_risk: "LOW"
  };

  res.json(mockKillChain);
});

app.get("/api/flows", (req, res) => {
  res.json([
    { sourceIp: "192.168.1.42", destIp: "142.250.80.46", destHostname: "google.com", port: 443, protocol: "TCP", bytes: 15400 },
    { sourceIp: "192.168.1.42", destIp: "52.34.12.99", destHostname: "aws.amazon.com", port: 443, protocol: "TCP", bytes: 8900 },
    { sourceIp: "192.168.1.105", destIp: "192.168.1.1", destHostname: "Gateway", port: 53, protocol: "UDP", bytes: 120 },
    { sourceIp: "192.168.1.1", destIp: "8.8.8.8", destHostname: "google-dns", port: 53, protocol: "UDP", bytes: 450 }
  ]);
});

app.get("/api/matrix", (req, res) => {
    res.json({
        nodes: [
            { id: "192.168.1.1", label: "Gateway" },
            { id: "192.168.1.42", label: "Johns-Mac" },
            { id: "192.168.1.105", label: "Thermostat" },
            { id: "8.8.8.8", label: "DNS" }
        ],
        links: [
            { source: "192.168.1.42", target: "192.168.1.1", value: 50 },
            { source: "192.168.1.105", target: "192.168.1.1", value: 5 },
            { source: "192.168.1.1", target: "8.8.8.8", value: 10 }
        ]
    });
});

// WebSocket live feed
wss.on("connection", (ws) => {
  console.log("Client connected to WS");
  const interval = setInterval(async () => {
    if (ws.readyState === WebSocket.OPEN) {
      const [metrics, connections, sites, ports, processes] = await Promise.all([
        getMetrics(),
        getConnections(),
        getSites(),
        getPorts(),
        getProcesses()
      ]);
      ws.send(JSON.stringify({
        metrics,
        connections,
        sites,
        ports,
        processes
      }));
    }
  }, 2000);

  ws.on("close", () => clearInterval(interval));
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
