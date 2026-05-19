import React, { useState, useEffect, useRef, useMemo } from "react";
import { 
  Activity, 
  Cpu, 
  Database, 
  Globe, 
  Hash, 
  Network, 
  Server, 
  Zap, 
  ArrowUp, 
  ArrowDown, 
  Clock, 
  Monitor,
  CheckCircle2,
  AlertCircle,
  Shield,
  ShieldCheck,
  Eye,
  EyeOff,
  Terminal,
  Search,
  Filter,
  Info,
  AlertTriangle,
  ShieldAlert,
  History,
  User,
  RotateCcw,
  Download,
  ExternalLink,
  Plus,
  Lock,
  Flag,
  Gauge,
  MoreHorizontal,
  Trash2,
  Calendar,
  Layers,
  Target,
  ArrowRight,
  Crosshair,
  Mail,
  Bug,
  HardDrive,
  Radio,
  FileUp,
  XCircle,
  SkipForward,
  FileText,
  Printer,
  Copy,
  FileJson,
  Check,
  Briefcase,
  ArrowLeft,
  ChevronDown,
  X,
  Link,
  ArrowUpRight
} from "lucide-react";
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  AreaChart, 
  Area,
  BarChart,
  Bar,
  Cell
} from "recharts";
import { motion, AnimatePresence } from "motion/react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { CONFIG } from "./config";
import { DataLayer } from "./data/dataLayer";

// --- Utils ---
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

function formatBytes(bytes: number, decimals = 2) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatMBps(bytesPerSec: number) {
  return (bytesPerSec / (1024 * 1024)).toFixed(2);
}

// --- Types ---
interface Metrics {
  cpu: number;
  ram: number;
  ram_total: number;
  ram_used: number;
  bytes_sent: number;
  bytes_recv: number;
  bytes_sent_per_sec: number;
  bytes_recv_per_sec: number;
  timestamp: number;
  hostname?: string;
  username?: string;
}

interface Connection {
  pid: number;
  process: string;
  local_port: number;
  remote_ip: string;
  remote_port: number;
  status: string;
  access_denied: boolean;
}

interface Site {
  hostname: string;
  remote_ip: string;
  remote_port: number;
  local_port: number;
  process: string;
  pid: number;
}

interface Port {
  port: number;
  protocol: string;
  process: string;
  pid: number;
}

interface Process {
  pid: number;
  name: string;
  cpu: number;
  memory: number;
  status: string;
}

interface Device {
  id: string;
  hostname: string;
  ip: string;
  mac: string;
  lastSeen: number;
  firstSeen: number;
  sent: number;
  recv: number;
  protocols: string[];
  status: 'active' | 'amber' | 'inactive';
  alertCount: number;
  activity: number[];
  // Extended fields for Live Mode
  vendor?: string;
  device_type?: 'vm' | 'android' | 'ios' | 'mac' | 'linux-vm' | 'windows' | 'router' | 'unknown';
  os?: string;
  is_vm?: boolean;
  hypervisor?: string;
  threat_score?: number;
  beacon_score?: number;
  drift_score?: number;
  recon_score?: number;
  exfil_score?: number;
}

interface Flow {
  sourceIp: string;
  destIp: string;
  destHostname: string;
  port: number;
  protocol: string;
  bytes: number;
}

interface Matrix {
  nodes: { id: string; label: string }[];
  links: { source: string; target: string; value: number }[];
}

interface VM {
  id: string;
  name: string;
  ip: string;
  mac: string;
  hypervisor: string;
  status: 'RUNNING' | 'INACTIVE';
  sent: number;
  recv: number;
  cpu?: number;
  memory?: number;
}

interface DeepDive {
  cpu: {
    manufacturer: string;
    brand: string;
    speed: number;
    cores: number;
    physicalCores: number;
    processors: number;
    temperature: number | null;
    load: number;
    loadByCore: number[];
  };
  memory: {
    total: number;
    free: number;
    used: number;
    active: number;
    swaptotal: number;
    swapused: number;
  };
  storage: {
    fs: string;
    type: string;
    size: number;
    used: number;
    available: number;
    use: number;
    mount: string;
  }[];
  network: {
    iface: string;
    ip4: string;
    mac: string;
    speed: number;
    dhcp: boolean;
  }[];
  os: {
    platform: string;
    distro: string;
    release: string;
    kernel: string;
    arch: string;
    hostname: string;
  };
  uptime: number;
}

interface Alert {
  id: string;
  type: 'PORT_SCAN' | 'EXFILTRATION_INDICATOR' | 'NEW_DEVICE' | 'DRIFT_DETECTED' | 'UNUSUAL_PROTOCOL' | 'BEACONING' | 'DNS_BEACONING' | 'HIGH_UPLOAD' | 'SEQUENTIAL_PORTS' | 'REGULAR_INTERVAL';
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  source: { name: string; ip: string };
  target: { name: string; ip: string };
  timestamp: string;
  description: string;
  isRead: boolean;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  mitre_tactic?: string;
  mitre_description?: string;
}

type ActionType = 'BLOCK_IP' | 'BLOCK_DOMAIN' | 'WATCH_DEVICE' | 'ISOLATE' | 'RATE_LIMIT' | 'FLAG_FOR_REVIEW';
type ActionStatus = 'PENDING' | 'ACTIVE' | 'EXPIRED' | 'REVOKED';

interface SecurityAction {
  id: string;
  type: ActionType;
  target: string;
  triggeredBy: string;
  triggeredAt: number;
  confirmedBy?: string;
  confirmedAt?: number;
  reason: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  duration?: string;
  expiresAt?: number;
  status: ActionStatus;
  alerts?: string[];
  extendedCount?: number;
}

interface ActionRule {
  id: string;
  name: string;
  condition: string;
  action: ActionType;
  mode: 'AUTO_CONFIRM' | 'PENDING';
  enabled: boolean;
  lastTriggered?: number;
  triggerCount: number;
}

interface UndoToast {
  id: string;
  actionId: string;
  message: string;
  timeLeft: number;
}

enum CaseStatus {
  OPEN = 'OPEN',
  IN_PROGRESS = 'IN_PROGRESS',
  ESCALATED = 'ESCALATED',
  CLOSED = 'CLOSED'
}

enum CaseSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

enum Resolution {
  TRUE_POSITIVE = 'TRUE_POSITIVE',
  FALSE_POSITIVE = 'FALSE_POSITIVE',
  INCONCLUSIVE = 'INCONCLUSIVE'
}

interface CaseNote {
  id: string;
  analyst: string;
  timestamp: string;
  content: string;
  tag?: 'OBSERVATION' | 'HYPOTHESIS' | 'EVIDENCE' | 'RECOMMENDATION';
}

interface InvestigationCase {
  id: string; // DW-2026-001
  title: string;
  description: string;
  status: CaseStatus;
  severity: CaseSeverity;
  assignedTo: string;
  deviceIds: string[];
  alertIds: string[];
  createdAt: string;
  updatedAt: string;
  summary: string;
  notes: CaseNote[];
  resolution?: Resolution;
  closingNotes?: string;
}

interface Capabilities {
  rest_api: boolean;
  websocket: boolean;
  promiscuous_mode: boolean;
  postgresql: boolean;
  redis: boolean;
  gmm_engine: boolean;
  kde_engine: boolean;
  lowess_engine: boolean;
}

interface FalsePositiveAlert {
  id: string;
  originalAlert: string;
  markedBy: string;
  reason: string;
  timestamp: string;
  layer: 'GMM' | 'KDE' | 'LOWESS' | 'FUSION' | 'RULE_ENGINE';
}

interface SystemStatus {
  uptime: number;
  packets_total: number;
  packets_per_sec: number;
  flows_tracked: number;
  devices_discovered: number;
  db_size_mb: number;
  redis_buffer_fill: number;
  api_latency_ms: number;
  ws_clients: number;
  engines: {
    gmm: {
      status: 'LEARNING' | 'ACTIVE' | 'DEGRADED';
      progress: number;
      day: number;
      components: number;
      decay: number;
      devices: number;
      anomalies_today: number;
      last_update: string;
    };
    kde: {
      status: 'LEARNING' | 'ACTIVE' | 'DEGRADED';
      window: string;
      last_retrain: string;
      next_retrain: string;
      bandwidth: string;
      observations: number;
      alerts_today: number;
      last_update: string;
    };
    lowess: {
      status: 'ACTIVE' | 'INSUFFICIENT_DATA' | 'DEGRADED';
      bandwidth: number;
      cycle: string;
      last_eval: string;
      next_eval: string;
      rising_trends: number;
      drift_alerts_today: number;
      last_update: string;
    };
    fusion: {
      status: 'ACTIVE' | 'DEGRADED';
      weights: { gmm: number; kde: number; lowess: number };
      composite_today: number;
      alerts: { high: number; med: number; low: number };
      thresholds: { low: number; med: number; high: number };
    };
  };
  ads: {
    status: 'MONITORING' | 'ALERT' | 'OFFLINE';
    last_anchor: string;
    drift: number;
    threshold: number;
    history: { time: number; drift: number }[];
  };
}

type KillChainStageStatus = 'CLEARED' | 'SUSPECTED' | 'CONFIRMED' | 'CLEAN';
type KillChainStageName = 'RECONNAISSANCE' | 'WEAPONIZATION' | 'DELIVERY' | 'EXPLOITATION' | 'INSTALLATION' | 'COMMAND_AND_CONTROL' | 'EXFILTRATION';

interface KillChainStage {
  stage: KillChainStageName;
  status: KillChainStageStatus;
  confidence: number;
  first_detected?: string;
  indicators: string[];
  mitre_techniques: string[];
  detection_layer: string;
}

interface KillChainData {
  stages: KillChainStage[];
  current_stage: KillChainStageName | 'NONE';
  overall_risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

interface BaselineData {
  established: boolean;
  learningProgress: number;
  summary: {
    activeHours: number[];
    avgSentGB: number;
    avgRecvGB: number;
    protocols: { name: string; percent: number }[];
    avgDestinationsPerHour: number;
    avgDuration: number;
    topDomains: string[];
    uploadDownloadRatio: string;
  };
  history: {
    date: string;
    mean: number | null;
    stdDev: number | null;
    actual: number;
    status: 'ESTABLISHED' | 'LEARNING' | 'NO_BASELINE';
  }[];
  deviations: {
    date: string;
    duration: string;
    farOutside: string;
    direction: 'HIGHER' | 'LOWER';
    investigated: 'YES' | 'NO' | 'PENDING';
  }[];
  params: {
    gmmK: number;
    decayLambda: number;
    trainingWindow: string;
    kdeBandwidth: string;
    kdeInterval: string;
    lowessBandwidth: number;
    lowessEval: string;
  };
  anchor: {
    date: string;
    drift: number;
    adsStatus: 'MONITORING' | 'ALERTING';
    adsDrift: { time: number; drift: number }[];
  };
}

interface ReportHistoryEntry {
  id: string;
  date: string;
  type: string;
  analyst: string;
  devices: number;
  actions: number;
  config: any;
}

interface GeneratedReport {
  id: string;
  title: string;
  timestamp: string;
  analyst: string;
  org: string;
  period: string;
  classification: string;
  summary: {
    text: string;
    metrics: { label: string; value: string }[];
  };
  deviceRisk: {
    device: string;
    ip: string;
    score: number;
    highestAlert: string;
    status: string;
    recommendation: string;
  }[];
  activeThreats: Alert[];
  killChains: { deviceId: string; hostname: string; data: KillChainData }[];
  baselines: { deviceId: string; hostname: string; data: BaselineData }[];
  beacons: { device: string; dest: string; interval: string; confidence: number }[];
  auditTrail: SecurityAction[];
  recommendations: string[];
}

interface DashboardData {
  metrics: Metrics;
  connections: Connection[];
  sites: Site[];
  ports: Port[];
  processes: Process[];
}

// --- Components ---

const Card = ({ children, title, icon: Icon, className }: { children: React.ReactNode; title?: string; icon?: any; className?: string }) => (
  <div className={cn("bg-card border border-border rounded-lg flex flex-col overflow-hidden min-h-fit", className)}>
    {title && (
      <div className="px-5 py-4 bg-white/2 border-b border-border flex items-center justify-between mb-0">
        <div className="flex items-center gap-2">
          {Icon && <Icon size={16} className="text-blue-400" />}
          <h3 className="text-[11px] font-bold text-text-dim uppercase tracking-[0.1em] opacity-60">{title}</h3>
        </div>
      </div>
    )}
    <div className="flex-grow p-5 relative">{children}</div>
  </div>
);

const MITRE_FRAMEWORK = [
  { tactic: "Reconnaissance", techniques: [
    { id: "T1595", name: "Active Scanning", desc: "Adversaries may execute active reconnaissance scanning to gather information about victim networks." },
    { id: "T1592", name: "Gather Victim Host Information", desc: "Adversaries may gather information about the victim host." }
  ]},
  { tactic: "Resource Development", techniques: [
    { id: "T1583", name: "Acquire Infrastructure", desc: "Adversaries may acquire infrastructure to support their operations." },
    { id: "T1588", name: "Obtain Capabilities", desc: "Adversaries may obtain capabilities to support their operations." }
  ]},
  { tactic: "Initial Access", techniques: [
    { id: "T1200", name: "Hardware Additions", desc: "Adversaries may introduce computer accessories or networking hardware into a system to gain access." },
    { id: "T1190", name: "Exploit Public-Facing Application", desc: "Adversaries may attempt to exploit a weakness in an Internet-facing host." }
  ]},
  { tactic: "Execution", techniques: [
    { id: "T1059", name: "Command and Scripting Interpreter", desc: "Adversaries may abuse command and script interpreters to execute commands." },
    { id: "T1204", name: "User Execution", desc: "Adversaries may rely on a user to perform an action to execute malicious code." }
  ]},
  { tactic: "Persistence", techniques: [
    { id: "T1053", name: "Scheduled Task/Job", desc: "Adversaries may abuse scheduling functionality to facilitate initial or recurring execution of malicious code." },
    { id: "T1547", name: "Boot or Logon Autostart Execution", desc: "Adversaries may configure system settings to automatically execute a program during system boot." }
  ]},
  { tactic: "Privilege Escalation", techniques: [
    { id: "T1055", name: "Process Injection", desc: "Adversaries may inject code into processes in order to evade process-based defenses." },
    { id: "T1068", name: "Exploitation for Privilege Escalation", desc: "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges." }
  ]},
  { tactic: "Defense Evasion", techniques: [
    { id: "T1070", name: "Indicator Removal", desc: "Adversaries may delete or modify artifacts generated during an intrusion to minimize their footprint." },
    { id: "T1027", name: "Obfuscated Files or Information", desc: "Adversaries may attempt to make an executable or file difficult to discover or analyze." }
  ]},
  { tactic: "Credential Access", techniques: [
    { id: "T1110.001", name: "Brute Force", desc: "Adversaries may use brute force techniques to gain access to accounts." },
    { id: "T1555", name: "Credentials from Password Stores", desc: "Adversaries may search for and retrieve passwords from common storage locations." }
  ]},
  { tactic: "Discovery", techniques: [
    { id: "T1046", name: "Network Service Discovery", desc: "Adversaries may attempt to get a listing of services running on remote hosts." },
    { id: "T1016", name: "System Network Configuration Discovery", desc: "Adversaries may look for details about the network configuration." }
  ]},
  { tactic: "Lateral Movement", techniques: [
    { id: "T1021", name: "Remote Services", desc: "Adversaries may use valid accounts to log into a service that accepts remote connections." },
    { id: "T1550", name: "Use Alternate Authentication Material", desc: "Adversaries may use alternate authentication material to move laterally within an environment." }
  ]},
  { tactic: "Collection", techniques: [
    { id: "T1005", name: "Data from Local System", desc: "Adversaries may search local system sources to find and gather data." },
    { id: "T1074", name: "Data Staged", desc: "Adversaries may stage collected data in a central location prior to exfiltration." }
  ]},
  { tactic: "C2", techniques: [
    { id: "T1071", name: "Application Layer Protocol", desc: "Adversaries may communicate using application layer protocols to avoid detection/filtering." },
    { id: "T1071.001", name: "Web Protocols", desc: "Adversaries may communicate using web protocols (HTTP/S) to avoid detection." },
    { id: "T1071.004", name: "DNS", desc: "Adversaries may communicate using DNS to avoid detection." },
    { id: "T1095", name: "Non-Application Layer Protocol", desc: "Adversaries may use a non-application layer protocol for C2." }
  ]},
  { tactic: "Exfiltration", techniques: [
    { id: "T1048", name: "Exfiltration Over Alternative Protocol", desc: "Adversaries may steal data by exfiltrating it over a different protocol than the main C2." },
    { id: "T1030", name: "Data Transfer Size Limits", desc: "Adversaries may exfiltrate data in fixed size chunks to avoid detection." },
    { id: "T1029", name: "Scheduled Transfer", desc: "Adversaries may exfiltrate data at specific times or intervals to hide activity." }
  ]},
  { tactic: "Impact", techniques: [
    { id: "T1485", name: "Data Destruction", desc: "Adversaries may render stored data on systems unusable by deleting files." },
    { id: "T1486", name: "Data Encrypted for Impact", desc: "Adversaries may encrypt data on target systems to interrupt availability." }
  ]}
];

const MITRE_TACTICS = MITRE_FRAMEWORK.map(f => f.tactic);

const ReportDocument = ({ report, onExport }: { report: GeneratedReport; onExport: (format: string) => void }) => {
  return (
    <div className="bg-white text-gray-900 min-h-screen p-8 md:p-12 shadow-2xl overflow-y-auto custom-scrollbar-light font-sans max-w-5xl mx-auto rounded-lg report-page">
      <header className="border-b-4 border-blue-900 pb-6 mb-8 flex justify-between items-start">
        <div>
          <h1 className="text-3xl font-black text-blue-900 tracking-tighter uppercase mb-2">DRIFTWATCH NDR Analysis Report</h1>
          <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-xs text-gray-600 font-medium">
             <div><span className="font-bold text-gray-900 uppercase">Analyst:</span> {report.analyst}</div>
             <div><span className="font-bold text-gray-900 uppercase">Generated:</span> {report.timestamp}</div>
             <div><span className="font-bold text-gray-900 uppercase">Organisation:</span> {report.org}</div>
             <div><span className="font-bold text-gray-900 uppercase">Period:</span> {report.period}</div>
          </div>
        </div>
        <div className="bg-red-600 text-white px-3 py-1 rounded text-[10px] font-black uppercase tracking-widest leading-none">
          {report.classification}
        </div>
      </header>

      {/* SECTION 1 - EXECUTIVE SUMMARY */}
      <section className="mb-10">
        <h2 className="text-xl font-bold text-blue-900 border-b border-gray-200 pb-2 mb-4 uppercase tracking-tight flex items-center gap-2">
          <div className="w-1.5 h-6 bg-blue-900" />
          Section 1: Executive Summary
        </h2>
        <div className="space-y-4">
           <p className="text-sm leading-relaxed text-gray-700 font-medium italic">
             {report.summary.text}
           </p>
           <div className="grid grid-cols-5 gap-4">
              {report.summary.metrics.map(m => (
                 <div key={m.label} className="bg-gray-50 p-4 border border-gray-100 rounded-lg text-center">
                    <div className="text-[10px] text-gray-400 font-bold uppercase mb-1">{m.label}</div>
                    <div className="text-lg font-black text-blue-900">{m.value}</div>
                 </div>
              ))}
           </div>
        </div>
      </section>

      {/* SECTION 2 - DEVICE RISK SUMMARY */}
      <section className="mb-10">
        <h2 className="text-xl font-bold text-blue-900 border-b border-gray-200 pb-2 mb-4 uppercase tracking-tight flex items-center gap-2">
          <div className="w-1.5 h-6 bg-blue-900" />
          Section 2: Device Risk Summary
        </h2>
        <div className="border border-gray-200 rounded overflow-hidden">
           <table className="w-full text-left text-xs">
              <thead className="bg-gray-50 border-b border-gray-200 font-bold uppercase text-gray-500">
                 <tr>
                    <th className="px-4 py-3">Device</th>
                    <th className="px-4 py-3">IP Address</th>
                    <th className="px-4 py-3 text-center">Risk Score</th>
                    <th className="px-4 py-3">Highest Alert</th>
                    <th className="px-4 py-3">Status</th>
                 </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                 {report.deviceRisk.map(dev => (
                    <tr key={dev.device} className={cn(
                      dev.score > 75 ? "bg-red-50" : dev.score > 40 ? "bg-amber-50" : "hover:bg-gray-25"
                    )}>
                       <td className="px-4 py-4 font-bold text-gray-900">{dev.device}</td>
                       <td className="px-4 py-4 font-mono text-gray-500">{dev.ip}</td>
                       <td className="px-4 py-4 text-center">
                          <span className={cn(
                            "inline-block w-8 py-1 rounded font-black text-white",
                            dev.score > 75 ? "bg-red-600" : dev.score > 40 ? "bg-amber-500" : "bg-green-600"
                          )}>
                            {dev.score}
                          </span>
                       </td>
                       <td className="px-4 py-4 font-medium italic text-gray-700">{dev.highestAlert}</td>
                       <td className="px-4 py-4">
                          <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border border-current opacity-70">
                            {dev.status}
                          </span>
                       </td>
                    </tr>
                 ))}
              </tbody>
           </table>
        </div>
      </section>

      {/* SECTION 3 - ACTIVE THREATS */}
      <section className="mb-10">
        <h2 className="text-xl font-bold text-blue-900 border-b border-gray-200 pb-2 mb-4 uppercase tracking-tight flex items-center gap-2">
          <div className="w-1.5 h-6 bg-blue-900" />
          Section 3: Active Threat Investigation
        </h2>
        <div className="space-y-6">
           {report.activeThreats.map((threat, idx) => (
              <div key={`${threat.id}-${idx}`} className="border-l-4 border-blue-900 pl-6 py-2">
                 <div className="flex justify-between items-center mb-2">
                    <h3 className="font-black text-gray-900 uppercase tracking-tight text-sm">
                       {threat.type} — Source: {threat.source.name} ({threat.source.ip})
                    </h3>
                    <span className="text-[10px] font-mono text-gray-400">{threat.timestamp}</span>
                 </div>
                 <p className="text-xs text-gray-600 leading-relaxed mb-3">{threat.description}</p>
                 <div className="flex gap-4">
                    <div className="bg-gray-50 px-3 py-1.5 rounded flex flex-col">
                       <span className="text-[8px] text-gray-400 uppercase font-black">MITRE Technique</span>
                       <span className="text-[10px] font-mono font-bold text-blue-800">{threat.mitre_technique_id}: {threat.mitre_technique_name}</span>
                    </div>
                    <div className="bg-gray-50 px-3 py-1.5 rounded flex flex-col">
                       <span className="text-[8px] text-gray-400 uppercase font-black">Detection Confidence</span>
                       <span className="text-[10px] font-bold text-gray-700">92% (Correlation Matrix)</span>
                    </div>
                 </div>
              </div>
           ))}
        </div>
      </section>

      {/* SECTION 4 - KILL CHAIN ANALYSIS */}
      <section className="mb-10">
        <h2 className="text-xl font-bold text-blue-900 border-b border-gray-200 pb-2 mb-4 uppercase tracking-tight flex items-center gap-2">
          <div className="w-1.5 h-6 bg-blue-900" />
          Section 4: Attack Path Progression
        </h2>
        <div className="space-y-12 mt-8">
           {report.killChains.map((kc, idx) => (
             <div key={`${kc.deviceId}-${idx}`} className="space-y-6">
                <div className="text-sm font-bold text-gray-900 italic mb-4">Host: {kc.hostname} — Kill Chain State</div>
                <div className="flex justify-between relative">
                   <div className="absolute top-4 left-0 right-0 h-1 bg-gray-100 z-0" />
                   {kc.data.stages.map((s, i) => {
                     const isActive = kc.data.current_stage === s.stage;
                     const isPast = activeStagesCount(kc.data) > i;
                     return (
                        <div key={`kc-stage-${s.stage}-${i}`} className="flex flex-col items-center gap-2 relative z-10 w-1/7">
                           <div className={cn(
                             "w-8 h-8 rounded-full border-2 flex items-center justify-center transition-all",
                             s.status === 'CONFIRMED' ? "bg-red-600 border-red-700 text-white" : 
                             s.status === 'SUSPECTED' ? "bg-amber-500 border-amber-600 text-white" : 
                             "bg-white border-gray-200 text-gray-300"
                           )}>
                              {s.status === 'CONFIRMED' || s.status === 'SUSPECTED' ? <AlertCircle size={14} /> : <div className="w-1.5 h-1.5 rounded-full bg-current" />}
                           </div>
                           <div className="text-[8px] font-black text-center uppercase tracking-tighter leading-none w-16">
                              {s.stage.replace('_', ' ')}
                           </div>
                        </div>
                     );
                   })}
                </div>
                <p className="text-xs text-gray-600 bg-gray-50 p-4 rounded italic border border-gray-100">
                   Adversary has reached the <span className="font-bold text-blue-900 inline-block px-1 bg-blue-50">{kc.data.current_stage.replace('_', ' ')}</span> stage on this host. Indicators suggest persistent beaconing and localized lateral discovery.
                </p>
             </div>
           ))}
        </div>
      </section>

      {/* SECTION 7 - ACTIONS AUDIT TRAIL */}
      <section className="mb-10">
        <h2 className="text-xl font-bold text-blue-900 border-b border-gray-200 pb-2 mb-4 uppercase tracking-tight flex items-center gap-2">
          <div className="w-1.5 h-6 bg-blue-900" />
          Section 7: Defensive Actions Audit Trail
        </h2>
        <div className="border border-gray-200 rounded overflow-hidden">
           <table className="w-full text-left text-xs font-mono">
              <thead className="bg-gray-50 border-b border-gray-200 font-bold uppercase text-gray-500">
                 <tr>
                    <th className="px-4 py-3">Timestamp</th>
                    <th className="px-4 py-3">Action</th>
                    <th className="px-4 py-3">Target</th>
                    <th className="px-4 py-3">Executed By</th>
                    <th className="px-4 py-3">Outcome</th>
                 </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 italic">
                 {report.auditTrail.map(action => (
                    <tr key={action.id}>
                       <td className="px-4 py-3 text-gray-400">{new Date(action.triggeredAt).toISOString().split('T')[0]}</td>
                       <td className="px-4 py-3 font-bold text-blue-900">{action.type}</td>
                       <td className="px-4 py-3 text-gray-600">{action.target}</td>
                       <td className="px-4 py-3 text-gray-500">{action.confirmedBy || action.triggeredBy}</td>
                       <td className="px-4 py-3 font-medium text-green-600">ENFORCED</td>
                    </tr>
                 ))}
              </tbody>
           </table>
        </div>
      </section>

      {/* SECTION 8 - RECOMMENDATIONS */}
      <section className="mb-12">
        <h2 className="text-xl font-bold text-blue-900 border-b border-gray-200 pb-2 mb-4 uppercase tracking-tight flex items-center gap-2">
          <div className="w-1.5 h-6 bg-blue-900" />
          Section 8: Analyst Recommendations
        </h2>
        <ul className="space-y-4">
           {report.recommendations.map((rec, i) => (
              <li key={i} className="flex gap-4 items-start">
                 <div className="bg-blue-900 text-white w-6 h-6 flex items-center justify-center rounded-full flex-shrink-0 text-xs font-bold">{i+1}</div>
                 <p className="text-sm text-gray-800 font-medium leading-relaxed">{rec}</p>
              </li>
           ))}
        </ul>
      </section>

      <footer className="mt-20 pt-8 border-t border-gray-200 flex justify-between items-end">
         <div className="space-y-1">
            <div className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Digital Signature</div>
            <div className="font-mono text-xs text-gray-600 border-b border-gray-900 pb-1 w-48 italic">/signed/ {report.analyst}</div>
         </div>
         <div className="text-right">
            <div className="text-[8px] text-gray-400 font-bold uppercase mb-1">DRIFTWATCH NDR v2.4.1 Final Report</div>
            <div className="text-[10px] font-mono text-gray-300">Generated on secure node DW-01 (64.223.1.5)</div>
         </div>
      </footer>
    </div>
  );
};

// Helper for kill chain calculation
const activeStagesCount = (kc: KillChainData) => {
  const STAGES: KillChainStageName[] = ['RECONNAISSANCE', 'WEAPONIZATION', 'DELIVERY', 'EXPLOITATION', 'INSTALLATION', 'COMMAND_AND_CONTROL', 'EXFILTRATION'];
  if (kc.current_stage === 'NONE') return 0;
  return STAGES.indexOf(kc.current_stage) + 1;
};

const BaselineViewer = ({ deviceId, onReset }: { deviceId: string; onReset: (reason: string) => void }) => {
  const [data, setData] = useState<BaselineData | null>(null);
  const [metricView, setMetricView] = useState<'SENT' | 'RECEIVED'>('SENT');
  const [showParams, setShowParams] = useState(false);
  const [showResetModal, setShowResetModal] = useState(false);
  const [resetReason, setResetReason] = useState("");

  useEffect(() => {
    fetch(`/api/devices/${deviceId}/baseline`)
      .then(res => res.json())
      .then(setData);
  }, [deviceId]);

  if (!data) return <div className="h-full flex items-center justify-center font-mono text-[10px] text-text-dim animate-pulse">Calculating Bayesian posteriors...</div>;

  if (!data.established && data.learningProgress > 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 text-center space-y-6">
         <div className="relative w-32 h-32">
            <svg className="w-full h-full -rotate-90">
               <circle cx="64" cy="64" r="60" stroke="currentColor" strokeWidth="2" fill="transparent" className="text-white/5" />
               <circle 
                 cx="64" cy="64" r="60" 
                 stroke="currentColor" 
                 strokeWidth="2" 
                 fill="transparent" 
                 strokeDasharray={377}
                 strokeDashoffset={377 - (377 * data.learningProgress / 100)}
                 className="text-blue-500 transition-all duration-1000" 
               />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
               <span className="text-2xl font-black text-white">{data.learningProgress}%</span>
               <span className="text-[8px] text-text-dim uppercase font-bold tracking-tighter">Learning</span>
            </div>
         </div>
         <div className="space-y-2">
            <h3 className="text-sm font-black uppercase text-white">Baseline Construction in Progress</h3>
            <p className="text-[10px] text-text-dim leading-relaxed max-w-xs mx-auto">
               System is currently observing device behavior to establish a 14-day statistical baseline. Full NDR capabilities restricted for this node until convergence.
            </p>
         </div>
      </div>
    );
  }

  if (!data.established) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 text-center space-y-4">
         <AlertTriangle className="text-amber-500 opacity-50" size={32} />
         <div className="space-y-1">
            <h3 className="text-xs font-black uppercase text-white">No Baseline Profile</h3>
            <p className="text-[10px] text-text-dim">Host recently joined segment. Awaiting first observation cycle.</p>
         </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-h-[600px] overflow-y-auto custom-scrollbar pr-2 pb-8">
       {/* Normal Behaviour Summary */}
       <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-white/3 border border-white/5 p-4 rounded-lg space-y-4">
             <div className="flex items-center gap-2 mb-2">
                <ShieldCheck size={14} className="text-green-500" />
                <h4 className="text-[10px] font-black uppercase tracking-widest text-white">Normal Behaviour Profile</h4>
             </div>
             
             <div className="space-y-4">
                <div>
                   <div className="text-[9px] text-text-dim uppercase font-bold mb-2">Typical Active Hours (24h)</div>
                   <div className="flex gap-0.5 h-6">
                      {data.summary.activeHours.map((h, i) => (
                        <div 
                          key={i} 
                          title={`${i}:00`}
                          className={cn(
                            "flex-1 rounded-sm border border-white/5",
                            h > 0 ? "bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.3)]" : "bg-white/5"
                          )} 
                        />
                      ))}
                   </div>
                   <div className="flex justify-between mt-1 text-[8px] font-mono text-text-dim uppercase">
                      <span>00:00</span>
                      <span>12:00</span>
                      <span>23:59</span>
                   </div>
                </div>

                <div className="grid grid-cols-2 gap-3 text-[10px] font-mono">
                   <div className="bg-white/2 p-2 rounded">
                      <div className="text-[8px] text-text-dim uppercase font-bold mb-1">Avg Sent/Day</div>
                      <div className="text-white font-bold">{data.summary.avgSentGB} GB</div>
                   </div>
                   <div className="bg-white/2 p-2 rounded">
                      <div className="text-[8px] text-text-dim uppercase font-bold mb-1">Avg Recv/Day</div>
                      <div className="text-white font-bold">{data.summary.avgRecvGB} GB</div>
                   </div>
                </div>

                <div className="pt-2 border-t border-white/5">
                   <div className="text-[9px] text-text-dim uppercase font-bold mb-2">Protocol Distribution</div>
                   <div className="flex h-2 rounded-full overflow-hidden mb-2">
                      {data.summary.protocols.map((p, i) => (
                         <div 
                           key={p.name} 
                           style={{ width: `${p.percent}%` }}
                           className={cn(i === 0 ? "bg-blue-500" : i === 1 ? "bg-purple-500" : "bg-amber-500", "h-full")}
                         />
                      ))}
                   </div>
                   <div className="flex gap-3 flex-wrap">
                      {data.summary.protocols.map((p, i) => (
                        <div key={p.name} className="flex items-center gap-1 text-[9px] font-mono">
                           <div className={cn("w-1.5 h-1.5 rounded-full", i === 0 ? "bg-blue-500" : i === 1 ? "bg-purple-500" : "bg-amber-500")} />
                           <span className="text-white">{p.name}</span>
                           <span className="text-text-dim">({p.percent}%)</span>
                        </div>
                      ))}
                   </div>
                </div>
             </div>
          </div>

          <div className="bg-white/3 border border-white/5 p-4 rounded-lg flex flex-col justify-between">
             <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                   <div>
                      <div className="text-[9px] text-text-dim uppercase font-bold mb-1">Destinations/Hr</div>
                      <div className="text-lg font-bold text-white font-mono">{data.summary.avgDestinationsPerHour}</div>
                   </div>
                   <div>
                      <div className="text-[9px] text-text-dim uppercase font-bold mb-1">Avg Duration</div>
                      <div className="text-lg font-bold text-white font-mono">{data.summary.avgDuration}s</div>
                   </div>
                </div>

                <div>
                   <div className="text-[9px] text-text-dim uppercase font-bold mb-2">Top Contacted Domains</div>
                   <div className="space-y-1">
                      {data.summary.topDomains.map((d, i) => (
                        <div key={i} className="flex items-center justify-between text-[10px] bg-white/2 p-1.5 px-2 rounded hover:bg-white/5 cursor-default group transition-all">
                           <span className="text-white/80 group-hover:text-blue-400 truncate max-w-[150px]">{d}</span>
                           <ExternalLink size={10} className="text-text-dim opacity-0 group-hover:opacity-100" />
                        </div>
                      ))}
                   </div>
                </div>
             </div>

             <div className="mt-4 pt-4 border-t border-white/5 flex justify-between items-end">
                <div>
                   <div className="text-[9px] text-text-dim uppercase font-bold mb-1">UL:DL Ratio</div>
                   <div className="text-sm font-black text-blue-400 font-mono tracking-tighter">{data.summary.uploadDownloadRatio}</div>
                </div>
                <button 
                  onClick={() => setShowResetModal(true)}
                  className="px-3 py-1.5 bg-red-500/10 hover:bg-red-500 text-red-500 hover:text-white border border-red-500/30 rounded text-[9px] font-black uppercase transition-all tracking-wider"
                >
                  Reset Baseline
                </button>
             </div>
          </div>
       </div>

       {/* Band Chart */}
       <div className="bg-white/3 border border-white/5 p-4 rounded-lg">
          <div className="flex items-center justify-between mb-6">
             <div>
                <h4 className="text-[10px] font-black uppercase tracking-widest text-white">Behavioural Variance Band</h4>
                <p className="text-[9px] text-text-dim font-mono">Comparing daily {metricView.toLowerCase()} payload against mean μ ± σ established ranges</p>
             </div>
             <div className="flex bg-white/5 p-1 rounded border border-white/5">
                {(['SENT', 'RECEIVED'] as const).map(m => (
                   <button 
                    key={m} 
                    onClick={() => setMetricView(m)}
                    className={cn(
                      "px-3 py-1 rounded text-[8px] font-black uppercase transition-all",
                      metricView === m ? "bg-blue-600 text-white" : "text-text-dim hover:text-white"
                    )}
                   >
                     {m}
                   </button>
                ))}
             </div>
          </div>

          <div className="h-[250px] w-full">
             <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.history.map(d => ({
                  ...d,
                  low: d.mean !== null && d.stdDev !== null ? Math.max(0, d.mean - d.stdDev) : 0,
                  high: d.mean !== null && d.stdDev !== null ? d.mean + d.stdDev : 0
                }))}>
                   <defs>
                      <linearGradient id="bandGradient" x1="0" y1="0" x2="0" y2="1">
                         <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                         <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.05} />
                      </linearGradient>
                      <linearGradient id="alertGradient" x1="0" y1="0" x2="0" y2="1">
                         <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                         <stop offset="95%" stopColor="#ef4444" stopOpacity={0.1} />
                      </linearGradient>
                   </defs>
                   <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                   <XAxis 
                     dataKey="date" 
                     stroke="#94a3b860" 
                     fontSize={9} 
                     tickLine={false} 
                     axisLine={false} 
                     tickFormatter={(val) => val.split('-').slice(1).join('/')}
                   />
                   <YAxis stroke="#94a3b860" fontSize={9} tickLine={false} axisLine={false} tickFormatter={(val) => `${val}GB`} />
                   <Tooltip 
                     contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '4px', fontSize: '10px' }}
                     itemStyle={{ color: '#fff', padding: '2px 0' }}
                   />
                   {/* Normal Range Band */}
                   <Area 
                     type="monotone" 
                     dataKey="high" 
                     stroke="none" 
                     fill="url(#bandGradient)" 
                     baseLine={0} 
                   />
                   <Area 
                     type="monotone" 
                     dataKey="low" 
                     stroke="none" 
                     fill="#0f172a" 
                     baseLine={0} 
                   />
                   {/* High Variance Markers would go here if we had more complex SVG layering */}
                   <Line 
                     type="monotone" 
                     dataKey="actual" 
                     stroke="#fff" 
                     strokeWidth={2} 
                     dot={{ r: 2, fill: '#fff' }} 
                     activeDot={{ r: 4, stroke: '#3b82f6', strokeWidth: 2 }}
                   />
                   <Line 
                     type="monotone" 
                     dataKey="mean" 
                     stroke="#3b82f6" 
                     strokeWidth={1} 
                     strokeDasharray="4 4" 
                     dot={false}
                   />
                </AreaChart>
             </ResponsiveContainer>
          </div>
       </div>

       {/* Deviation History */}
       <div className="bg-white/2 border border-white/5 rounded-lg overflow-hidden">
          <table className="w-full text-left font-mono">
             <thead className="bg-white/5 text-[8px] font-black uppercase text-text-dim border-b border-white/5">
                <tr>
                   <th className="px-4 py-2">Date</th>
                   <th className="px-4 py-2">Duration</th>
                   <th className="px-4 py-2">Deviation</th>
                   <th className="px-4 py-2">Direction</th>
                   <th className="px-4 py-2">Investigated</th>
                </tr>
             </thead>
             <tbody className="text-[10px]">
                {data.deviations.map((dev, i) => (
                   <tr key={i} className="border-b border-white/5 hover:bg-white/2 transition-colors">
                      <td className="px-4 py-2 text-white">{dev.date}</td>
                      <td className="px-4 py-2 text-text-dim">{dev.duration}</td>
                      <td className="px-4 py-2">
                        <span className={cn(
                          "font-black",
                          parseFloat(dev.farOutside) > 100 ? "text-red-500" : "text-amber-500"
                        )}>{dev.farOutside}</span>
                      </td>
                      <td className="px-4 py-2 text-text-dim">{dev.direction}</td>
                      <td className="px-4 py-2">
                         <span className={cn(
                           "px-1 rounded uppercase font-black text-[8px]",
                           dev.investigated === 'YES' ? "bg-green-500/20 text-green-400" : dev.investigated === 'PENDING' ? "bg-amber-500/20 text-amber-400" : "bg-red-500/20 text-red-400"
                         )}>{dev.investigated}</span>
                      </td>
                   </tr>
                ))}
                {data.deviations.length === 0 && (
                   <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-text-dim italic text-[9px]">No baseline deviations recorded in history window.</td>
                   </tr>
                )}
             </tbody>
          </table>
       </div>

       {/* Anchor Snapshot & ADS */}
       <div className="bg-white/3 border border-white/5 p-4 rounded-lg space-y-4">
          <div className="flex items-center justify-between">
             <div>
                <h4 className="text-[10px] font-black uppercase tracking-widest text-white">Dissertation ch 3.3.7: Anchor Snapshot</h4>
                <div className="flex items-center gap-4 mt-1">
                   <div className="flex items-center gap-1.5 text-[9px] text-text-dim font-mono">
                      <Calendar size={10} />
                      Baseline anchored on: <span className="text-white">{data?.anchor?.date || 'N/A'}</span>
                   </div>
                   <div className="flex items-center gap-1.5 text-[9px] font-mono">
                      <Zap size={10} className={(data?.anchor?.drift || 0) > 15 ? 'text-red-500' : 'text-green-500'} />
                      Parameter drift from anchor: <span className={cn("font-bold", (data?.anchor?.drift || 0) > 15 ? 'text-red-500' : 'text-green-500')}>{data?.anchor?.drift || 0}%</span>
                   </div>
                </div>
             </div>
             <div className="bg-white/5 px-2 py-1 rounded border border-white/5 flex flex-col items-end">
                <span className="text-[8px] text-text-dim uppercase font-black mb-0.5">ADS Sentinel</span>
                <span className={cn(
                  "text-[9px] font-black uppercase animate-pulse",
                  data?.anchor?.adsStatus === 'ALERTING' ? 'text-red-500' : 'text-green-500'
                )}>{data?.anchor?.adsStatus || 'OFFLINE'}</span>
             </div>
          </div>

          <div className="h-[60px] w-full opacity-60">
             <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data?.anchor?.adsDrift || []}>
                   <Line type="monotone" dataKey="drift" stroke="#3b82f6" strokeWidth={1.5} dot={false} />
                   <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                </LineChart>
             </ResponsiveContainer>
          </div>
          <p className="text-[8px] text-text-dim italic leading-tight uppercase font-bold text-right tracking-tighter">
             Adversarial Drift Sentinel (ADS): Monitoring GMM parameter convergence against historical anchor.
          </p>
       </div>

       {/* Parameters */}
       <div className="border border-white/5 rounded-lg overflow-hidden">
          <button 
            onClick={() => setShowParams(!showParams)}
            className="w-full p-3 bg-white/3 flex items-center justify-between hover:bg-white/5 transition-all"
          >
             <div className="flex items-center gap-2">
                <Database size={12} className="text-blue-400" />
                <span className="text-[10px] font-black uppercase text-text-dim tracking-widest">Algorithm Parameters</span>
             </div>
             <MoreHorizontal size={14} className={cn("text-text-dim transition-transform", showParams ? "rotate-90" : "")} />
          </button>
          
          <AnimatePresence>
             {showParams && (
                <motion.div 
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="bg-white/1 p-4 grid grid-cols-2 md:grid-cols-4 gap-4"
                >
                   {Object.entries(data.params).map(([key, val]) => (
                      <div key={key} className="group relative">
                         <div className="flex items-center gap-1 mb-1">
                            <span className="text-[8px] text-text-dim uppercase font-bold">{key.replace(/[A-Z]/g, letter => ` ${letter.toLowerCase()}`)}</span>
                            <Info size={8} className="text-blue-400/50 cursor-pointer" />
                            {/* Tooltip Content */}
                            <div className="absolute bottom-full left-0 mb-2 p-2 bg-gray-900 border border-border rounded text-[8px] text-text-dim w-48 hidden group-hover:block z-50 shadow-2xl">
                               Detailed algorithmic configuration for {key}. Controls the sensitive boundary of the {key.includes('lowess') ? 'local regression' : 'kernel density'} estimation layer.
                            </div>
                         </div>
                         <div className="text-[10px] font-mono text-white bg-white/5 px-1.5 py-0.5 rounded border border-white/5">{val}</div>
                      </div>
                   ))}
                </motion.div>
             )}
          </AnimatePresence>
       </div>

       {/* Reset Modal */}
       <AnimatePresence>
          {showResetModal && (
            <div className="fixed inset-0 z-[400] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
               <motion.div 
                 initial={{ scale: 0.9, opacity: 0 }}
                 animate={{ scale: 1, opacity: 1 }}
                 className="bg-card border border-border p-6 rounded-lg max-w-sm w-full shadow-2xl space-y-6"
               >
                  <div className="flex flex-col items-center gap-4 text-center">
                     <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center">
                        <RotateCcw className="text-red-500" size={32} />
                     </div>
                     <div className="space-y-1">
                        <h3 className="text-lg font-black uppercase text-white tracking-tight">Confirm Baseline Reset</h3>
                        <p className="text-[10px] text-text-dim leading-relaxed">
                           Resetting the baseline will require 14 days of clean traffic before full detection capability is restored for this device. This cannot be undone.
                        </p>
                     </div>
                  </div>

                  <div className="space-y-2">
                     <label className="text-[10px] text-text-dim uppercase font-bold">Reason for reset (Required)</label>
                     <textarea 
                        value={resetReason}
                        onChange={(e) => setResetReason(e.target.value)}
                        placeholder="e.g. Host reimaged, hardware changed, network role update..."
                        className="w-full bg-white/5 border border-border p-3 rounded text-sm text-white focus:outline-none focus:border-red-500 min-h-[80px]"
                     />
                  </div>

                  <div className="flex gap-3">
                     <button 
                       disabled={resetReason.length < 5}
                       onClick={() => {
                          onReset(resetReason);
                          setShowResetModal(false);
                          setResetReason("");
                       }}
                       className={cn(
                        "flex-grow py-3 rounded text-[10px] font-black uppercase tracking-widest transition-all",
                        resetReason.length >= 5 ? "bg-red-600 hover:bg-red-500 text-white shadow-lg" : "bg-gray-800 text-gray-500 border border-white/5 cursor-not-allowed"
                       )}
                     >
                        Confirm Reset
                     </button>
                     <button 
                       onClick={() => setShowResetModal(false)}
                       className="flex-grow py-3 border border-border hover:bg-white/5 text-text-dim font-black rounded text-[10px] uppercase tracking-widest transition-all"
                     >
                        Cancel
                     </button>
                  </div>
               </motion.div>
            </div>
          )}
       </AnimatePresence>
    </div>
  );
};

const MitreCoverageCard = ({ alerts }: { alerts: Alert[] }) => {
  const observedTechniques = useMemo(() => {
    const techSet = new Set();
    alerts.forEach(a => {
      if (a.mitre_technique_id) techSet.add(a.mitre_technique_id);
    });
    return techSet.size;
  }, [alerts]);

  const observedTactics = useMemo(() => {
    const tacticSet = new Set();
    alerts.forEach(a => {
      if (a.mitre_tactic) tacticSet.add(a.mitre_tactic);
    });
    return tacticSet.size;
  }, [alerts]);

  const totalTechniques = MITRE_FRAMEWORK.reduce((acc, curr) => acc + curr.techniques.length, 0);
  const totalTactics = MITRE_FRAMEWORK.length;
  
  const coveragePercent = (observedTechniques / totalTechniques) * 100;

  return (
    <div className="bg-blue-500/5 border border-blue-500/20 p-5 rounded-lg relative group overflow-hidden min-h-[120px]">
       <div className="absolute top-4 right-5">
          <Shield size={16} className="text-blue-500 opacity-60" />
       </div>
       <div className="text-[11px] text-blue-500 mb-2 uppercase font-bold tracking-[0.1em] opacity-60">MITRE COVERAGE</div>
       <div className="flex flex-col gap-1">
          <div className="flex items-end gap-2">
             <span className="text-[28px] font-bold text-white">{observedTechniques}</span>
             <span className="text-[12px] text-text-dim/50 font-bold uppercase tracking-wider mb-2">techniques</span>
          </div>
          <div className="text-[12px] text-text-dim/50 font-medium mb-1">Observed in {observedTactics} tactics</div>
          <div className="mt-2 h-1 bg-white/5 rounded-full overflow-hidden">
             <div className="h-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]" style={{ width: `${Math.max(coveragePercent, 5)}%` }} />
          </div>
          <div className="mt-3 text-[10px] text-text-dim/40 flex justify-between uppercase font-bold tracking-widest">
             <span>Observed: {observedTechniques}</span>
             <span>Total: {totalTechniques}</span>
          </div>
       </div>
    </div>
  );
};

const MitreMatrixView = ({ alerts, onSelectTechnique }: { alerts: Alert[]; onSelectTechnique: (techId: string, tactic: string) => void }) => {
  return (
    <div className="w-full overflow-x-auto custom-scrollbar pb-4">
      <div className="flex gap-1 min-w-[1200px]">
        {MITRE_FRAMEWORK.map(tacticGroup => (
          <div key={tacticGroup.tactic} className="flex-1 flex flex-col gap-1">
             <div className="bg-white/5 p-2 border border-border text-[9px] font-black uppercase text-center tracking-tighter h-[40px] flex items-center justify-center">
                {tacticGroup.tactic}
             </div>
             <div className="flex flex-col gap-1">
                {tacticGroup.techniques.map(tech => {
                  const techAlerts = alerts.filter(a => a.mitre_technique_id === tech.id);
                  const count = techAlerts.length;
                  
                  let bgColor = "bg-white/3";
                  let borderColor = "border-white/5";
                  let textColor = "text-text-dim";
                  
                  if (count >= 2) {
                    bgColor = "bg-red-500/40";
                    borderColor = "border-red-500/50";
                    textColor = "text-white";
                  } else if (count === 1) {
                    bgColor = "bg-amber-500/40";
                    borderColor = "border-amber-500/50";
                    textColor = "text-white";
                  }

                  return (
                    <div 
                      key={`${tacticGroup.tactic}-${tech.id}`} 
                      onClick={() => onSelectTechnique(tech.id, tacticGroup.tactic)}
                      className={cn(
                        "p-2 text-[9px] font-mono border min-h-[50px] cursor-pointer hover:brightness-125 transition-all flex flex-col justify-between",
                        bgColor,
                        borderColor,
                        textColor
                      )}
                    >
                       <span className="font-bold opacity-60">{tech.id}</span>
                       <span className="leading-tight">{tech.name}</span>
                       {count > 0 && <span className="mt-1 text-[8px] font-black self-end px-1 bg-black/40 rounded">{count}</span>}
                    </div>
                  );
                })}
             </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const ALERT_TYPE_TO_MITRE: Record<string, { mitre_technique_id: string; mitre_technique_name: string; mitre_tactic: string; mitre_description: string }> = {
  PORT_SCAN: { mitre_technique_id: "T1046", mitre_technique_name: "Network Service Discovery", mitre_tactic: "Discovery", mitre_description: "Adversaries may attempt to get a listing of services running on remote hosts." },
  BEACONING: { mitre_technique_id: "T1071.001", mitre_technique_name: "Web Protocols C2", mitre_tactic: "C2", mitre_description: "Adversaries may communicate using web protocols to avoid detection." },
  DNS_BEACONING: { mitre_technique_id: "T1071.004", mitre_technique_name: "DNS C2", mitre_tactic: "C2", mitre_description: "Adversaries may communicate using DNS to avoid detection." },
  EXFIL_INDICATOR: { mitre_technique_id: "T1030", mitre_technique_name: "Data Transfer Size Limits", mitre_tactic: "Exfiltration", mitre_description: "Adversaries may exfiltrate data in fixed size chunks components to avoid detection." },
  NEW_DEVICE: { mitre_technique_id: "T1200", mitre_technique_name: "Hardware Additions", mitre_tactic: "Initial Access", mitre_description: "Adversaries may introduce hardware into a system to gain access." },
  DRIFT_DETECTED: { mitre_technique_id: "T1029", mitre_technique_name: "Scheduled Transfer", mitre_tactic: "Exfiltration", mitre_description: "Adversaries may exfiltrate data at specific times or intervals." },
  HIGH_UPLOAD: { mitre_technique_id: "T1048", mitre_technique_name: "Exfiltration Over Alternative Protocol", mitre_tactic: "Exfiltration", mitre_description: "Adversaries may exfiltrate it over a different protocol." },
  SEQUENTIAL_PORTS: { mitre_technique_id: "T1046", mitre_technique_name: "Network Service Discovery", mitre_tactic: "Discovery", mitre_description: "Adversaries may attempt to get a listing of services running on remote hosts." },
  REGULAR_INTERVAL: { mitre_technique_id: "T1071", mitre_technique_name: "Application Layer Protocol", mitre_tactic: "C2", mitre_description: "Adversaries may communicate using application layer protocols to avoid detection." },
  UNUSUAL_PROTOCOL: { mitre_technique_id: "T1095", mitre_technique_name: "Non-Application Layer Protocol", mitre_tactic: "C2", mitre_description: "Adversaries may use a non-application layer protocol for C2." },
};

const KILL_CHAIN_STAGES_INFO = [
  { id: 'RECONNAISSANCE', label: 'Reconnaissance', icon: Search, desc: 'Scanning, probing, enumeration' },
  { id: 'WEAPONIZATION', label: 'Weaponization', icon: Target, desc: 'Payload preparation' },
  { id: 'DELIVERY', label: 'Delivery', icon: Mail, desc: 'Phishing, exploit delivery' },
  { id: 'EXPLOITATION', label: 'Exploitation', icon: Bug, desc: 'Process behavior indicators' },
  { id: 'INSTALLATION', label: 'Installation', icon: HardDrive, desc: 'Persistence mechanisms' },
  { id: 'COMMAND_AND_CONTROL', label: 'C2', icon: Radio, desc: 'Beaconing, regular callbacks' },
  { id: 'EXFILTRATION', label: 'Exfiltration', icon: FileUp, desc: 'Sustained high upload' },
];

const KillChainVisualizer = ({ data, onMarkFalsePositive, onClearStage }: { data: KillChainData; onMarkFalsePositive: (stage: KillChainStageName) => void; onClearStage: (stage: KillChainStageName) => void }) => {
  return (
    <div className="space-y-6">
      {/* Horizontal Pipeline */}
      <div className="flex items-center justify-between gap-2 overflow-x-auto pb-4 custom-scrollbar">
        {KILL_CHAIN_STAGES_INFO.map((stageInfo, idx) => {
          const stageData = data.stages.find(s => s.stage === stageInfo.id);
          const isCurrent = data.current_stage === stageInfo.id;
          
          let bgColor = "bg-white/5";
          let borderColor = "border-border";
          let iconColor = "text-text-dim";
          
          if (stageData?.status === 'CONFIRMED') {
            bgColor = "bg-red-500/10";
            borderColor = "border-red-500/50";
            iconColor = "text-red-500";
          } else if (stageData?.status === 'SUSPECTED') {
            bgColor = "bg-amber-500/10";
            borderColor = "border-amber-500/50";
            iconColor = "text-amber-500";
          } else if (stageData?.status === 'CLEARED') {
            bgColor = "bg-green-500/10";
            borderColor = "border-green-500/50";
            iconColor = "text-green-500";
          }

          return (
            <React.Fragment key={stageInfo.id}>
              <div 
                className={cn(
                  "relative flex flex-col items-center p-3 rounded-lg border min-w-[120px] transition-all",
                  bgColor,
                  borderColor,
                  isCurrent && "ring-2 ring-blue-500 ring-offset-2 ring-offset-bg animate-pulse"
                )}
              >
                <stageInfo.icon size={20} className={cn("mb-2", iconColor)} />
                <span className="text-[10px] font-black uppercase text-center leading-tight">{stageInfo.label}</span>
                {stageData?.status !== 'CLEAN' && (
                  <span className={cn(
                    "mt-2 text-[8px] font-bold px-1.5 py-0.5 rounded uppercase tracking-tighter",
                    stageData?.status === 'CONFIRMED' ? "bg-red-500 text-white" :
                    stageData?.status === 'SUSPECTED' ? "bg-amber-500 text-white" : "bg-green-500 text-white"
                  )}>
                    {stageData?.status}
                  </span>
                )}
              </div>
              {idx < KILL_CHAIN_STAGES_INFO.length - 1 && (
                <ArrowRight size={16} className="text-border shrink-0" />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Detection Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {data.stages.filter(s => s.status !== 'CLEAN').map(stage => (
          <div key={stage.stage} className="bg-white/3 border border-border rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
               <div className="flex items-center gap-2">
                 <div className={cn(
                    "w-2 h-2 rounded-full",
                    stage.status === 'CONFIRMED' ? "bg-red-500" : stage.status === 'SUSPECTED' ? "bg-amber-500" : "bg-green-500"
                 )} />
                 <h4 className="text-xs font-black uppercase tracking-wider text-white">
                   {KILL_CHAIN_STAGES_INFO.find(info => info.id === stage.stage)?.label}
                 </h4>
               </div>
               <span className="text-[10px] font-mono text-text-dim">{stage.confidence}% CONFIDENCE</span>
            </div>

            <div className="space-y-1">
               {stage.indicators.map((indicator, idx) => (
                 <p key={idx} className="text-[11px] text-white/90 leading-relaxed">• {indicator}</p>
               ))}
            </div>

            <div className="grid grid-cols-2 gap-2 pt-2 border-t border-white/5">
                <div>
                   <div className="text-[9px] text-text-dim uppercase font-bold">First Detected</div>
                   <div className="text-[10px] font-mono text-white">{stage.first_detected ? new Date(stage.first_detected).toLocaleString() : 'N/A'}</div>
                </div>
                <div>
                   <div className="text-[9px] text-text-dim uppercase font-bold">Detection Layer</div>
                   <div className="text-[10px] font-mono text-blue-400">{stage.detection_layer}</div>
                </div>
                <div className="col-span-2">
                   <div className="text-[9px] text-text-dim uppercase font-bold mb-1">MITRE ATT&CK</div>
                   <div className="flex gap-1 flex-wrap">
                      {stage.mitre_techniques.map((t, idx) => (
                        <span key={`${t}-${idx}`} className="px-1.5 py-0.5 bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded text-[9px] font-mono">{t}</span>
                      ))}
                   </div>
                </div>
            </div>

            <div className="flex gap-2 pt-2">
               <button 
                onClick={() => onMarkFalsePositive(stage.stage)}
                className="flex-grow py-2 border border-border hover:bg-red-500/10 hover:text-red-500 rounded text-[9px] font-black uppercase transition-all flex items-center justify-center gap-1"
               >
                 <XCircle size={10} /> Mark False Positive
               </button>
               <button 
                onClick={() => onClearStage(stage.stage)}
                className="flex-grow py-2 border border-border hover:bg-green-500/10 hover:text-green-500 rounded text-[9px] font-black uppercase transition-all flex items-center justify-center gap-1"
               >
                 <ShieldCheck size={10} /> Clear Stage
               </button>
            </div>
          </div>
        ))}

        {data.stages.filter(s => s.status !== 'CLEAN').length === 0 && (
           <div className="col-span-full py-12 flex flex-col items-center justify-center border border-dashed border-border rounded-lg bg-white/2">
              <ShieldCheck size={32} className="text-green-500 mb-4 opacity-50" />
              <p className="text-text-dim text-xs font-mono">No active kill chain indicators detected for this device.</p>
           </div>
        )}
      </div>

      {/* Recommended Action Summary */}
      <div className="p-4 bg-blue-500/5 border border-blue-500/20 rounded-lg">
         <div className="flex items-start gap-3">
            <Info size={16} className="text-blue-400 mt-0.5 shrink-0" />
            <div>
               <h5 className="text-[11px] font-black uppercase text-blue-400 mb-1">Analyst Assessment & Recommended Action</h5>
               <p className="text-[11px] text-text-dim leading-relaxed">
                  {data.stages.filter(s => s.status === 'CONFIRMED' || s.status === 'SUSPECTED').length > 0 
                    ? `This device shows indicators consistent with stages ${data.stages.filter(s => s.status === 'CONFIRMED' || s.status === 'SUSPECTED').map(s => KILL_CHAIN_STAGES_INFO.findIndex(info => info.id === s.stage) + 1).join(' and ')} of the cyber kill chain. Recommended action: INVESTIGATE ${data.current_stage.replace(/_/g, ' ')} activity and consider isolating from network pending full forensic review.`
                    : "No indicators detected. Continuously monitoring per-node session patterns for adversarial drift."
                  }
               </p>
            </div>
         </div>
      </div>
    </div>
  );
};

const StatCard = ({ label, value, subvalue, icon: Icon, colorClass, trend }: { label: string; value: string; subvalue?: string; icon: any; colorClass?: string; trend?: "up" | "down" }) => (
  <div className="bg-white/3 border border-border p-5 rounded-lg flex flex-col justify-center min-h-[70px]">
    <div className="text-[11px] text-text-dim mb-2 uppercase tracking-[0.1em] font-bold opacity-60">{label}</div>
    <div className="flex flex-col gap-1">
      <div className="flex items-baseline gap-2">
        <div className={cn("font-sans text-[28px] font-bold", colorClass || "text-white")}>{value}</div>
        {trend && (
          <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded flex items-center", trend === "up" ? "text-green-500 bg-green-500/10" : "text-blue-500 bg-blue-500/10")}>
            {trend === "up" ? <ArrowUp size={8} /> : <ArrowDown size={8} />}
          </span>
        )}
      </div>
      {subvalue && <p className="text-[12px] text-text-dim font-medium opacity-50">{subvalue}</p>}
      <div className="mt-2 h-1 bg-white/5 rounded-full overflow-hidden">
        <div className={cn("h-full", colorClass?.replace('text-', 'bg-') || "bg-blue-500")} style={{ width: value.includes('%') ? value : '100%' }} />
      </div>
    </div>
  </div>
);

const ActionConfirmModal = ({ config, onClose, onConfirm }: { config: any; onClose: () => void; onConfirm: (reason: string, duration: string, severity: 'LOW' | 'MEDIUM' | 'HIGH') => void }) => {
  const [reason, setReason] = useState("");
  const [duration, setDuration] = useState("1 hour");
  const [severity, setSeverity] = useState<'LOW' | 'MEDIUM' | 'HIGH'>('MEDIUM');
  const [alertId, setAlertId] = useState("");

  if (!config.show) return null;

  const isValid = reason.length >= 10 && duration && severity;

  return (
    <div className="fixed inset-0 z-[300] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <motion.div 
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className="bg-card border border-border max-w-lg w-full rounded-lg shadow-2xl overflow-hidden"
      >
        <div className="p-6">
          <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2 uppercase tracking-tight">
            <ShieldAlert className="text-red-500" />
            Confirm Security Action
          </h2>

          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4 bg-white/5 p-4 rounded-lg border border-border border-dashed font-mono text-[11px]">
               <div>
                  <div className="text-[9px] text-text-dim uppercase font-bold mb-1">Action Type</div>
                  <div className="text-white font-bold">{config.type.replace('_', ' ')}</div>
               </div>
               <div>
                  <div className="text-[9px] text-text-dim uppercase font-bold mb-1">Target Entity</div>
                  <div className="text-white font-bold">{config.target}</div>
               </div>
               <div className="col-span-2 pt-2 border-t border-white/5">
                  <div className="text-[9px] text-text-dim uppercase font-bold mb-1">Initiated By</div>
                  <div className="text-white">{config.triggeredBy}</div>
               </div>
            </div>

            <div className="space-y-4">
               <div>
                  <label className="text-[10px] text-text-dim uppercase font-bold block mb-2">Justification / Reason (min 10 chars)</label>
                  <textarea 
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="e.g. Suspected C2 beaconing to Tor exit node, blocking pending investigation"
                    className="w-full bg-white/5 border border-border p-3 rounded text-sm text-white focus:outline-none focus:border-blue-500 min-h-[100px]"
                  />
               </div>

               <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-[10px] text-text-dim uppercase font-bold block mb-2">Enforcement Duration</label>
                    <select 
                      value={duration}
                      onChange={(e) => setDuration(e.target.value)}
                      className="w-full bg-white/5 border border-border p-2 rounded text-xs text-white focus:outline-none"
                    >
                      {['15 min', '30 min', '1 hour', '6 hours', '24 hours', '7 days', 'Permanent'].map(d => (
                        <option key={d} value={d} className="bg-bg">{d}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] text-text-dim uppercase font-bold block mb-2">Severity Assessment</label>
                    <div className="flex gap-2">
                       {(['LOW', 'MEDIUM', 'HIGH'] as const).map(s => (
                         <button
                           key={s}
                           onClick={() => setSeverity(s)}
                           className={cn(
                             "flex-grow py-2 rounded text-[9px] font-black uppercase transition-all border",
                             severity === s 
                               ? s === 'HIGH' ? "bg-red-500 text-white border-red-500" : s === 'MEDIUM' ? "bg-amber-500 text-white border-amber-500" : "bg-blue-500 text-white border-blue-500"
                               : "border-border text-text-dim hover:text-white"
                           )}
                         >
                           {s}
                         </button>
                       ))}
                    </div>
                  </div>
               </div>

               <div>
                  <label className="text-[10px] text-text-dim uppercase font-bold block mb-2">Related Alert ID (Optional)</label>
                  <div className="flex items-center gap-2">
                     <span className="text-text-dim font-mono text-xs">ALT-</span>
                     <input 
                       value={alertId}
                       onChange={(e) => setAlertId(e.target.value)}
                       placeholder="0042"
                       className="w-full bg-white/5 border border-border p-2 rounded text-xs text-white focus:outline-none font-mono"
                     />
                  </div>
               </div>
            </div>

            <div className="flex gap-3 pt-4">
               <button 
                 disabled={!isValid}
                 onClick={() => onConfirm(reason, duration, severity)}
                 className={cn(
                   "flex-grow py-3 rounded text-xs font-black uppercase tracking-widest transition-all text-white",
                   isValid ? "bg-red-600 hover:bg-red-500 shadow-lg" : "bg-gray-800 text-gray-500 cursor-not-allowed border border-white/5"
                 )}
               >
                  Confirm Action →
               </button>
               <button 
                 onClick={onClose}
                 className="px-6 py-3 border border-border hover:bg-white/5 text-text-dim font-bold rounded text-xs uppercase tracking-widest transition-all"
               >
                  Cancel
               </button>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default function App() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [flows, setFlows] = useState<Flow[]>([]);
  const [matrix, setMatrix] = useState<Matrix | null>(null);
  const [vms, setVms] = useState<VM[]>([]);
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [deepDive, setDeepDive] = useState<DeepDive | null>(null);
  const [falsePositives, setFalsePositives] = useState<FalsePositiveAlert[]>([]);
  
  const [cases, setCases] = useState<InvestigationCase[]>([]);

  const [activeTab, setActiveTab] = useState<'overview' | 'connections' | 'devices' | 'alerts' | 'actions' | 'controls' | 'reports' | 'system' | 'cases' | 'host'>('overview');
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [caseFilter, setCaseFilter] = useState<CaseStatus | 'ALL'>('ALL');
  const [isNewCaseModalOpen, setIsNewCaseModalOpen] = useState(false);
  const [newCasePreFill, setNewCasePreFill] = useState<{title?: string, description?: string, alerts?: string[], devices?: string[]} | null>(null);

  const [actionsSubTab, setActionsSubTab] = useState<'PENDING' | 'ACTIVE' | 'HISTORY'>('PENDING');
  const [mode, setMode] = useState<'local' | 'network'>('local');
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [selectedVmId, setSelectedVmId] = useState<string | null>(null);
  const [watchedDeviceIds, setWatchedDeviceIds] = useState<string[]>([]);
  const [armouredDeviceId, setArmouredDeviceId] = useState<string | null>(null);
  const [readAlertIds, setReadAlertIds] = useState<string[]>([]);
  const [showSetupModal, setShowSetupModal] = useState(false);
  const [hasDismissedSetupModal, setHasDismissedSetupModal] = useState(false);
  const [alertFilter, setAlertFilter] = useState<'ALL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNREAD' | 'MITRE'>('ALL');
  const [selectedMitreTech, setSelectedMitreTech] = useState<{ id: string; tactic: string } | null>(null);
  const [deviceDetailTab, setDeviceDetailTab] = useState<'flow' | 'alerts' | 'killchain' | 'baseline'>('flow');
  const [deviceKillChains, setDeviceKillChains] = useState<Record<string, KillChainData>>({});
  
  // Reports State
  const [reportHistory, setReportHistory] = useState<ReportHistoryEntry[]>([
    { id: 'rep-1', date: '2026-05-15 09:42', type: 'EXECUTIVE', analyst: 'T. Munyaradzi', devices: 12, actions: 3, config: {} },
    { id: 'rep-2', date: '2026-05-10 14:15', type: 'TECHNICAL', analyst: 'T. Munyaradzi', devices: 12, actions: 8, config: {} },
    { id: 'rep-3', date: '2026-05-01 10:00', type: 'AUDIT', analyst: 'K. Chen', devices: 5, actions: 24, config: {} },
  ]);
  const [currentReport, setCurrentReport] = useState<GeneratedReport | null>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [reportConfig, setReportConfig] = useState({
    type: 'TECHNICAL',
    range: '7D',
    devices: 'ALL',
    sections: {
      exec: true,
      risk: true,
      threats: true,
      killchain: true,
      baseline: true,
      beacon: true,
      audit: true,
      recs: true
    },
    analyst: 'T. Munyaradzi',
    org: 'University of Zimbabwe'
  });
  
  const [dataLayerMode, setDataLayerMode] = useState<'live' | 'demo'>('live');
  const [notifications, setNotifications] = useState<any[]>([]);
  
  // Actions & Controls State
  const [actions, setActions] = useState<SecurityAction[]>([]);

  const [rules, setRules] = useState<ActionRule[]>([
    { id: 'rule-1', name: 'High Recon Score Auto-Flag', condition: 'Recon > 80 for 10min', action: 'BLOCK_IP', mode: 'PENDING', enabled: false, triggerCount: 12, lastTriggered: Date.now() - 30 * 60 * 1000 },
    { id: 'rule-2', name: 'Beaconing Detection', condition: 'Beacon Score > 75', action: 'FLAG_FOR_REVIEW', mode: 'PENDING', enabled: true, triggerCount: 45, lastTriggered: Date.now() - 5 * 60 * 1000 },
    { id: 'rule-3', name: 'Baseline Drift Alert', condition: 'Drift > 60 for 3 days', action: 'FLAG_FOR_REVIEW', mode: 'PENDING', enabled: false, triggerCount: 3 },
    { id: 'rule-4', name: 'New Device Alert', condition: 'Unknown MAC joins', action: 'WATCH_DEVICE', mode: 'PENDING', enabled: true, triggerCount: 124 },
    { id: 'rule-5', name: 'Exfiltration Indicator', condition: 'Upload > 100MB/5min', action: 'BLOCK_IP', mode: 'PENDING', enabled: false, triggerCount: 0 },
    { id: 'rule-6', name: 'C2 Port Beaconing', condition: 'Port in [4444, 1337, 8080] repeated', action: 'FLAG_FOR_REVIEW', mode: 'PENDING', enabled: true, triggerCount: 8, lastTriggered: Date.now() - 2 * 60 * 60 * 1000 },
  ]);

  const [actionModal, setActionModal] = useState<{
    show: boolean;
    type: ActionType;
    target: string;
    triggeredBy: string;
    alertId?: string;
  }>({
    show: false,
    type: 'BLOCK_IP',
    target: '',
    triggeredBy: ''
  });

  const [toasts, setToasts] = useState<UndoToast[]>([]);

  // Timer for toasts and action expiry
  useEffect(() => {
    const timer = setInterval(() => {
      // Handle toasts
      setToasts(prev => prev.map(t => ({ ...t, timeLeft: t.timeLeft - 1 })).filter(t => t.timeLeft > 0));
      
      // Handle action expiry
      setActions(prev => prev.map(action => {
        if (action.status === 'ACTIVE' && action.expiresAt && action.expiresAt < Date.now()) {
          return { ...action, status: 'EXPIRED' };
        }
        return action;
      }));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleActionConfirm = (id: string, reason: string, duration: string, severity: 'LOW' | 'MEDIUM' | 'HIGH') => {
    const action = actions.find(a => a.id === id);
    if (!action) return;

    let expiresAt: number | undefined;
    if (duration !== 'Permanent') {
      const ms = duration === '15 min' ? 15 * 60 * 1000 :
                 duration === '30 min' ? 30 * 60 * 1000 :
                 duration === '1 hour' ? 60 * 60 * 1000 :
                 duration === '6 hours' ? 6 * 60 * 60 * 1000 :
                 duration === '24 hours' ? 24 * 60 * 60 * 1000 :
                 duration === '7 days' ? 7 * 24 * 60 * 60 * 1000 : 0;
      expiresAt = Date.now() + ms;
    }

    const updatedAction: SecurityAction = {
      ...action,
      status: 'ACTIVE',
      reason,
      duration,
      severity,
      confirmedBy: 'Analyst: Current User',
      confirmedAt: Date.now(),
      expiresAt
    };

    setActions(prev => prev.map(a => a.id === id ? updatedAction : a));

    // Add Undo Toast
    const toastId = `toast-${Math.random().toString(36).substr(2, 9)}`;
    setToasts(prev => [...prev, {
      id: toastId,
      actionId: id,
      message: `${action.type.replace('_', ' ')} ${action.target} confirmed for ${duration}`,
      timeLeft: 10
    }]);
  };

  const undoAction = (toastId: string, actionId: string) => {
    setActions(prev => prev.map(a => a.id === actionId ? { ...a, status: 'PENDING', confirmedBy: undefined, confirmedAt: undefined, expiresAt: undefined } : a));
    setToasts(prev => prev.filter(t => t.id !== toastId));
  };

  const revokeAction = (id: string, reason: string) => {
    setActions(prev => prev.map(a => a.id === id ? { ...a, status: 'REVOKED', reason: `${a.reason} | REVOKED: ${reason}` } : a));
  };

  const extendAction = (id: string, extraMs: number) => {
    setActions(prev => prev.map(a => {
      if (a.id === id && a.expiresAt) {
        return { 
          ...a, 
          expiresAt: a.expiresAt + extraMs, 
          extendedCount: (a.extendedCount || 0) + 1 
        };
      }
      return a;
    }));
  };

  const makePermanent = (id: string) => {
    setActions(prev => prev.map(a => a.id === id ? { ...a, duration: 'Permanent', expiresAt: undefined } : a));
  };

  const reapplyAction = (action: SecurityAction) => {
    const newAction: SecurityAction = {
      ...action,
      id: `act-${Math.random().toString(36).substr(2, 9)}`,
      status: 'PENDING',
      triggeredAt: Date.now(),
      confirmedBy: undefined,
      confirmedAt: undefined,
      expiresAt: undefined
    };
    setActions(prev => [newAction, ...prev]);
    setActiveTab('actions');
    setActionsSubTab('PENDING');
  };
  
  const [history, setHistory] = useState<{ time: string; in: number; out: number }[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [time, setTime] = useState(new Date().toLocaleTimeString());
  const [hostname, setHostname] = useState("DRIFTWATCH-NODE-01");
  const [username, setUsername] = useState("analyst");
  const wsRef = useRef<WebSocket | null>(null);

  // Mock Alerts
  const [alerts, setAlerts] = useState<Alert[]>([]);

  useEffect(() => {
    const initDataLayer = async () => {
      const dl = DataLayer.getInstance();
      await dl.initialize();
      setDataLayerMode(dl.mode);
      
      if (dl.mode === 'live') {
        setMode('network');
        // Initial fetch
        const devList = await dl.getDevices();
        if (devList.length > 0) setDevices(devList);
      }
    };
    initDataLayer();
  }, []);

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Fetch capabilities on mount
  // Fetch capabilities on mount
  useEffect(() => {
    const dl = DataLayer.getInstance();
    dl.getCapabilities().then(setCapabilities).catch(e => console.error(e));
  }, []);

  // WebSocket live feed
  useEffect(() => {
    if (dataLayerMode !== 'live') return;

    const connectWS = () => {
      const ws = new WebSocket(CONFIG.WS_BASE);
      
      ws.onopen = () => {
        setIsConnected(true);
        console.log("[DRIFTWATCH] WebSocket Connected");
      };
      
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'full_update') {
            if (data.devices) setDevices(data.devices);
            if (data.flows) setFlows(data.flows);
            if (data.alerts) {
              setAlerts(prev => {
                const combined = [...data.alerts, ...prev];
                const unique = Array.from(new Map(combined.map(a => [a.id, a])).values());
                return unique.slice(0, 100);
              });
            }
            if (data.metrics) {
              setSystemStatus(prev => prev ? { ...prev, ...data.metrics } : data.metrics);
               // Also sync some top level metrics if needed
            }

            // Handle new alerts for toasts
            if (data.new_alerts && data.new_alerts.length > 0) {
              data.new_alerts.forEach((alert: any) => {
                const toast = {
                  id: alert.id || Math.random().toString(),
                  title: `${alert.alert_type} DETECTED`,
                  message: alert.description,
                  severity: alert.severity,
                  timestamp: new Date().toLocaleTimeString()
                };
                setNotifications(prev => [toast, ...prev].slice(0, 5));
                
                // If high severity alert, play sound if we had a sound hook
                if (alert.severity === 'HIGH') {
                  // flash threat indicator logic
                }
              });
            }
          }
        } catch (e) {
          console.error("WS Message Error", e);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        setTimeout(connectWS, 3000); // Reconnect
      };

      wsRef.current = ws;
    };

    connectWS();
    return () => wsRef.current?.close();
  }, [dataLayerMode]);

  // System Status Polling
  useEffect(() => {
    const fetchSystemStatus = async () => {
      try {
        const dl = DataLayer.getInstance();
        if (dl.mode === 'live') {
          const [res, dd] = await Promise.all([
            dl.getMetrics(),
            dl.getDeepDive()
          ]);
          if (res) setSystemStatus(res);
          if (dd) setDeepDive(dd);
        } else {
          const res = await fetch('/api/system/status').then(r => r.json());
          setSystemStatus(res);
        }
      } catch (err) {
        console.error("Failed to fetch system status", err);
      }
    };
    fetchSystemStatus();
    const interval = setInterval(fetchSystemStatus, 2000);
    return () => clearInterval(interval);
  }, []);

  const generateCaseId = () => {
    const year = new Date().getFullYear();
    const count = cases.length + 1;
    return `DW-${year}-${count.toString().padStart(3, '0')}`;
  };

  const handleCreateCase = (data: Partial<InvestigationCase>) => {
    const newCase: InvestigationCase = {
      id: generateCaseId(),
      title: data.title || 'Untitled Case',
      description: data.description || '',
      status: CaseStatus.OPEN,
      severity: data.severity || CaseSeverity.MEDIUM,
      assignedTo: data.assignedTo || username || 'analyst',
      deviceIds: data.deviceIds || [],
      alertIds: data.alertIds || [],
      createdAt: new Date().toLocaleString(),
      updatedAt: new Date().toLocaleString(),
      summary: data.description?.slice(0, 80) + '...' || '',
      notes: [],
      ...data
    };
    setCases(prev => [newCase, ...prev]);
    setIsNewCaseModalOpen(false);
    setNewCasePreFill(null);
  };

  const handleCreateCaseFromAlert = (alert: Alert) => {
    setNewCasePreFill({
      title: `Investigation: ${alert.type.replace('_', ' ')}`,
      description: alert.description,
      alerts: [alert.id],
      devices: [alert.source.ip]
    });
    setIsNewCaseModalOpen(true);
  };

  const handleAddNote = (caseId: string, content: string, tag?: CaseNote['tag']) => {
    setCases(prev => prev.map(c => {
      if (c.id === caseId) {
        const newNote: CaseNote = {
          id: `n-${Date.now()}`,
          analyst: username || 'analyst',
          timestamp: new Date().toLocaleString(),
          content,
          tag
        };
        return {
          ...c,
          notes: [...c.notes, newNote],
          updatedAt: new Date().toLocaleString()
        };
      }
      return c;
    }));
  };

  const handleUpdateCaseStatus = (caseId: string, status: CaseStatus) => {
    setCases(prev => prev.map(c => {
      if (c.id === caseId) {
        return { ...c, status, updatedAt: new Date().toLocaleString() };
      }
      return c;
    }));
  };

  const handleUpdateCaseSeverity = (caseId: string, severity: CaseSeverity) => {
    setCases(prev => prev.map(c => {
      if (c.id === caseId) {
        return { ...c, severity, updatedAt: new Date().toLocaleString() };
      }
      return c;
    }));
  };

  const handleMarkFalsePositive = (alert: Alert, reason: string) => {
    const layer = (alert.mitre_description?.includes('GMM') ? 'GMM' : 
                   alert.mitre_description?.includes('KDE') ? 'KDE' : 
                   alert.mitre_description?.includes('LOWESS') ? 'LOWESS' : 'RULE_ENGINE') as any;
                   
    const newFP: FalsePositiveAlert = {
      id: `fp-${Date.now()}`,
      originalAlert: alert.description,
      markedBy: username || 'analyst',
      reason,
      timestamp: new Date().toLocaleString(),
      layer
    };
    setFalsePositives(prev => [newFP, ...prev]);
    setAlerts(prev => prev.filter(a => a.id !== alert.id));
  };

  // Network-wide Polling
  useEffect(() => {
    if (mode === 'network' && dataLayerMode === 'live') {
      if (!hasDismissedSetupModal) {
        setShowSetupModal(true);
      }
      
      const dl = DataLayer.getInstance();

      const fetchDevices = async () => {
        try {
          const devs = await dl.getDevices();
          setDevices(devs);
        } catch (err) {
          console.error("Failed to fetch devices", err);
        }
      };

      const fetchFlowsAndMatrix = async () => {
        try {
          const [flws, mtrx] = await Promise.all([
            dl.getFlows(),
            dl.getMatrix()
          ]);
          if (flws) setFlows(flws);
          if (mtrx) setMatrix(mtrx);
        } catch (err) {
          console.error("Failed to fetch flows/matrix", err);
        }
      };

      const fetchVMs = async () => {
        try {
          const res = await dl.getVMs();
          if (res) setVms(res);
        } catch (err) {
          console.error("Failed to fetch VMs", err);
        }
      };

      fetchDevices();
      fetchFlowsAndMatrix();
      fetchVMs();

      // Fetch KillChains for all devices
      const fetchAllKillChains = async () => {
         try {
            const devs = await dl.getDevices();
            const kcPromises = devs.map((d: any) => 
               dl.getKillChain(d.id).then(data => ({ id: d.id, data }))
            );
            const kcResults = await Promise.all(kcPromises);
            const newKCs: Record<string, KillChainData> = {};
            kcResults.forEach((res: any) => {
               if (res.data) newKCs[res.id] = res.data;
            });
            setDeviceKillChains(newKCs);
         } catch (err) {
            console.error("Failed to fetch all killchains", err);
         }
      };
      
      fetchAllKillChains();

      const devicesInterval = setInterval(fetchDevices, 5000);
      const watchInterval = setInterval(() => {
        // Watched devices get 1s polling for flows (represented by re-fetching matrix/flows)
        if (watchedDeviceIds.length > 0) fetchFlowsAndMatrix();
      }, 1000);
      const flowsInterval = setInterval(fetchFlowsAndMatrix, 2000);
      const vmsInterval = setInterval(fetchVMs, 10000);

      return () => {
        clearInterval(devicesInterval);
        clearInterval(watchInterval);
        clearInterval(flowsInterval);
        clearInterval(vmsInterval);
      };
    } else {
      setDevices([]);
      setFlows([]);
      setMatrix(null);
      setVms([]);
    }
  }, [mode, watchedDeviceIds]);

  const connect = () => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const ws = new WebSocket(`${protocol}//${host}/live`);

    ws.onopen = () => {
      console.log("WebSocket connected");
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const payload: DashboardData = JSON.parse(event.data);
        if (wsRef.current === null) {
           console.log("First WS data received:", payload);
        }
        if (payload.metrics.hostname) setHostname(payload.metrics.hostname);
        if (payload.metrics.username) setUsername(payload.metrics.username);
        setData(payload);
        
        // Update history
        setHistory(prev => {
          const newPoint = {
            time: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            in: parseFloat(formatMBps(payload.metrics.bytes_recv_per_sec)),
            out: parseFloat(formatMBps(payload.metrics.bytes_sent_per_sec))
          };
          const next = [...prev, newPoint].slice(-60);
          return next;
        });
      } catch (err) {
        console.error("WS parse error", err);
      }
    };

    ws.onclose = () => {
      console.log("WebSocket closed, retrying...");
      setIsConnected(false);
      setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };

    wsRef.current = ws;
  };

  useEffect(() => {
    connect();
    const dl = DataLayer.getInstance();
    // Fetch initial hostname if possible
    dl.getMetrics().then(d => {
        if (d && d.hostname) setHostname(d.hostname);
        if (d && d.username) setUsername(d.username);
    }).catch(() => {});
    return () => wsRef.current?.close();
  }, []);

  // Fallback polling if WS is down
  useEffect(() => {
    const interval = setInterval(() => {
      if (!isConnected) {
        const dl = DataLayer.getInstance();
        dl.getMetrics().then(metrics => {
          if (metrics) setData(prev => prev ? { ...prev, metrics } : null);
        }).catch(() => {});
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [isConnected]);

  const metrics = data?.metrics;
  const cpuColor = !metrics ? "text-gray-400" : metrics.cpu < 50 ? "text-green-400" : metrics.cpu < 80 ? "text-amber-400" : "text-red-400";
  const ramColor = !metrics ? "text-gray-400" : metrics.ram < 50 ? "text-green-400" : metrics.ram < 80 ? "text-amber-400" : "text-red-400";

  return (
    <div className="h-screen bg-bg text-white flex flex-col overflow-hidden font-sans">
      <style>{`
        @media print {
          html, body { overflow: visible !important; height: auto !important; background: white !important; }
          body { background: white !important; color: black !important; padding: 0 !important; margin: 0 !important; }
          .bg-card, .bg-background { background: white !important; border: 1px solid #eee !important; color: black !important; }
          .text-white, .text-text-dim, .text-blue-400, .text-red-400 { color: black !important; }
          .no-print, header, nav, .sidebar-nav, .tabs-container, button, .notifications-panel, .action-pill { display: none !important; }
          .report-container { 
            position: absolute !important; 
            left: 0 !important; 
            top: 0 !important; 
            width: 100% !important; 
            height: auto !important; 
            overflow: visible !important; 
            padding: 0 !important;
            margin: 0 !important;
            display: block !important;
            background: white !important;
            z-index: 9999 !important;
          }
          .report-page {
            box-shadow: none !important;
            border: none !important;
            margin: 0 !important;
            padding: 0 !important;
            width: 100% !important;
            max-width: none !important;
            min-height: auto !important;
          }
          .card-break { page-break-inside: avoid !important; }
          .border-white\/5, .border-border { border-color: #ddd !important; }
          * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
        }
      `}</style>
      {/* Top Bar */}
      <header className="h-[52px] bg-card border-b border-border flex items-center justify-between px-4 flex-shrink-0 no-print">
        <div className="flex items-center gap-4">
          <div className="flex flex-col">
            <h1 className="text-xl font-black italic tracking-tighter flex items-center gap-1.5 leading-none">
              DRIFTWATCH
              <span className="text-blue-500 font-mono text-sm not-italic">NDR</span>
            </h1>
            <span className="text-[9px] uppercase tracking-[0.2em] font-bold text-text-dim/60 mt-1 ml-0.5 opacity-60">
              Adversarial Drift Detection Engine
            </span>
          </div>
          
          <div className="flex items-center bg-white/5 p-0.5 rounded-full border border-border ml-2">
            <button 
              onClick={() => { setMode('local'); setActionsSubTab('PENDING'); }}
              className={cn(
                "px-3 py-1 rounded-full text-[9px] font-bold transition-all uppercase",
                mode === 'local' ? "bg-gray-600 text-white shadow-sm" : "text-text-dim hover:text-white"
              )}
            >
              Host Mode
            </button>
            <button 
              onClick={() => { setMode('network'); setActionsSubTab('PENDING'); }}
              className={cn(
                "px-3 py-1 rounded-full text-[9px] font-bold transition-all uppercase",
                mode === 'network' ? "bg-blue-600 text-white shadow-sm" : "text-text-dim hover:text-white"
              )}
            >
              Sentinel Mode
            </button>
          </div>
        </div>
        
        <div className="flex items-center gap-6">
          <div className="hidden lg:flex items-center gap-5 font-mono text-[11px] text-text-dim">
            <div className="flex items-center gap-2 uppercase">
              <span>HOST:</span>
              <span className="text-white lowercase">{username}@<span className="uppercase">{deepDive?.os?.hostname || hostname}</span></span>
            </div>
            <div className="flex items-center gap-2 uppercase">
              <span>UPTIME:</span>
              <span className="text-white">{time}</span>
            </div>
          </div>
          
          <div className="flex items-center gap-2 px-2 py-0.5 bg-green-500/10 text-green-500 rounded-full border border-green-500/20 text-[10px] font-bold">
            <div className={cn("w-1.5 h-1.5 rounded-full", isConnected ? "bg-green-500" : "bg-red-500")} />
            {isConnected ? "CONNECTED" : "OFFLINE"}
          </div>

          <button 
            onClick={() => setActiveTab('system')}
            className={cn(
              "p-2 rounded hover:bg-white/5 transition-all text-text-dim hover:text-blue-400",
              activeTab === 'system' && "text-blue-400 bg-white/5"
            )}
            title="System Health & Sensor Metrics"
          >
            <Server size={18} />
          </button>

          {/* ACTIONS Pill */}
          <button 
            onClick={() => { setActiveTab('actions'); setActionsSubTab('PENDING'); }}
            className={cn(
              "flex items-center gap-2 px-3 py-1 rounded-full border text-[10px] font-bold transition-all",
              actions.filter(a => a.status === 'PENDING').length > 0 
                ? "bg-amber-500/10 text-amber-500 border-amber-500/30 animate-pulse" 
                : "bg-green-500/10 text-green-500 border-green-500/30 whitespace-nowrap"
            )}
          >
            <Shield size={12} />
            {actions.filter(a => a.status === 'PENDING').length > 0 
              ? `${actions.filter(a => a.status === 'PENDING').length} PENDING` 
              : "ALL CLEAR"
            }
          </button>
        </div>
      </header>

      {/* Tabs & Banner */}
      <div className="no-print">
        {dataLayerMode === 'demo' ? (
          <div className="h-9 bg-amber-600/20 border-b border-amber-500/30 px-6 flex items-center justify-between text-[10px] text-amber-500 font-bold uppercase tracking-widest shrink-0">
            <div className="flex items-center gap-2">
              <AlertTriangle size={12} className="animate-pulse" />
              DEMO MODE — Simulated data. Connect the DRIFTWATCH backend to see real devices.
            </div>
            <button onClick={() => window.location.reload()} className="hover:text-white transition-colors bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20 flex items-center gap-1">
              <RotateCcw size={10} /> RE-SCAN
            </button>
          </div>
        ) : (
          <div className="h-9 bg-green-600/20 border-b border-green-500/30 px-6 flex items-center gap-2 text-[10px] text-green-500 font-bold uppercase tracking-widest shrink-0">
              <CheckCircle2 size={12} />
              LIVE — Connected to DRIFTWATCH Backend at {CONFIG.API_BASE}
          </div>
        )}

        <div className="flex-shrink-0 bg-card border-b border-border">
          {mode === 'network' && (
            <motion.div 
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 32, opacity: 1 }}
              className="bg-blue-900/20 border-b border-blue-500/30 px-6 flex items-center gap-2 text-[10px] text-blue-400 font-medium overflow-hidden"
            >
              <Shield size={12} />
              SENTINEL MODE ACTIVE — Monitoring all network entities for adversarial drift
            </motion.div>
          )}
          <div className="flex px-4 gap-6">
            {[
              { id: 'overview', label: 'Overview', icon: Activity },
              { id: 'host', label: 'Host Deep Dive', icon: Cpu },
              { id: 'connections', label: 'Connections', icon: Zap },
              { id: 'devices', label: 'Devices', count: devices?.length || 0, icon: Globe },
              { id: 'alerts', label: 'Alerts', icon: AlertCircle, count: alerts?.filter?.(a => !a.isRead).length || 0 },
              { id: 'actions', label: 'Actions', icon: Shield, count: actions?.filter?.(a => a.status === 'PENDING').length || 0 },
              { id: 'cases', label: 'Cases', icon: Briefcase, count: cases?.filter?.(c => c.status !== CaseStatus.CLOSED).length || 0 },
              { id: 'controls', label: 'Controls', icon: Gauge },
              { id: 'reports', label: 'Reports', icon: FileText },
              { id: 'system', label: 'System', icon: Server },
            ].map(tab => (
              <button 
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={cn(
                  "py-3 text-[11px] font-bold uppercase tracking-widest flex items-center gap-2 border-b-2 transition-all",
                  activeTab === tab.id ? "border-blue-500 text-blue-400" : "border-transparent text-text-dim hover:text-white"
                )}
              >
                <tab.icon size={12} />
                {tab.label}
                {tab.count !== undefined && tab.count > 0 && (
                  <span className={cn(
                    "px-1.5 py-0.5 rounded-full text-[9px]",
                    tab.id === 'alerts' ? "bg-red-500 text-white" : "bg-blue-500/20 text-blue-400"
                  )}>
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>

      <main className="flex-grow overflow-hidden relative">
        <AnimatePresence mode="wait">
          {activeTab === 'overview' && (
            <motion.div 
               key="overview"
               initial={{ opacity: 0, y: 10 }}
               animate={{ opacity: 1, y: 0 }}
               exit={{ opacity: 0, y: -10 }}
                className="flex-grow overflow-y-auto custom-scrollbar p-6 space-y-6 scroll-smooth h-full pb-20"
            >
              {/* PANEL 1 - Host Traffic Baseline */}
              <div className="grid grid-cols-12 gap-6">
                <Card title="Host Traffic Baseline (MB/s)" icon={Activity} className="col-span-12 min-h-[320px]">
                   <div className="absolute top-4 right-5 flex gap-6 text-[11px] font-mono font-bold">
                      <span className="text-blue-400 uppercase">INBOUND: {formatMBps(metrics?.bytes_recv_per_sec || 0)} MB/s</span>
                      <span className="text-orange-400 uppercase">OUTBOUND: {formatMBps(metrics?.bytes_sent_per_sec || 0)} MB/s</span>
                   </div>
                  <div className="w-full h-[220px] pt-6 flex flex-col">
                    <div className="flex-grow">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={history} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
                          <defs>
                            <linearGradient id="colorIn" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2}/>
                              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                            </linearGradient>
                            <linearGradient id="colorOut" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#f97316" stopOpacity={0.2}/>
                              <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="4" stroke="#1e293b" vertical={false} />
                          <XAxis dataKey="time" hide />
                          <YAxis stroke="#475569" fontSize={9} tickFormatter={(v) => `${v}`} />
                          <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', padding: '12px', fontSize: '11px', borderRadius: '8px' }} />
                          <Area type="monotone" dataKey="in" name="Inbound" stroke="#3b82f6" strokeWidth={3} fillOpacity={1} fill="url(#colorIn)" isAnimationActive={false} />
                          <Area type="monotone" dataKey="out" name="Outbound" stroke="#f97316" strokeWidth={3} fillOpacity={1} fill="url(#colorOut)" isAnimationActive={false} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="mt-4 text-[11px] text-text-dim/60 font-medium italic">
                       Establishing behavioural baseline using GMM+KDE sensor fusion. GMM engine activates at day 14.
                    </div>
                  </div>
                </Card>

                {/* ROW 2 - System Metrics, Processes, Ports */}
                <div className="col-span-12 lg:col-span-4 space-y-6 flex flex-col h-full">
                  <Card title="Baseline Health" icon={Clock} className="min-h-[140px]">
                    <div className="space-y-4">
                      <div className="flex flex-col">
                        <div className="text-[28px] font-bold text-white leading-tight">LEARNING</div>
                        <div className="text-[12px] text-text-dim/50 font-bold uppercase tracking-wider mb-2">Day 0 of 14</div>
                        <div className="h-2 bg-white/5 rounded-full overflow-hidden relative">
                          <div className="h-full bg-amber-500 w-[2%] shadow-[0_0_8px_rgba(245,158,11,0.5)]" />
                        </div>
                      </div>
                      <p className="text-[11px] text-amber-500/80 italic font-medium leading-relaxed bg-amber-500/5 p-3 border border-amber-500/10 rounded">
                        "GMM engine activates at day 14. Currently establishing Bayesian priors for network host fingerprint."
                      </p>
                    </div>
                  </Card>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <StatCard 
                      label="CPU" 
                      value={`${metrics?.cpu?.toFixed(1) ?? 0}%`} 
                      icon={Cpu}
                      colorClass={metrics && metrics.cpu > 80 ? "text-red-500" : metrics && metrics.cpu > 50 ? "text-amber-500" : "text-green-500"}
                    />
                    <StatCard 
                      label="RAM" 
                      value={`${metrics?.ram?.toFixed(1) ?? 0}%`} 
                      icon={Database}
                      colorClass={metrics && metrics.ram > 80 ? "text-red-500" : metrics && metrics.ram > 50 ? "text-amber-500" : "text-green-500"}
                    />
                  </div>

                  <MitreCoverageCard alerts={alerts} />
                </div>

                <Card title="Top Processes (CPU %)" icon={Hash} className="col-span-12 lg:col-span-4 min-h-[400px]">
                   <div className="flex flex-col gap-5 h-full">
                    {(data?.processes || []).slice(0, 10).map((p, i) => (
                      <div key={i} className="w-full">
                        <div className="flex justify-between text-[11px] text-text-dim mb-1.5 font-bold uppercase tracking-wider">
                           <span>{p.name} <span className="opacity-40 font-mono text-[9px]">({p.pid})</span></span>
                           <span className="text-white">{(p.cpu ?? 0).toFixed(1)}%</span>
                        </div>
                        <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                          <motion.div initial={{ width: 0 }} animate={{ width: `${Math.max(p.cpu, 2)}%` }} className={cn("h-full rounded-full", p.cpu > 50 ? "bg-red-500" : p.cpu > 20 ? "bg-amber-500" : "bg-blue-500")} />
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>

                <Card title="Open Ports" icon={Server} className="col-span-12 lg:col-span-4 min-h-[400px]">
                   <div className="h-full overflow-hidden font-mono text-[11px]">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="text-text-dim font-bold border-b border-border uppercase text-[10px] tracking-widest opacity-60">
                          <th className="pb-3 px-2">Port</th>
                          <th className="pb-3 px-2">Proto</th>
                          <th className="pb-3 px-2 text-right">Process</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(data?.ports || []).slice(0, 12).map((port, i) => (
                          <tr key={`${port.port}-${i}`} className="border-b border-white/5 hover:bg-white/2 transition-colors">
                            <td className="py-2.5 px-2 text-blue-400 font-bold">{port.port}</td>
                            <td className="py-2.5 px-2 text-text-dim">{port.protocol}</td>
                            <td className="py-2.5 px-2 text-right text-white/90 truncate max-w-[120px]">{port.process}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>

                {/* ROW 3 - Case Summary & Kill Chain Matrix */}
                <Card title="Investigation Case Summary" icon={Briefcase} className="col-span-12 lg:col-span-4 min-h-[400px]">
                  <div className="h-full overflow-y-auto custom-scrollbar pr-2 space-y-4">
                    {cases.slice(0, 5).map(c => (
                      <div key={c.id} className="p-4 bg-white/3 border border-border rounded-lg group hover:border-blue-500/50 transition-all cursor-pointer">
                        <div className="flex justify-between items-start mb-2">
                          <span className="text-[10px] font-bold text-blue-500 font-mono tracking-tighter">{c.id}</span>
                          <span className={cn(
                            "px-2 py-0.5 rounded text-[9px] font-black uppercase",
                            c.status === CaseStatus.OPEN ? "bg-red-500/10 text-red-500 border border-red-500/20" : "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                          )}>
                            {c.status}
                          </span>
                        </div>
                        <h4 className="text-[12px] font-bold text-white mb-1 group-hover:text-blue-400 transition-colors uppercase tracking-tight">{c.title}</h4>
                        <p className="text-[11px] text-text-dim line-clamp-2 leading-relaxed opacity-60">{c.summary}</p>
                      </div>
                    ))}
                    {cases.length === 0 && (
                      <div className="h-full flex flex-col items-center justify-center text-text-dim opacity-50 italic text-[11px]">
                         No active investigation cases.
                      </div>
                    )}
                  </div>
                </Card>

                <Card title="Network Attack Kill Chain Matrix" icon={Crosshair} className="col-span-12 lg:col-span-8 min-h-[400px]">
                    <div className="h-full overflow-hidden">
                       <MitreMatrixView alerts={alerts} onSelectTechnique={() => {}} />
                    </div>
                </Card>

                {/* ROW 4 - Resolved External Sites */}
                <Card title="Resolved External Sites" icon={Globe} className="col-span-12 min-h-[300px]">
                   <div className="w-full overflow-x-auto custom-scrollbar pb-2">
                    <table className="w-full text-left border-collapse text-[11px]">
                      <thead>
                        <tr className="text-text-dim/60 font-bold border-b border-border uppercase text-[10px] tracking-widest">
                          <th className="pb-3 px-2">Hostname</th>
                          <th className="pb-3 px-2">Remote IP</th>
                          <th className="pb-3 px-2">Process</th>
                          <th className="pb-3 px-2 text-right">PID</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(data?.sites || []).slice(0, 10).map((site, i) => (
                          <tr key={`${site.hostname}-${i}`} className="border-b border-white/5 hover:bg-white/2 transition-colors">
                            <td className="py-3 px-2 text-blue-400 font-bold">{site.hostname}</td>
                            <td className="py-3 px-2 text-text-dim font-mono">{site.remote_ip}</td>
                            <td className="py-3 px-2 text-white/90">{site.process}</td>
                            <td className="py-3 px-2 text-right text-text-dim font-mono">{site.pid}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              </div>
            </motion.div>
          )}

          {activeTab === 'host' && (
            <motion.div 
               key="host"
               initial={{ opacity: 0, scale: 0.98 }}
               animate={{ opacity: 1, scale: 1 }}
               exit={{ opacity: 0, scale: 0.98 }}
               className="h-full p-6 overflow-y-auto custom-scrollbar space-y-6"
            >
              <div className="max-w-6xl mx-auto space-y-6">
                <div className="flex items-center justify-between">
                   <div className="flex items-center gap-3">
                      <div className="p-3 bg-blue-500/10 rounded-xl border border-blue-500/20">
                         <Cpu className="text-blue-400" size={24} />
                      </div>
                      <div>
                         <h2 className="text-xl font-black text-white uppercase tracking-tighter">Host Deep Dive</h2>
                         <p className="text-xs text-text-dim font-mono">{deepDive?.os?.hostname || 'Unknown'} • {deepDive?.os?.distro || 'Unknown'} {deepDive?.os?.release || ''}</p>
                      </div>
                   </div>
                   <div className="flex gap-4">
                      <div className="bg-white/5 px-4 py-2 rounded-lg border border-white/5 flex flex-col items-end">
                         <span className="text-[10px] text-text-dim uppercase font-bold">Uptime</span>
                         <span className="text-sm font-mono text-white">{Math.floor((deepDive?.uptime || 0) / 3600)}h {Math.floor(((deepDive?.uptime || 0) % 3600) / 60)}m</span>
                      </div>
                      <div className="bg-white/5 px-4 py-2 rounded-lg border border-white/5 flex flex-col items-end">
                         <span className="text-[10px] text-text-dim uppercase font-bold">Kernel</span>
                         <span className="text-sm font-mono text-white">{deepDive?.os?.kernel || 'Unknown'}</span>
                      </div>
                   </div>
                </div>

                <div className="grid grid-cols-12 gap-6">
                   {/* CPU Panel */}
                   <Card title="Processor Intelligence" icon={Cpu} className="col-span-12 lg:col-span-8 overflow-hidden">
                      <div className="space-y-6">
                         <div className="flex justify-between items-end">
                            <div>
                               <div className="text-2xl font-black text-white">{deepDive?.cpu?.brand || 'Unknown CPU'}</div>
                               <div className="text-[10px] text-text-dim font-mono uppercase">{deepDive?.cpu?.cores || 0} Cores • {deepDive?.cpu?.speed || 0} GHz • {deepDive?.cpu?.manufacturer || 'Unknown'}</div>
                            </div>
                            <div className="text-right">
                               <div className="text-4xl font-black text-blue-400">{Math.round(deepDive?.cpu?.load || 0)}%</div>
                               <div className="text-[10px] text-text-dim font-mono uppercase">Current Load</div>
                            </div>
                         </div>
                         
                         <div className="grid grid-cols-4 md:grid-cols-8 gap-2">
                            {deepDive?.cpu?.loadByCore?.map((load, i) => (
                               <div key={i} className="bg-white/5 p-2 rounded border border-white/5 flex flex-col items-center gap-2">
                                  <div className="h-16 w-1 bg-white/10 rounded-full relative overflow-hidden">
                                     <motion.div 
                                        initial={{ height: 0 }}
                                        animate={{ height: `${load}%` }}
                                        className="absolute bottom-0 w-full bg-blue-500 shadow-[0_0_10px_rgba(59,130,246,0.5)]" 
                                     />
                                  </div>
                                  <span className="text-[8px] font-mono text-text-dim">C{i}</span>
                               </div>
                            ))}
                         </div>
                      </div>
                   </Card>

                   {/* Thermals & Health */}
                   <Card title="System Health" icon={Zap} className="col-span-12 lg:col-span-4">
                      <div className="space-y-5">
                         <div className="flex justify-between items-center bg-white/5 p-3 rounded border border-white/5">
                            <span className="text-[10px] font-bold text-text-dim uppercase">Core Thermal</span>
                            <span className={cn(
                               "text-lg font-mono font-bold",
                               (deepDive?.cpu?.temperature || 0) > 80 ? "text-red-400" : "text-green-400"
                            )}>{deepDive?.cpu?.temperature ? `${deepDive.cpu.temperature}°C` : 'N/A'}</span>
                         </div>
                         <div className="flex justify-between items-center bg-white/5 p-3 rounded border border-white/5">
                            <span className="text-[10px] font-bold text-text-dim uppercase">Process Count</span>
                            <span className="text-lg font-mono font-bold text-blue-400">{deepDive?.cpu?.processors || 0}</span>
                         </div>
                         <div className="flex justify-between items-center bg-white/5 p-3 rounded border border-white/5">
                            <span className="text-[10px] font-bold text-text-dim uppercase">Architecture</span>
                            <span className="text-lg font-mono font-bold text-white uppercase">{deepDive?.os?.arch || 'Unknown'}</span>
                         </div>
                      </div>
                   </Card>

                   {/* Memory Layout */}
                   <Card title="Memory Allocation" icon={Activity} className="col-span-12 lg:col-span-5">
                      <div className="space-y-6">
                         <div className="flex justify-between items-end">
                            <div className="text-3xl font-black text-white">{formatBytes(deepDive?.memory?.used || 0)}</div>
                            <div className="text-xs text-text-dim font-bold uppercase tracking-wider">/ {formatBytes(deepDive?.memory?.total || 0)} Used</div>
                         </div>
                         <div className="h-3 bg-white/5 rounded-full overflow-hidden flex">
                            <div className="h-full bg-blue-500" style={{ width: `${((deepDive?.memory?.active || 0) / (deepDive?.memory?.total || 1)) * 100}%` }} />
                            <div className="h-full bg-blue-800" style={{ width: `${(((deepDive?.memory?.used || 0) - (deepDive?.memory?.active || 0)) / (deepDive?.memory?.total || 1)) * 100}%` }} />
                         </div>
                         <div className="grid grid-cols-2 gap-4 text-[10px] font-mono">
                            <div className="flex items-center gap-2">
                               <div className="w-2 h-2 rounded-full bg-blue-500" />
                               <span className="text-text-dim">Active:</span>
                               <span className="text-white">{formatBytes(deepDive?.memory?.active || 0)}</span>
                            </div>
                            <div className="flex items-center gap-2">
                               <div className="w-2 h-2 rounded-full bg-blue-800" />
                               <span className="text-text-dim">Cached:</span>
                               <span className="text-white">{formatBytes((deepDive?.memory?.used || 0) - (deepDive?.memory?.active || 0))}</span>
                            </div>
                            <div className="flex items-center gap-2">
                               <div className="w-2 h-2 rounded-full bg-white/10" />
                               <span className="text-text-dim">Free:</span>
                               <span className="text-white">{formatBytes(deepDive?.memory?.free || 0)}</span>
                            </div>
                            <div className="flex items-center gap-2 font-bold">
                               <div className="w-2 h-2 rounded-full bg-orange-500" />
                               <span className="text-text-dim">Swap:</span>
                               <span className="text-orange-400">{formatBytes(deepDive?.memory?.swapused || 0)}</span>
                            </div>
                         </div>
                      </div>
                   </Card>

                   {/* Storage Entities */}
                   <Card title="File Systems" icon={Server} className="col-span-12 lg:col-span-7">
                      <div className="overflow-x-auto">
                         <table className="w-full text-left">
                            <thead>
                               <tr className="text-[10px] font-black uppercase text-text-dim border-b border-white/5">
                                  <th className="pb-3">Mount</th>
                                  <th className="pb-3">Size</th>
                                  <th className="pb-3">Used</th>
                                  <th className="pb-3 text-right">In-Use %</th>
                               </tr>
                            </thead>
                            <tbody className="text-[11px] font-mono">
                               {deepDive?.storage?.map(d => (
                                  <tr key={d.mount} className="border-b border-white/2 hover:bg-white/2">
                                     <td className="py-3 text-white font-bold">{d.mount}</td>
                                     <td className="py-3 text-text-dim">{formatBytes(d.size)}</td>
                                     <td className="py-3 text-text-dim">{formatBytes(d.used)}</td>
                                     <td className="py-3 text-right">
                                        <div className="flex items-center justify-end gap-3">
                                           <div className="w-16 h-1 bg-white/5 rounded-full overflow-hidden">
                                              <div className={cn(
                                                 "h-full rounded-full",
                                                 d.use > 80 ? "bg-red-500" : "bg-blue-500"
                                              )} style={{ width: `${d.use}%` }} />
                                           </div>
                                           <span className={cn(
                                              "font-black",
                                              d.use > 80 ? "text-red-400" : "text-white"
                                           )}>{d.use}%</span>
                                        </div>
                                     </td>
                                  </tr>
                               ))}
                            </tbody>
                         </table>
                      </div>
                   </Card>

                   {/* Network Interfaces */}
                   <Card title="Interface Matrix" icon={Globe} className="col-span-12">
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                         {deepDive?.network?.filter(n => n.ip4).map(n => (
                            <div key={n.iface} className="bg-white/2 border border-white/5 p-4 rounded-lg space-y-4">
                               <div className="flex justify-between items-start">
                                  <div className="p-2 bg-blue-500/10 rounded border border-blue-500/20">
                                     <Zap size={14} className="text-blue-400" />
                                  </div>
                                  <div className="text-right">
                                     <div className="text-xs font-black text-white">{n.iface}</div>
                                     <div className="text-[9px] text-text-dim font-mono uppercase">{n.speed} Mbps</div>
                                  </div>
                               </div>
                               <div className="space-y-1">
                                  <div className="text-[10px] text-text-dim uppercase font-bold">IPv4 Address</div>
                                  <div className="text-sm font-mono text-white">{n.ip4}</div>
                               </div>
                               <div className="space-y-1">
                                  <div className="text-[10px] text-text-dim uppercase font-bold">MAC Entity</div>
                                  <div className="text-[11px] font-mono text-white/60">{n.mac}</div>
                               </div>
                               <div className="flex items-center gap-2 pt-2 border-t border-white/5">
                                  <div className={cn("w-1.5 h-1.5 rounded-full animate-pulse", n.dhcp ? "bg-green-500" : "bg-blue-500")} />
                                  <span className="text-[9px] font-mono text-text-dim uppercase">{n.dhcp ? 'DHCP PERSISTENT' : 'STATIC ASSIGN'}</span>
                               </div>
                            </div>
                         ))}
                      </div>
                   </Card>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'connections' && (
            <motion.div 
               key="connections"
               initial={{ opacity: 0, scale: 0.98 }}
               animate={{ opacity: 1, scale: 1 }}
               exit={{ opacity: 0, scale: 0.98 }}
               className="h-full p-6 flex flex-col gap-6"
            >
              <Card title="Full Active Connection List" icon={Zap} className="flex-grow">
                <div className="h-full overflow-y-auto custom-scrollbar pr-2">
                  <table className="w-full text-left font-mono text-[11px] border-collapse">
                    <thead className="sticky top-0 bg-card z-10">
                      <tr className="text-text-dim/60 font-black border-b border-border uppercase text-[10px] tracking-widest opacity-80">
                        <th className="pb-4 pt-0 px-3">Process</th>
                        <th className="pb-4 pt-0 px-3">PID</th>
                        <th className="pb-4 pt-0 px-3">Remote Host</th>
                        <th className="pb-4 pt-0 px-3">Remote IP</th>
                        <th className="pb-4 pt-0 px-3 text-right">R-Port</th>
                        <th className="pb-4 pt-0 px-3 text-right">L-Port</th>
                        <th className="pb-4 pt-0 px-3">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {(data?.connections || []).map((c, i) => (
                        <tr key={`${c.pid}-${i}`} className={cn("hover:bg-white/2 transition-colors", c.status === "ESTABLISHED" && "bg-blue-500/5")}>
                          <td className="py-4 px-3 font-bold text-white uppercase tracking-tight">{c.process}</td>
                          <td className="py-4 px-3 text-text-dim/80">{c.pid}</td>
                          <td className="py-4 px-3 text-white truncate max-w-[150px] font-bold">{(data?.sites || []).find(s => s.remote_ip === c.remote_ip)?.hostname || "-"}</td>
                          <td className="py-4 px-3 text-text-dim group flex items-center justify-between">
                             <span className="font-mono">{c.remote_ip || "*"}</span>
                             {c.remote_ip && (
                               <button 
                                 onClick={() => setActionModal({
                                   show: true,
                                   type: 'BLOCK_IP',
                                   target: c.remote_ip,
                                   triggeredBy: 'MANUAL (Connections Tab)'
                                 })}
                                 className="opacity-0 group-hover:opacity-100 p-1.5 hover:bg-red-500/20 text-red-500 rounded transition-all border border-red-500/30"
                               >
                                  <ShieldAlert size={14} />
                                </button>
                             )}
                          </td>
                          <td className="py-4 px-3 text-right text-text-dim/80 font-mono">{c.remote_port || "-"}</td>
                          <td className="py-4 px-3 text-right text-text-dim/80 font-mono">{c.local_port || "-"}</td>
                          <td className="py-4 px-3">
                            <span className={cn(
                              "text-[9px] font-black px-2 py-0.5 rounded-full uppercase tracking-widest border",
                              c.status === "ESTABLISHED" ? "bg-green-500/10 text-green-400 border-green-500/20" : 
                              c.status === "LISTEN" ? "bg-blue-500/10 text-blue-400 border-blue-500/20" : "bg-white/5 text-text-dim border-border/50"
                            )}>{c.status}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </motion.div>
          )}

          {activeTab === 'devices' && (
            <motion.div 
               key="devices"
               className="h-full p-6 grid grid-cols-12 gap-6"
            >
              <div className="col-span-12 lg:col-span-8 flex flex-col gap-6 overflow-y-auto custom-scrollbar pr-3 h-full pb-10">
                {mode === 'local' ? (
                  <div className="flex-grow flex items-center justify-center border-2 border-dashed border-border rounded-xl min-h-[300px]">
                    <div className="text-center">
                      <Globe size={48} className="mx-auto mb-4 text-text-dim opacity-20" />
                      <p className="text-sm text-text-dim font-medium">Enable Sentinel Mode to see other devices</p>
                      <button onClick={() => setMode('network')} className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg text-xs font-bold uppercase tracking-wider">Activate Sentinel</button>
                    </div>
                  </div>
                ) : devices.length === 0 ? (
                  <div className="flex-grow flex flex-col items-center justify-center border-2 border-dashed border-border rounded-xl min-h-[300px]">
                    <AlertCircle size={48} className="mb-4 text-amber-500 opacity-50" />
                    <p className="text-sm text-text-dim font-medium">No devices discovered on segment.</p>
                    <p className="text-[10px] text-text-dim mt-2 max-w-xs text-center">Ensure the backend has appropriate network capture permissions.</p>
                    <button className="mt-6 flex items-center gap-2 px-4 py-2 bg-gray-800 text-white rounded-lg text-xs font-bold uppercase" onClick={() => window.location.reload()}>
                      <Activity size={14} /> Re-scan Segment
                    </button>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Sort devices: Watched first */}
                    {[...devices].sort((a, b) => {
                      const aWatched = watchedDeviceIds.includes(a.id);
                      const bWatched = watchedDeviceIds.includes(b.id);
                      if (aWatched && !bWatched) return -1;
                      if (!aWatched && bWatched) return 1;
                      return 0;
                    }).map(device => {
                      const isWatched = watchedDeviceIds.includes(device.id);
                      const isArmoured = armouredDeviceId === device.id;
                      
                      return (
                        <motion.div 
                          key={device.id}
                          layout
                          className={cn(
                            "bg-card border p-6 rounded-lg transition-all relative overflow-hidden",
                            selectedDeviceId === device.id ? "border-gray-500 shadow-[0_0_20px_rgba(59,130,246,0.1)]" : "border-border hover:border-gray-600",
                            isWatched && "border-l-4 border-l-blue-600",
                            isArmoured && "border-l-4 border-l-green-600",
                            (device.recon_score || 0) > 70 && "border-r-4 border-r-red-500",
                            (device.beacon_score || 0) > 70 && "border-r-4 border-r-orange-500"
                          )}
                        >
                          <div className="flex justify-between items-start mb-3">
                            <div className="cursor-pointer" onClick={() => setSelectedDeviceId(selectedDeviceId === device.id ? null : device.id)}>
                              <div className="flex items-center gap-2">
                                <h3 className="text-lg font-bold text-white leading-tight">{device.hostname}</h3>
                                {isWatched && (
                                  <span className="bg-blue-600 text-white text-[8px] font-black px-1.5 py-0.5 rounded flex items-center gap-1 uppercase tracking-tighter animate-pulse">
                                    <Eye size={8} /> Watching
                                  </span>
                                )}
                                {isArmoured && (
                                  <span className="bg-green-600 text-white text-[8px] font-black px-1.5 py-0.5 rounded flex items-center gap-1 uppercase tracking-tighter">
                                    <Lock size={8} /> Sentinel Active
                                  </span>
                                )}
                                {device.is_vm && (
                                  <span className="bg-purple-600 text-white text-[8px] font-black px-1.5 py-0.5 rounded uppercase tracking-tighter flex items-center gap-1 shadow-sm">
                                    <Terminal size={8} /> VM: {device.hypervisor}
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center gap-2 text-[10px] text-text-dim font-mono mt-1">
                                 <span>{device.ip}</span>
                                 <span className="opacity-30">|</span>
                                 <span>{device.mac}</span>
                              </div>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                               {device.alertCount > 0 && <span className="bg-red-500 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-full">{device.alertCount}</span>}
                               <button 
                                 onClick={(e) => {
                                   e.stopPropagation();
                                   setSelectedDeviceId(selectedDeviceId === device.id ? null : device.id);
                                 }}
                                 className={cn(
                                   "p-1.5 rounded bg-white/5 hover:bg-white/10 transition-all",
                                   selectedDeviceId === device.id ? "text-blue-400 rotate-180" : "text-text-dim"
                                 )}
                               >
                                 <ChevronDown size={14} />
                               </button>
                               <div className={cn(
                                 "w-2 h-2 rounded-full",
                                 device.status === 'active' || (device.threat_score || 0) < 10 ? "bg-green-500" : (device.status === 'amber' || (device.threat_score || 0) < 60) ? "bg-amber-500" : "bg-red-500"
                               )} />
                            </div>
                          </div>

                          {/* Threat Badges */}
                          <div className="flex items-center gap-2 mb-3">
                            {(device.recon_score || 0) > 70 && (
                              <div className="bg-red-500/20 text-red-500 border border-red-500/30 px-1.5 py-0.5 rounded font-black text-[7px] uppercase tracking-[0.1em] animate-pulse">
                                ⚠ Scanner Detected
                              </div>
                            )}
                            {(device.beacon_score || 0) > 70 && (
                              <div className="bg-orange-500/20 text-orange-500 border border-orange-500/30 px-1.5 py-0.5 rounded font-black text-[7px] uppercase tracking-[0.1em] animate-pulse">
                                ⚠ Beaconing Active
                              </div>
                            )}
                            {device.os && (
                               <div className="text-[7px] font-bold text-text-dim/60 uppercase border border-white/5 px-1 rounded flex items-center gap-1">
                                  <Cpu size={6} /> OS: {device.os}
                               </div>
                            )}
                          </div>

                          <div className="grid grid-cols-2 gap-4 mb-4 text-[10px] uppercase font-bold text-text-dim bg-white/2 p-2 rounded">
                             <div className="flex flex-col">
                                <span className="text-[8px] opacity-60">Session Sent</span>
                                <span className="text-white font-mono flex items-center gap-1">
                                  <ArrowUp size={10} className="text-orange-400" />
                                  {formatBytes(device.sent)}
                                </span>
                             </div>
                             <div className="flex flex-col">
                                <span className="text-[8px] opacity-60">Session Recv</span>
                                <span className="text-white font-mono flex items-center gap-1">
                                  <ArrowDown size={10} className="text-blue-400" />
                                  {formatBytes(device.recv)}
                                </span>
                             </div>
                          </div>

                          <div className="flex flex-wrap gap-1 mb-4">
                             {device.protocols.map(p => (
                               <span key={p} className="bg-white/5 border border-border/50 px-2 py-0.5 rounded-full text-[8px] font-bold text-text-dim uppercase tracking-wider">{p}</span>
                             ))}
                          </div>

                          <AnimatePresence>
                            {selectedDeviceId === device.id && (
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: 'auto', opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                className="overflow-hidden"
                              >
                                <div className="mt-4 pt-4 border-t border-white/5 space-y-4">
                                  <div className="h-24 w-full bg-white/2 rounded p-2">
                                     <div className="text-[8px] uppercase font-bold text-text-dim mb-1 flex justify-between">
                                        <span>Real-time Traffic Activity</span>
                                        <span className="text-blue-400">Live Analytics</span>
                                     </div>
                                     <ResponsiveContainer width="100%" height="100%">
                                        <AreaChart data={device.activity.map((val, i) => ({ val, i }))}>
                                           <defs>
                                              <linearGradient id={`grad-${device.id}`} x1="0" y1="0" x2="0" y2="1">
                                                 <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                                                 <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                                              </linearGradient>
                                           </defs>
                                           <Area 
                                              type="monotone" 
                                              dataKey="val" 
                                              stroke="#3b82f6" 
                                              strokeWidth={2} 
                                              fill={`url(#grad-${device.id})`} 
                                              isAnimationActive={false} 
                                           />
                                        </AreaChart>
                                     </ResponsiveContainer>
                                  </div>

                                  <div className="grid grid-cols-3 gap-2">
                                     <div className="bg-white/5 p-2 rounded">
                                        <div className="text-[7px] text-text-dim uppercase font-bold mb-1">Risk Score</div>
                                        <div className="text-xs font-mono text-white">{(device.threat_score || 2).toFixed(1)}%</div>
                                     </div>
                                     <div className="bg-white/5 p-2 rounded">
                                        <div className="text-[7px] text-text-dim uppercase font-bold mb-1">Baseline</div>
                                        <div className="text-xs font-mono text-green-400">NORMAL</div>
                                     </div>
                                     <div className="bg-white/5 p-2 rounded">
                                        <div className="text-[7px] text-text-dim uppercase font-bold mb-1">GMM Status</div>
                                        <div className="text-xs font-mono text-blue-400 flex items-center gap-1">
                                           <span className="w-1 h-1 rounded-full bg-blue-400 animate-pulse" />
                                           SENSING
                                        </div>
                                     </div>
                                  </div>
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>

                          <div className="grid grid-cols-2 gap-2 mt-4 pt-3 border-t border-white/5">
                              <button 
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setActionModal({
                                    show: true,
                                    type: 'WATCH_DEVICE',
                                    target: device.hostname,
                                    triggeredBy: 'MANUAL (Devices Tab)'
                                  });
                                }}
                                className={cn(
                                 "flex items-center justify-center gap-1.5 py-1.5 rounded text-[9px] font-bold uppercase tracking-widest transition-all",
                                 isWatched ? "bg-blue-600/10 text-blue-400 border border-blue-600/50" : "border border-blue-500/30 text-blue-400/70 hover:bg-blue-500/10 hover:text-blue-400"
                               )}
                             >
                                {isWatched ? <EyeOff size={10} /> : <Eye size={10} />}
                                {isWatched ? "Stop Watch" : "Watch"}
                             </button>
                             <button 
                               onClick={(e) => {
                                 e.stopPropagation();
                                 setActionModal({
                                   show: true,
                                   type: 'ISOLATE',
                                   target: device.hostname,
                                   triggeredBy: 'MANUAL (Devices Tab)'
                                 });
                               }}
                               className={cn(
                                 "flex items-center justify-center gap-1.5 py-1.5 rounded text-[9px] font-bold uppercase tracking-widest transition-all",
                                 isArmoured ? "bg-green-600/10 text-green-400 border border-green-600/50" : "border border-green-500/30 text-green-400/70 hover:bg-green-500/10 hover:text-green-400"
                               )}
                             >
                                <Lock size={10} />
                                {isArmoured ? "Isolated" : "Isolate"}
                             </button>
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>
                )}

                {/* Active Host Nodes Section */}
                {mode === 'network' && (
                  <div className="mt-8 border-t border-border pt-8">
                    <div className="flex items-center justify-between mb-4">
                       <h3 className="text-xs font-black uppercase tracking-[0.2em] text-white flex items-center gap-2">
                          <Cpu size={14} className="text-blue-400" />
                          Host Systems & Endpoints
                       </h3>
                       <span className="text-[9px] text-text-dim font-mono">{vms.length} DETECTED</span>
                    </div>

                    {vms.length === 0 ? (
                      <div className="bg-white/2 border border-dashed border-border p-8 rounded-lg text-center">
                         <p className="text-[10px] text-text-dim italic leading-relaxed max-w-sm mx-auto">
                            No local VMs detected. VMs appear here automatically when their virtual network adapters are discovered on the network segment.
                         </p>
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                          {vms.map(vm => (
                            <div key={vm.id} className={cn(
                              "bg-card border border-border p-3 rounded flex flex-col gap-3 group transition-colors",
                              selectedVmId === vm.id ? "border-blue-500/50 shadow-lg" : "hover:border-gray-600"
                            )}>
                               <div className="flex justify-between items-start">
                                  <div className="cursor-pointer flex-grow" onClick={() => setSelectedVmId(selectedVmId === vm.id ? null : vm.id)}>
                                     <h4 className="text-xs font-bold text-white mb-1 flex items-center gap-2">
                                        {vm.name}
                                        {selectedVmId === vm.id && <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />}
                                     </h4>
                                     <div className="flex items-center gap-1.5 text-[9px] text-text-dim font-mono">
                                        <span className="bg-blue-500/10 text-blue-400 px-1 rounded">{vm.hypervisor}</span>
                                        <span>{vm.ip}</span>
                                     </div>
                                  </div>
                                  <div className="flex items-center gap-2">
                                     <div className={cn(
                                       "px-1.5 py-0.5 rounded text-[8px] font-black",
                                       vm.status === 'RUNNING' ? "bg-green-500/20 text-green-400" : "bg-gray-500/20 text-gray-400"
                                     )}>{vm.status}</div>
                                     <button 
                                       onClick={() => setSelectedVmId(selectedVmId === vm.id ? null : vm.id)}
                                       className={cn(
                                         "p-1 rounded bg-white/5 hover:bg-white/10 transition-all",
                                         selectedVmId === vm.id ? "text-blue-400 rotate-180" : "text-text-dim"
                                       )}
                                     >
                                       <ChevronDown size={12} />
                                     </button>
                                  </div>
                               </div>
                               
                               <AnimatePresence>
                                  {selectedVmId === vm.id && (
                                    <motion.div
                                      initial={{ height: 0, opacity: 0 }}
                                      animate={{ height: 'auto', opacity: 1 }}
                                      exit={{ height: 0, opacity: 0 }}
                                      className="overflow-hidden space-y-3"
                                    >
                                       <div className="pt-2 border-t border-white/5 space-y-2">
                                          <div className="flex justify-between items-center text-[8px] font-black uppercase text-text-dim tracking-widest">
                                             <span>Hypervisor Resource Allocation</span>
                                             <span className="text-blue-400 font-mono">Real-time</span>
                                          </div>
                                          <div className="grid grid-cols-2 gap-2">
                                             <div className="bg-white/5 p-2 rounded border border-white/5">
                                                <div className="text-[7px] text-text-dim uppercase font-bold mb-1">CPU Load</div>
                                                <div className="flex items-center gap-2">
                                                   <div className="flex-grow h-1 bg-white/10 rounded-full overflow-hidden">
                                                      <div className="h-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]" style={{ width: `${vm.cpu || 0}%` }} />
                                                   </div>
                                                   <span className="text-[9px] font-mono text-white">{vm.cpu || 0}%</span>
                                                </div>
                                             </div>
                                             <div className="bg-white/5 p-2 rounded border border-white/5">
                                                <div className="text-[7px] text-text-dim uppercase font-bold mb-1">Memory</div>
                                                <div className="flex items-center gap-2">
                                                   <div className="flex-grow h-1 bg-white/10 rounded-full overflow-hidden">
                                                      <div className="h-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]" style={{ width: `${vm.memory || 0}%` }} />
                                                   </div>
                                                   <span className="text-[9px] font-mono text-white">{vm.memory || 0}%</span>
                                                </div>
                                             </div>
                                          </div>
                                       </div>

                                       <div className="bg-blue-500/5 border border-blue-500/20 p-2 rounded space-y-1 mt-2">
                                          <div className="text-[7px] font-black uppercase text-blue-400 tracking-tighter flex items-center gap-1">
                                             <Activity size={8} /> Interface Diagnostics
                                          </div>
                                          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[9px] font-mono">
                                             <div className="flex justify-between text-text-dim"><span>vNIC Path</span> <span className="text-white">veth77a21</span></div>
                                             <div className="flex justify-between text-text-dim"><span>MTU</span> <span className="text-white">1500</span></div>
                                             <div className="flex justify-between text-text-dim"><span>Errors</span> <span className="text-green-500">0</span></div>
                                             <div className="flex justify-between text-text-dim"><span>Drops</span> <span className="text-green-500">0</span></div>
                                          </div>
                                       </div>
                                       
                                       <div className="text-[8px] text-text-dim italic leading-tight uppercase font-bold text-center border-t border-white/5 pt-2 opacity-50">
                                          Retrieve-ing telemetry data directly from host hypervisor tap.
                                       </div>
                                    </motion.div>
                                  )}
                               </AnimatePresence>

                               <div className="grid grid-cols-2 gap-2 text-[9px] font-mono text-text-dim">
                                  <div className="flex justify-between border-b border-white/5 pb-1">
                                     <span>Sent</span>
                                     <span className="text-white">{formatBytes(vm.sent)}</span>
                                  </div>
                                  <div className="flex justify-between border-b border-white/5 pb-1">
                                     <span>Recv</span>
                                     <span className="text-white">{formatBytes(vm.recv)}</span>
                                  </div>
                               </div>
                               <button className="w-full py-1.5 bg-white/5 hover:bg-blue-600 hover:text-white border border-white/10 rounded text-[9px] font-bold uppercase tracking-widest transition-all">
                                  Watch VM
                               </button>
                            </div>
                          ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className="col-span-12 lg:col-span-4 flex flex-col gap-3 h-full overflow-hidden">
                <Card title="Network Map" icon={Globe} className="flex-grow h-[300px]">
                   <div className="w-full h-full bg-white/2 rounded-[2px] flex items-center justify-center p-4">
                      {mode === 'network' && matrix ? (
                        <svg className="w-full h-full" viewBox="0 0 100 100">
                          {/* Links */}
                          {matrix.links.map((link, i) => {
                            const source = matrix.nodes.find(n => n.id === link.source);
                            const target = matrix.nodes.find(n => n.id === link.target);
                            if (!source || !target) return null;
                            const si = matrix.nodes.indexOf(source);
                            const ti = matrix.nodes.indexOf(target);
                            const sx = 20 + (si % 2) * 60;
                            const sy = 20 + Math.floor(si / 2) * 60;
                            const tx = 20 + (ti % 2) * 60;
                            const ty = 20 + Math.floor(ti / 2) * 60;
                            return (
                              <line key={i} x1={sx} y1={sy} x2={tx} y2={ty} stroke="#3b82f6" strokeWidth={link.value / 10} strokeOpacity={0.4} />
                            );
                          })}
                          {/* Nodes */}
                          {matrix.nodes.map((node, i) => {
                            const isWatched = watchedDeviceIds.includes(node.id);
                            const x = 20 + (i % 2) * 60;
                            const y = 20 + Math.floor(i / 2) * 60;
                            return (
                              <g key={node.id} className="cursor-pointer">
                                {isWatched && (
                                  <motion.circle 
                                    cx={x} cy={y} r="10" 
                                    fill="transparent" 
                                    stroke="#3b82f6" 
                                    strokeWidth="1"
                                    animate={{ scale: [1, 1.5, 1], opacity: [0.5, 0, 0.5] }}
                                    transition={{ duration: 2, repeat: Infinity }}
                                  />
                                )}
                                <circle 
                                  cx={x} cy={y} r="6" 
                                  fill="#0f172a" 
                                  stroke={isWatched ? "#3b82f6" : "#475569"} 
                                  strokeWidth={isWatched ? "2" : "1"} 
                                />
                                <text x={x} y={y + 12} textAnchor="middle" fill={isWatched ? "#3b82f6" : "#94a3b8"} fontSize="4" fontWeight="bold">{node.label}</text>
                              </g>
                            );
                          })}
                        </svg>
                      ) : (
                        <div className="text-[10px] text-text-dim text-center italic flex flex-col items-center gap-2">
                           <Globe size={24} className="opacity-20" />
                           {mode === 'network' ? "No devices on network segment yet" : "Map visualization available in Sentinel mode"}
                        </div>
                      )}
                   </div>
                </Card>

                {mode === 'network' && selectedDeviceId ? (
                   <motion.div 
                     initial={{ opacity: 0, x: 20 }}
                     animate={{ opacity: 1, x: 0 }}
                     className="bg-card border border-border p-4 rounded-[4px] flex flex-col gap-4"
                   >
                      <div className="flex justify-between items-center pb-3 border-b border-white/5 mb-4">
                        <h4 className="text-xs font-bold text-white uppercase tracking-wider">Device Detail</h4>
                        <button onClick={() => setSelectedDeviceId(null)} className="text-text-dim hover:text-white">✕</button>
                     </div>
                                <div className="flex border-b border-white/5 mb-6 px-1 gap-6">
                        {(['flow', 'baseline', 'killchain', 'alerts'] as const).map(tab => (
                          <button
                            key={tab}
                            onClick={() => setDeviceDetailTab(tab)}
                            className={cn(
                              "pb-2 text-[10px] font-bold uppercase tracking-widest transition-all border-b-2",
                              deviceDetailTab === tab ? "border-blue-500 text-blue-400" : "border-transparent text-text-dim hover:text-white"
                            )}
                          >
                            {tab === 'killchain' ? 'Kill Chain' : tab.charAt(0).toUpperCase() + tab.slice(1)}
                            {(tab === 'killchain' || tab === 'baseline') && deviceKillChains[selectedDeviceId]?.current_stage !== 'NONE' && (
                               <span className="ml-1.5 w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                            )}
                          </button>
                        ))}
                     </div>

                     <div className="flex-grow overflow-y-auto custom-scrollbar pr-1">
                        <AnimatePresence mode="wait">
                          {deviceDetailTab === 'flow' && (
                             <motion.div key="flow" initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }} className="space-y-4 font-mono text-[11px]">
                                <div>
                                  <div className="text-text-dim text-[9px] uppercase mb-2 font-bold tracking-wider">Active Host Flows</div>
                                  <div className="space-y-2">
                                     {flows.filter(f => f.sourceIp === devices.find(d => d.id === selectedDeviceId)?.ip).length === 0 ? (
                                        <div className="text-[10px] text-text-dim italic bg-white/2 p-4 rounded border border-dashed border-border text-center">No active external flows detected</div>
                                     ) : flows.filter(f => f.sourceIp === devices.find(d => d.id === selectedDeviceId)?.ip).map((f, i) => (
                                       <div key={i} className="flex justify-between bg-white/2 p-2 rounded hover:bg-white/5 transition-colors group">
                                         <div>
                                           <div className="text-white truncate max-w-[150px] font-bold">{f.destHostname}</div>
                                           <div className="text-[9px] text-text-dim font-mono">{f.destIp}:{f.port} <span className="opacity-30">|</span> {f.protocol}</div>
                                         </div>
                                         <div className="text-blue-400 font-bold self-center">{formatBytes(f.bytes)}</div>
                                       </div>
                                     ))}
                                  </div>
                                </div>
                             </motion.div>
                          )}

                          {deviceDetailTab === 'baseline' && (
                             <motion.div key="baseline" initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }}>
                                {selectedDeviceId && (
                                   <BaselineViewer 
                                     deviceId={selectedDeviceId} 
                                     onReset={(reason) => {
                                        fetch(`/api/devices/${selectedDeviceId}/baseline/reset`, {
                                          method: 'POST',
                                          headers: { 'Content-Type': 'application/json' },
                                          body: JSON.stringify({ reason })
                                        }).then(() => {
                                           alert("Baseline reset request logged to audit trail. Re-learning phase initiated.");
                                        });
                                     }}
                                   />
                                )}
                             </motion.div>
                          )}

                          {deviceDetailTab === 'alerts' && (
                             <motion.div key="alerts" initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }} className="space-y-4 font-mono text-[11px]">
                                <div>
                                  <div className="text-text-dim text-[9px] uppercase mb-2 font-bold tracking-wider">Device Security Alerts</div>
                                  {devices.find(d => d.id === selectedDeviceId)?.alertCount === 0 ? (
                                    <div className="bg-green-500/5 border border-dashed border-green-500/20 p-6 rounded-lg text-center flex flex-col items-center gap-2">
                                       <ShieldCheck className="text-green-500 opacity-50" size={24} />
                                       <span className="text-green-500/70 text-[10px]">No active security anomalies detected for this host.</span>
                                    </div>
                                  ) : (
                                    <div className="space-y-3">
                                       <div className="p-3 border border-red-500/30 bg-red-500/5 rounded text-red-400 group">
                                          <div className="flex items-center justify-between mb-1">
                                             <div className="flex items-center gap-2 font-bold uppercase tracking-tight">
                                                <AlertCircle size={10} />
                                                <span>Potential Credential Stuffing</span>
                                             </div>
                                             <span className="text-[8px] bg-red-500 text-white px-1 rounded font-black">HIGH</span>
                                          </div>
                                          <div className="text-[10px] text-text-dim leading-relaxed mb-3">Unusual frequency of TCP connection attempts on port 443 detected by GMM Layer.</div>
                                          <button className="w-full py-1.5 bg-red-500/10 hover:bg-red-500 hover:text-white rounded text-[9px] font-black uppercase transition-all border border-red-500/30">
                                            Acknowledge & Investigate
                                          </button>
                                       </div>
                                       <div className="p-3 border border-amber-500/30 bg-amber-500/5 rounded text-amber-500">
                                          <div className="flex items-center justify-between mb-1">
                                             <div className="flex items-center gap-2 font-bold uppercase tracking-tight">
                                                <History size={10} />
                                                <span>Session Duration Drift</span>
                                             </div>
                                             <span className="text-[8px] bg-amber-500 text-white px-1 rounded font-black">MED</span>
                                          </div>
                                          <div className="text-[10px] text-text-dim leading-relaxed">Average session duration increased by 400% over the last 24 hours. Detected by LOWESS Layer.</div>
                                       </div>
                                    </div>
                                  )}
                                </div>
                             </motion.div>
                          )}

                          {deviceDetailTab === 'killchain' && (
                             <motion.div key="killchain" initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }}>
                                {selectedDeviceId && deviceKillChains[selectedDeviceId] && (
                                   <div className="max-h-[600px] overflow-y-auto custom-scrollbar pr-2">
                                      <KillChainVisualizer 
                                        data={deviceKillChains[selectedDeviceId]} 
                                        onMarkFalsePositive={(stage) => console.log('False positive:', stage)}
                                        onClearStage={(stage) => {
                                           // Simulated local update
                                           setDeviceKillChains(prev => {
                                              const kc = prev[selectedDeviceId];
                                              if (!kc) return prev;
                                              const newStages = kc.stages.map(s => s.stage === stage ? { ...s, status: 'CLEARED' as const } : s);
                                              return { ...prev, [selectedDeviceId]: { ...kc, stages: newStages } };
                                           });
                                        }}
                                      />
                                   </div>
                                )}
                             </motion.div>
                          )}
                        </AnimatePresence>
                     </div>
                   </motion.div>
                ) : (
                   <div className="bg-card border border-border border-dashed p-12 rounded-[4px] text-center">
                      <Monitor size={24} className="mx-auto mb-3 text-text-dim opacity-20" />
                      <p className="text-[10px] text-text-dim">Select a device card to inspect detailed traffic flows</p>
                   </div>
                )}
              </div>
            </motion.div>
          )}

          {activeTab === 'alerts' && (
            <motion.div 
               key="alerts"
               initial={{ opacity: 0 }}
               animate={{ opacity: 1 }}
               exit={{ opacity: 0 }}
               className="h-full p-8 max-w-5xl mx-auto flex flex-col gap-8"
            >
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-black text-white flex items-center gap-4 tracking-tight uppercase">
                  <AlertCircle className="text-red-500" size={28} />
                  Security Alerts Archive
                </h2>
                <div className="flex items-center gap-2 bg-white/5 p-1.5 rounded-xl border border-border/50">
                   {['ALL', 'HIGH', 'MEDIUM', 'LOW', 'UNREAD', 'MITRE'].map(f => (
                     <button
                       key={f}
                       onClick={() => setAlertFilter(f as any)}
                       className={cn(
                         "px-3 py-1.5 rounded text-[9px] font-bold transition-all uppercase tracking-widest",
                         alertFilter === f ? "bg-white/10 text-white shadow-sm" : "text-text-dim hover:text-white"
                       )}
                     >
                       {f}
                     </button>
                   ))}
                </div>
              </div>

              {alertFilter === 'MITRE' ? (
                <div className="flex flex-col gap-4 overflow-hidden h-full">
                   <div className="bg-card border border-border p-4 rounded-lg overflow-hidden flex flex-col h-[500px]">
                      <div className="flex justify-between items-center mb-4">
                         <div className="flex items-center gap-2">
                            <span className="w-3 h-3 bg-red-500/50 border border-red-500 rounded-sm"></span>
                            <span className="text-[9px] text-text-dim uppercase font-bold">Confirmed Observation (2+)</span>
                            <span className="ml-4 w-3 h-3 bg-amber-500/50 border border-amber-500 rounded-sm"></span>
                            <span className="text-[9px] text-text-dim uppercase font-bold">Suspected (1)</span>
                         </div>
                      </div>
                      <div className="flex-grow overflow-auto custom-scrollbar">
                         <MitreMatrixView alerts={alerts} onSelectTechnique={(id, tactic) => setSelectedMitreTech({ id, tactic })} />
                      </div>
                   </div>

                   {/* Technique Detail Side Panel */}
                   <AnimatePresence>
                     {selectedMitreTech && (
                       <motion.div 
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 20 }}
                        className="fixed right-4 top-[120px] bottom-4 w-[350px] bg-card border border-gray-600 shadow-2xl rounded-lg z-50 flex flex-col overflow-hidden"
                       >
                          <div className="p-4 border-b border-white/10 flex justify-between items-center bg-blue-500/5">
                             <div>
                                <div className="text-[10px] text-blue-400 font-black uppercase tracking-widest">{selectedMitreTech.tactic}</div>
                                <h3 className="text-white font-bold text-sm">
                                   {selectedMitreTech.id}: {MITRE_FRAMEWORK.find(g => g.tactic === selectedMitreTech.tactic)?.techniques.find(t => t.id === selectedMitreTech.id)?.name}
                                </h3>
                             </div>
                             <button onClick={() => setSelectedMitreTech(null)} className="text-text-dim hover:text-white transition-colors">✕</button>
                          </div>
                          
                          <div className="p-4 flex-grow overflow-y-auto custom-scrollbar space-y-6">
                             <div>
                                <h4 className="text-[10px] text-text-dim uppercase font-bold mb-2">Description</h4>
                                <p className="text-xs text-white leading-relaxed">
                                   {MITRE_FRAMEWORK.find(g => g.tactic === selectedMitreTech.tactic)?.techniques.find(t => t.id === selectedMitreTech.id)?.desc}
                                </p>
                             </div>

                             <div>
                                <h4 className="text-[10px] text-text-dim uppercase font-bold mb-3 flex items-center gap-2">
                                   Observational Evidence ({alerts.filter(a => a.mitre_technique_id === selectedMitreTech.id).length})
                                </h4>
                                <div className="space-y-2">
                                   {alerts.filter(a => a.mitre_technique_id === selectedMitreTech.id).map(a => (
                                      <div key={a.id} className="p-2 bg-white/3 border border-white/5 rounded text-[10px] hover:bg-white/5 transition-all">
                                         <div className="flex justify-between mb-1">
                                            <span className="font-bold text-white uppercase">{a.type}</span>
                                            <span className="text-[8px] text-text-dim">{a.timestamp}</span>
                                         </div>
                                         <div className="text-text-dim mb-2">{a.description}</div>
                                         <div className="flex justify-between items-center pt-2 border-t border-white/5">
                                            <div className="flex items-center gap-1">
                                               <Monitor size={8} className="text-blue-400" />
                                               <span className="text-blue-400 font-black uppercase tracking-tight">{a.source.name}</span>
                                            </div>
                                            <div className={cn(
                                               "px-1 rounded font-black text-[8px]",
                                               a.severity === 'HIGH' ? "bg-red-500 text-white" : "bg-amber-500 text-white"
                                            )}>{a.severity}</div>
                                         </div>
                                      </div>
                                   ))}
                                   {alerts.filter(a => a.mitre_technique_id === selectedMitreTech.id).length === 0 && (
                                     <div className="py-8 text-center text-text-dim text-[10px] italic border border-dashed border-border rounded">
                                        No active observations for this technique in current dataset.
                                     </div>
                                   )}
                                </div>
                             </div>
                          </div>
                          
                          <div className="p-4 border-t border-white/10 bg-white/2">
                             <button className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white font-black text-[10px] uppercase tracking-widest rounded transition-all">
                                Download Full Attack Graph
                             </button>
                          </div>
                       </motion.div>
                     )}
                   </AnimatePresence>
                </div>
              ) : (
                <div className="space-y-3 overflow-y-auto custom-scrollbar pr-2 flex-grow">
                   {alerts
                     .filter(a => {
                       if (alertFilter === 'ALL') return true;
                       if (alertFilter === 'UNREAD') return !a.isRead;
                       return a.severity === alertFilter;
                     })
                     .map((alert) => (
                     <div 
                      key={alert.id} 
                      onClick={() => {
                        setAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, isRead: true } : a));
                      }}
                      className={cn(
                        "bg-card border p-4 rounded-[4px] relative overflow-hidden group transition-all cursor-pointer",
                        alert.isRead ? "border-border opacity-70" : "border-gray-500 shadow-md",
                        !alert.isRead && alert.severity === 'HIGH' && "border-red-500/50"
                      )}
                     >
                       <div className={cn(
                         "absolute left-0 top-0 bottom-0 w-1",
                         alert.severity === 'HIGH' ? "bg-red-500" : alert.severity === 'MEDIUM' ? "bg-amber-500" : "bg-blue-500"
                       )} />
                       
                       {!alert.isRead && (
                         <div className="absolute top-4 left-3 w-1.5 h-1.5 rounded-full bg-blue-500 shadow-[0_0_10px_rgba(59,130,246,0.8)]" />
                       )}
  
                       <div className="flex justify-between items-start pl-3">
                          <div className="flex-grow">
                            <div className="flex items-center gap-3 mb-2">
                              <span className={cn(
                                "text-[8px] font-black px-1.5 py-0.5 rounded uppercase tracking-tighter",
                                alert.severity === 'HIGH' ? "bg-red-500/20 text-red-500 border border-red-500/30" : 
                                alert.severity === 'MEDIUM' ? "bg-amber-500/20 text-amber-500 border border-amber-500/30" : 
                                "bg-blue-500/20 text-blue-500 border border-blue-500/30"
                              )}>{alert.severity}</span>
                              <span className="text-[10px] font-mono text-white font-bold">{alert.type}</span>
                              {alert.mitre_technique_id && (
                                <div className="group/mitre relative flex items-center gap-2">
                                  <span className="text-[10px] font-mono bg-white/10 px-1.5 py-0.5 rounded text-blue-400 font-bold border border-blue-500/20">
                                    {alert.mitre_technique_id}
                                  </span>
                                  <span className="text-[8px] text-blue-400/70 font-black uppercase tracking-tighter bg-blue-500/5 px-1 rounded border border-blue-500/10">
                                    {alert.mitre_tactic}
                                  </span>
                                  <span className="text-[9px] text-text-dim font-bold hidden md:inline truncate max-w-[120px]">
                                    {alert.mitre_technique_name}
                                  </span>
                                  {/* MITRE Tooltip */}
                                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover/mitre:block w-[240px] p-3 bg-gray-900 border border-border rounded shadow-2xl z-[100] text-[10px]">
                                     <div className="font-black text-blue-400 uppercase mb-1 tracking-widest text-[8px]">{alert.mitre_tactic}</div>
                                     <div className="font-bold text-white mb-2 pb-2 border-b border-white/5">{alert.mitre_technique_name}</div>
                                     <div className="text-text-dim leading-relaxed italic mb-2">"{alert.mitre_description}"</div>
                                     <div className="mt-1 pt-1 text-blue-400 font-black text-center text-[8px] uppercase tracking-widest animate-pulse">CLICK TO VIEW MATRIX & EVIDENCE</div>
                                  </div>
                                </div>
                              )}
                              <span className="text-[9px] text-text-dim font-mono">{alert.timestamp}</span>
                            </div>
                            
                            <p className="text-sm font-bold text-white mb-3 group-hover:text-blue-400 transition-colors uppercase tracking-tight font-black">{alert.description}</p>
                          
                          <div className="flex flex-wrap items-center gap-6 font-mono text-[10px] text-text-dim border-t border-white/5 pt-3">
                             <div className="flex flex-col gap-1">
                                <span className="text-[8px] uppercase font-bold opacity-50">Source Entity</span>
                                <div className="flex items-center gap-2 text-white">
                                   <Monitor size={10} className="text-blue-400" />
                                   <span>{alert.source.name}</span>
                                   <span className="opacity-40">{alert.source.ip}</span>
                                </div>
                             </div>
                             <div className="flex flex-col gap-1">
                                <span className="text-[8px] uppercase font-bold opacity-50">Target Destination</span>
                                <div className="flex items-center gap-2 text-white">
                                   <Globe size={10} className="text-amber-400" />
                                   <span>{alert.target.name}</span>
                                   <span className="opacity-40">{alert.target.ip}</span>
                                </div>
                             </div>
                          </div>
                        </div>
                        
                        <div className="flex flex-col gap-2">
                          <button 
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCreateCaseFromAlert(alert);
                            }}
                            className="text-[9px] font-bold text-text-dim hover:text-blue-400 uppercase tracking-widest border border-white/5 px-3 py-1.5 rounded bg-white/2 hover:bg-white/5 transition-all flex items-center gap-2"
                          >
                            <Briefcase size={10} />
                            Create Case
                          </button>
                          <button 
                            onClick={(e) => {
                              e.stopPropagation();
                              const reason = prompt("Reason for marking as False Positive?");
                              if (reason) handleMarkFalsePositive(alert, reason);
                            }}
                            className="text-[9px] font-bold text-text-dim hover:text-blue-400 uppercase tracking-widest border border-white/5 px-3 py-1.5 rounded bg-white/2 hover:bg-white/5 transition-all flex items-center gap-2"
                          >
                            <Trash2 size={10} />
                            False Positive
                          </button>
                          <button 
                            onClick={(e) => {
                              e.stopPropagation();
                              setActionModal({
                                show: true,
                                type: 'BLOCK_IP',
                                target: alert.source.ip,
                                triggeredBy: `Alert: ${alert.type}`,
                                alertId: alert.id
                              });
                            }}
                            className="text-[9px] font-bold text-red-400 hover:text-white uppercase tracking-widest border border-red-500/30 px-3 py-1.5 rounded bg-red-500/5 hover:bg-red-600 transition-all flex items-center gap-2"
                          >
                            <Shield size={10} />
                            Block Source
                          </button>
                          <button 
                            onClick={(e) => {
                              e.stopPropagation();
                              setActiveTab('devices');
                              setSelectedDeviceId(devices.find(d => d.ip === alert.source.ip)?.id || null);
                            }}
                            className="text-[9px] font-bold text-blue-400 hover:text-white uppercase tracking-widest border border-blue-500/30 px-3 py-1.5 rounded bg-blue-500/5 hover:bg-blue-600 transition-all flex items-center gap-2"
                          >
                            <Search size={10} />
                            Investigate
                          </button>
                        </div>
                     </div>
                   </div>
                 ))}
                 
                 {alerts.filter(a => {
                    if (alertFilter === 'ALL') return true;
                    if (alertFilter === 'UNREAD') return !a.isRead;
                    return a.severity === alertFilter;
                  }).length === 0 && (
                    <div className="h-64 flex flex-col items-center justify-center border border-dashed border-border rounded-xl">
                       <Filter size={32} className="text-text-dim opacity-20 mb-4" />
                       <p className="text-sm text-text-dim">No alerts match the selected filter.</p>
                    </div>
                  )}
              </div>
              )}
            </motion.div>
          )}

          {activeTab === 'actions' && (
            <motion.div 
               key="actions"
               initial={{ opacity: 0, scale: 0.98 }}
               animate={{ opacity: 1, scale: 1 }}
               exit={{ opacity: 0, scale: 0.98 }}
               className="h-full p-6 flex flex-col gap-6"
            >
              <div className="flex items-center justify-between bg-card border border-border p-1.5 rounded-xl">
                <div className="flex">
                   {(['PENDING', 'ACTIVE', 'HISTORY'] as const).map(tab => (
                     <button
                       key={tab}
                       onClick={() => setActionsSubTab(tab)}
                       className={cn(
                         "px-8 py-2.5 rounded-lg text-[10px] font-black transition-all uppercase tracking-widest flex items-center gap-2",
                         actionsSubTab === tab ? "bg-white/10 text-white shadow-sm" : "text-text-dim hover:text-white"
                       )}
                     >
                       {tab}
                       {tab !== 'HISTORY' && (
                         <span className={cn(
                           "px-2 py-0.5 rounded-full text-[9px]",
                           tab === 'PENDING' && actions.filter(a => a.status === 'PENDING').length > 0 ? "bg-amber-500 text-white" : "bg-white/10 text-text-dim"
                         )}>
                           {actions.filter(a => a.status === tab).length}
                         </span>
                       )}
                     </button>
                   ))}
                </div>
                {actionsSubTab === 'HISTORY' && (
                   <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg text-[10px] font-black uppercase tracking-widest hover:bg-blue-500 transition-all">
                      <Download size={14} /> Export Audit Log
                   </button>
                )}
              </div>

              <div className="flex-grow overflow-y-auto custom-scrollbar pr-3 pb-10">
                 {actionsSubTab === 'PENDING' && (
                   <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                      {actions.filter(a => a.status === 'PENDING').map(action => (
                        <div key={action.id} className="bg-card border border-border p-6 rounded-lg relative overflow-hidden flex flex-col gap-6">
                           <div className="absolute top-0 left-0 w-full h-1 bg-amber-500/50" />
                           <div className="flex justify-between items-start">
                              <div className="flex items-center gap-2">
                                 <div className="bg-amber-500/10 p-1.5 rounded">
                                    {action.type === 'BLOCK_IP' ? <ShieldAlert size={16} className="text-amber-500" /> : <Eye size={16} className="text-amber-500" />}
                                 </div>
                                 <div>
                                    <div className="text-[10px] font-black uppercase text-amber-500">{action.type.replace('_', ' ')}</div>
                                    <div className="text-lg font-bold text-white font-mono">{action.target}</div>
                                 </div>
                              </div>
                           </div>

                           <div className="space-y-3">
                              <div className="grid grid-cols-2 gap-4 text-[10px] font-mono text-text-dim">
                                 <div>
                                    <div className="opacity-50 uppercase text-[8px] font-bold">Triggered By</div>
                                    <div className="text-white">{action.triggeredBy}</div>
                                 </div>
                                 <div>
                                    <div className="opacity-50 uppercase text-[8px] font-bold">Time</div>
                                    <div className="text-white">{new Date(action.triggeredAt).toLocaleTimeString()}</div>
                                 </div>
                              </div>
                              <div>
                                 <div className="opacity-50 uppercase text-[8px] font-bold text-text-dim mb-1">Reason / Justification</div>
                                 <p className="text-[11px] text-white leading-relaxed bg-white/5 p-2 rounded italic border-l-2 border-amber-500/30">
                                    "{action.reason}"
                                 </p>
                              </div>
                           </div>

                           <div className="mt-auto space-y-3 pt-3 border-t border-white/5">
                              <div className="flex flex-col gap-2">
                                 <div className="text-[9px] text-text-dim uppercase font-bold">Confirm Action</div>
                                 <div className="flex gap-2">
                                    <button 
                                      onClick={() => setActionModal({
                                        show: true,
                                        type: action.type,
                                        target: action.target,
                                        triggeredBy: action.triggeredBy
                                      })}
                                      className="flex-grow py-2 bg-amber-600 hover:bg-amber-500 text-white font-bold rounded text-[9px] uppercase tracking-widest transition-all"
                                    >
                                       Review & Confirm
                                    </button>
                                    <button 
                                      onClick={() => setActions(prev => prev.filter(a => a.id !== action.id))}
                                      className="px-4 py-2 border border-border hover:bg-white/10 text-text-dim font-bold rounded text-[9px] uppercase transition-all"
                                    >
                                       Dismiss
                                    </button>
                                 </div>
                              </div>
                           </div>
                        </div>
                      ))}
                      {actions.filter(a => a.status === 'PENDING').length === 0 && (
                        <div className="col-span-full h-64 flex flex-col items-center justify-center border-2 border-dashed border-border rounded-xl">
                            <CheckCircle2 size={48} className="text-green-500 opacity-20 mb-4" />
                            <p className="text-sm text-text-dim font-medium uppercase tracking-widest">Awaiting new detections...</p>
                        </div>
                      )}
                   </div>
                 )}

                 {actionsSubTab === 'ACTIVE' && (
                   <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                      {actions.filter(a => a.status === 'ACTIVE').map(action => {
                        const isExpiringSoon = action.expiresAt && (action.expiresAt - Date.now() < 10 * 60 * 1000);
                        const timeLeft = action.expiresAt ? Math.max(0, action.expiresAt - Date.now()) : null;
                        const hours = timeLeft ? Math.floor(timeLeft / (60 * 60 * 1000)) : 0;
                        const mins = timeLeft ? Math.floor((timeLeft % (60 * 60 * 1000)) / (60 * 1000)) : 0;

                        return (
                          <div key={action.id} className={cn(
                            "bg-card border p-4 rounded-[4px] relative overflow-hidden flex flex-col gap-4 transition-all",
                            isExpiringSoon ? "border-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.1)]" : "border-green-500/30"
                          )}>
                             <div className={cn(
                               "absolute top-0 left-0 w-full h-1",
                               isExpiringSoon ? "bg-amber-500" : "bg-green-500"
                             )} />
                             
                             <div className="flex justify-between items-start">
                                <div>
                                   <div className="flex items-center gap-2 mb-1">
                                      <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-green-500/20 text-green-500 border border-green-500/30 uppercase">ACTIVE</span>
                                      {isExpiringSoon && (
                                        <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-500 border border-amber-500/30 uppercase animate-pulse">EXPIRING SOON</span>
                                      )}
                                   </div>
                                   <div className="text-[10px] font-black uppercase text-text-dim">{action.type.replace('_', ' ')}</div>
                                   <div className="text-lg font-bold text-white font-mono">{action.target}</div>
                                </div>
                                <div className="text-right">
                                   <div className="text-[10px] font-mono text-white bg-white/5 px-2 py-1 rounded">
                                      {action.duration === 'Permanent' ? 'PERMANENT' : `${hours}h ${mins}m`}
                                   </div>
                                   <div className="text-[8px] text-text-dim mt-1 font-bold uppercase tracking-tighter">REMAINING</div>
                                </div>
                             </div>

                             <div className="space-y-3">
                                <div>
                                   <div className="opacity-50 uppercase text-[8px] font-bold text-text-dim mb-1">Confirmed By</div>
                                   <div className="text-[11px] text-white flex items-center gap-1.5">
                                      <User size={10} className="text-blue-400" />
                                      {action.confirmedBy}
                                      <span className="text-text-dim opacity-40 px-1 font-mono text-[10px]">|</span>
                                      <span className="text-text-dim font-mono text-[10px]">{new Date(action.confirmedAt || 0).toLocaleTimeString()}</span>
                                   </div>
                                </div>
                                <div>
                                   <div className="opacity-50 uppercase text-[8px] font-bold text-text-dim mb-1">Reason Provided</div>
                                   <p className="text-[11px] text-white italic">"{action.reason}"</p>
                                </div>
                             </div>

                             <div className="mt-auto grid grid-cols-2 gap-2 pt-4 border-t border-white/5">
                                <button 
                                  onClick={() => extendAction(action.id, 60 * 60 * 1000)}
                                  className="py-2 bg-white/5 hover:bg-white/10 text-white rounded text-[9px] font-bold uppercase tracking-widest transition-all flex items-center justify-center gap-2 border border-white/10"
                                >
                                   <Plus size={10} /> Extend
                                </button>
                                <button 
                                  onClick={() => {
                                    const reason = prompt("Enter reason for revoking this action:");
                                    if (reason) revokeAction(action.id, reason);
                                  }}
                                  className="py-2 bg-red-900/20 hover:bg-red-900/40 text-red-500 rounded text-[9px] font-bold uppercase tracking-widest transition-all border border-red-500/30"
                                >
                                   Revoke Action
                                </button>
                                {action.duration !== 'Permanent' && (
                                   <button 
                                     onClick={() => makePermanent(action.id)}
                                     className="col-span-2 py-1 text-[8px] text-text-dim hover:text-white uppercase font-bold tracking-tighter text-center mt-1"
                                   >
                                      Make Permanent Record
                                   </button>
                                )}
                             </div>
                          </div>
                        );
                      })}
                   </div>
                 )}

                 {actionsSubTab === 'HISTORY' && (
                    <Card title="Activity Audit Log" className="h-full">
                       <table className="w-full text-left font-mono text-[11px]">
                          <thead className="sticky top-0 bg-card z-10">
                             <tr className="text-text-dim border-b border-border uppercase text-[10px]">
                                <th className="p-3">Type</th>
                                <th className="p-3">Target</th>
                                <th className="p-3">Reason</th>
                                <th className="p-3">Analyst</th>
                                <th className="p-3">Started</th>
                                <th className="p-3">Status</th>
                                <th className="p-3 text-right">Actions</th>
                             </tr>
                          </thead>
                          <tbody>
                             {actions.filter(a => ['EXPIRED', 'REVOKED'].includes(a.status)).map(action => (
                               <tr key={action.id} className="border-b border-white/2 hover:bg-white/5 transition-colors group">
                                  <td className="p-3">
                                     <div className="flex items-center gap-2">
                                        {action.type === 'BLOCK_IP' ? <ShieldAlert size={12} className="text-text-dim" /> : <Eye size={12} className="text-text-dim" />}
                                        <span className="font-bold text-white">{action.type}</span>
                                     </div>
                                  </td>
                                  <td className="p-3 text-white font-bold">{action.target}</td>
                                  <td className="p-3 max-w-[200px]">
                                     <div className="truncate group-hover:whitespace-normal group-hover:overflow-visible transition-all">
                                        {action.reason}
                                     </div>
                                  </td>
                                  <td className="p-3 text-text-dim">{action.confirmedBy || action.triggeredBy}</td>
                                  <td className="p-3 text-text-dim whitespace-nowrap">
                                     <div>{new Date(action.confirmedAt || action.triggeredAt).toLocaleDateString()}</div>
                                     <div className="text-[9px] opacity-50">{new Date(action.confirmedAt || action.triggeredAt).toLocaleTimeString()}</div>
                                  </td>
                                  <td className="p-3">
                                     <span className={cn(
                                       "text-[8px] font-black px-1.5 py-0.5 rounded uppercase",
                                       action.status === 'EXPIRED' ? "bg-gray-500/20 text-gray-400" : "bg-amber-500/20 text-amber-500"
                                     )}>
                                        {action.status}
                                     </span>
                                  </td>
                                  <td className="p-3 text-right">
                                     <button 
                                       onClick={() => reapplyAction(action)}
                                       className="p-1.5 bg-blue-600/10 hover:bg-blue-600 text-blue-400 hover:text-white rounded border border-blue-600/30 transition-all font-bold text-[9px] uppercase px-3"
                                     >
                                        Reapply
                                     </button>
                                  </td>
                               </tr>
                             ))}
                          </tbody>
                       </table>
                    </Card>
                 )}
              </div>
            </motion.div>
          )}

          {activeTab === 'controls' && (
            <motion.div 
               key="controls"
               initial={{ opacity: 0 }}
               animate={{ opacity: 1 }}
               exit={{ opacity: 0 }}
               className="h-full p-8 max-w-7xl mx-auto flex flex-col gap-8"
            >
              <div className="flex items-center justify-between">
                <div>
                   <h2 className="text-2xl font-black text-white flex items-center gap-4 tracking-tight uppercase">
                     <Gauge className="text-blue-500" size={28} />
                     Auto-Action Policy Engine
                   </h2>
                   <p className="text-[11px] text-text-dim uppercase tracking-[0.2em] font-bold mt-2 opacity-60">Configure automated response thresholds and rule behaviors</p>
                </div>
                <button className="flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg text-[10px] font-black uppercase tracking-[0.2em] hover:bg-blue-500 transition-all shadow-lg hover:shadow-blue-500/20">
                   <Plus size={16} /> Add Custom Rule
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 overflow-y-auto custom-scrollbar pr-3 pb-10">
                 {rules.map(rule => (
                   <div key={rule.id} className={cn(
                     "bg-card border p-5 rounded-lg flex flex-col gap-4 relative transition-all group",
                     rule.enabled ? "border-blue-500/50 shadow-lg" : "border-border opacity-60 grayscale hover:opacity-100 hover:grayscale-0"
                   )}>
                      <div className="flex justify-between items-start">
                         <div className={cn(
                           "p-2 rounded-lg",
                           rule.enabled ? "bg-blue-500/20" : "bg-white/5"
                         )}>
                            {rule.action === 'BLOCK_IP' ? <ShieldAlert size={20} className={rule.enabled ? "text-blue-400" : "text-text-dim"} /> : <Eye size={20} className={rule.enabled ? "text-blue-400" : "text-text-dim"} />}
                         </div>
                         <div className="flex items-center gap-3">
                            <div className="flex flex-col items-end">
                               <div className="text-[9px] font-bold text-text-dim uppercase">Enabled</div>
                               <button 
                                 onClick={() => setRules(prev => prev.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r))}
                                 className={cn(
                                   "w-8 h-4 rounded-full relative transition-all mt-1",
                                   rule.enabled ? "bg-blue-600" : "bg-gray-700"
                                 )}
                               >
                                  <div className={cn(
                                    "absolute top-0.5 w-3 h-3 bg-white rounded-full transition-all",
                                    rule.enabled ? "left-4.5" : "left-0.5"
                                  )} />
                               </button>
                            </div>
                         </div>
                      </div>

                      <div>
                         <h3 className="text-sm font-bold text-white mb-1 group-hover:text-blue-400 transition-colors uppercase tracking-tight">{rule.name}</h3>
                         <div className="bg-white/5 p-2 rounded font-mono text-[10px] text-blue-400 mb-3 border border-white/5">
                            IF {rule.condition}
                         </div>
                         <div className="flex items-center gap-2">
                            <span className="text-[9px] font-bold text-text-dim uppercase">Then:</span>
                            <span className="text-[9px] font-black px-1.5 py-0.5 rounded bg-white/5 text-white border border-white/10 uppercase tracking-tighter">CREATE {rule.action.replace('_', ' ')}</span>
                            <span className={cn(
                              "text-[9px] font-black px-1.5 py-0.5 rounded uppercase tracking-tighter",
                              rule.mode === 'AUTO_CONFIRM' ? "bg-red-500/20 text-red-500 border border-red-500/30" : "bg-amber-500/20 text-amber-500 border border-amber-500/30"
                            )}>{rule.mode.replace('_', ' ')}</span>
                         </div>
                      </div>

                      <div className="mt-auto pt-4 border-t border-white/5 flex items-center justify-between">
                         <div className="flex flex-col">
                            <span className="text-[8px] text-text-dim font-bold uppercase">Trigger Count</span>
                            <span className="text-xs font-mono text-white">{rule.triggerCount}</span>
                         </div>
                         <div className="text-right">
                            <span className="text-[8px] text-text-dim font-bold uppercase">Last Active</span>
                            <span className="text-xs font-mono text-white block">{rule.lastTriggered ? new Date(rule.lastTriggered).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'NEVER'}</span>
                         </div>
                      </div>

                      <div className="flex gap-2 mt-2 opacity-0 group-hover:opacity-100 transition-opacity">
                         <button className="flex-grow py-2 bg-white/5 hover:bg-white/10 text-white rounded text-[9px] font-bold uppercase border border-white/10">Edit</button>
                         <button className="flex-grow py-2 bg-white/5 hover:bg-white/10 text-white rounded text-[9px] font-bold uppercase border border-white/10">Duplicate</button>
                         <button className="p-2 bg-red-900/10 hover:bg-red-900/30 text-red-500 rounded border border-red-500/20"><Trash2 size={12} /></button>
                      </div>
                   </div>
                 ))}
              </div>
            </motion.div>
          )}

          {activeTab === 'reports' && (
            <motion.div 
               key="reports"
               initial={{ opacity: 0 }}
               animate={{ opacity: 1 }}
               exit={{ opacity: 0 }}
               className="h-full p-8 max-w-7xl mx-auto flex flex-col gap-8"
            >
              {currentReport ? (
                <div className="flex flex-col h-full gap-6">
                   <div className="flex items-center justify-between bg-card border border-border p-4 rounded-xl flex-shrink-0">
                      <div className="flex items-center gap-4">
                         <button 
                           onClick={() => setCurrentReport(null)}
                           className="p-2 hover:bg-white/5 rounded text-text-dim hover:text-white transition-all transform rotate-180"
                         >
                           <ArrowRight size={16} />
                         </button>
                         <div>
                            <h3 className="text-sm font-black uppercase text-white tracking-widest">{currentReport.title}</h3>
                            <div className="text-[10px] text-text-dim font-mono">{currentReport.period} | {currentReport.timestamp}</div>
                         </div>
                      </div>
                      <div className="flex items-center gap-2">
                         <button 
                           onClick={() => window.print()}
                           className="flex items-center gap-2 px-3 py-1.5 bg-white/5 hover:bg-white/10 text-white rounded text-[10px] font-bold uppercase transition-all"
                         >
                            <Printer size={12} />
                            Print / PDF
                         </button>
                         <button 
                           onClick={() => {
                              const blob = new Blob([document.querySelector('.report-container')?.innerHTML || ''], { type: 'text/html' });
                              const url = URL.createObjectURL(blob);
                              const a = document.createElement('a');
                              a.href = url;
                              a.download = `driftwatch_report_${currentReport.id}.html`;
                              a.click();
                           }}
                           className="flex items-center gap-2 px-3 py-1.5 bg-white/5 hover:bg-white/10 text-white rounded text-[10px] font-bold uppercase transition-all"
                         >
                            <Download size={12} />
                            HTML
                         </button>
                         <button 
                           onClick={() => {
                              navigator.clipboard.writeText(currentReport.summary.text);
                              alert("Executive Summary copied to clipboard");
                           }}
                           className="flex items-center gap-2 px-3 py-1.5 bg-white/5 hover:bg-white/10 text-white rounded text-[10px] font-bold uppercase transition-all"
                         >
                            <Copy size={12} />
                            Summary
                         </button>
                      </div>
                   </div>
                   <div className="flex-grow overflow-auto report-container custom-scrollbar pr-2">
                      <ReportDocument report={currentReport} onExport={() => {}} />
                   </div>
                </div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-full overflow-hidden">
                   {/* Generator Form */}
                   <div className="lg:col-span-2 bg-card border border-border p-6 rounded-lg flex flex-col overflow-y-auto custom-scrollbar">
                      <div className="flex items-center gap-3 mb-8 pb-4 border-b border-white/5 flex-shrink-0">
                         <div className="p-2 bg-blue-500/10 rounded">
                            <FileText size={20} className="text-blue-400" />
                         </div>
                         <div>
                            <h3 className="text-lg font-black uppercase text-white tracking-tight">Report Generator</h3>
                            <p className="text-[10px] text-text-dim">Configure and generate structured intelligence reports</p>
                         </div>
                      </div>

                      <div className="space-y-8 flex-grow text-left">
                         <div className="grid grid-cols-2 gap-6">
                            <div className="space-y-4">
                               <label className="text-[10px] text-text-dim uppercase font-black tracking-widest">Report Type</label>
                               <div className="grid grid-cols-1 gap-2">
                                  {[
                                    { id: 'EXECUTIVE', label: 'Executive Summary', desc: '1-2 pages, non-technical summary' },
                                    { id: 'TECHNICAL', label: 'Technical Threat Report', desc: 'Full forensic detail & mapping' },
                                    { id: 'AUDIT', label: 'Audit Trail Report', desc: 'Actions & enforcement records only' },
                                    { id: 'BASELINE', label: 'Baseline Analysis', desc: 'Drift scores & statistical models' },
                                    { id: 'CUSTOM', label: 'Custom Build', desc: 'Select specific sections manually' }
                                  ].map(t => (
                                     <button 
                                       key={t.id}
                                       onClick={() => setReportConfig(prev => ({ ...prev, type: t.id }))}
                                       className={cn(
                                         "px-4 py-3 rounded border text-left flex items-center justify-between transition-all group",
                                         reportConfig.type === t.id ? "bg-blue-600/10 border-blue-500 text-blue-400" : "bg-white/2 border-white/5 text-text-dim hover:text-white"
                                       )}
                                     >
                                        <div className="flex flex-col">
                                           <span className="text-[10px] font-black uppercase tracking-tight">{t.label}</span>
                                           <span className="text-[8px] opacity-70 italic">{t.desc}</span>
                                        </div>
                                        {reportConfig.type === t.id && <Check size={12} />}
                                     </button>
                                  ))}
                               </div>
                            </div>

                            <div className="space-y-6">
                               <div className="space-y-2">
                                  <label className="text-[10px] text-text-dim uppercase font-black tracking-widest">Analysis Window</label>
                                  <div className="grid grid-cols-2 gap-2">
                                     {['24H', '7D', '30D', 'CUSTOM'].map(r => (
                                        <button 
                                          key={r}
                                          onClick={() => setReportConfig(prev => ({ ...prev, range: r }))}
                                          className={cn(
                                            "py-2 rounded border text-[10px] font-bold transition-all",
                                            reportConfig.range === r ? "bg-white/10 border-white/30 text-white" : "bg-white/2 border-white/5 text-text-dim"
                                          )}
                                        >
                                           {r === '24H' ? 'Last 24h' : r === '7D' ? '7 Days' : r === '30D' ? '30 Days' : 'Custom'}
                                        </button>
                                     ))}
                                  </div>
                               </div>

                               <div className="space-y-2">
                                  <label className="text-[10px] text-text-dim uppercase font-black tracking-widest">Device Scope</label>
                                  <select 
                                    value={reportConfig.devices}
                                    onChange={(e) => setReportConfig(prev => ({ ...prev, devices: e.target.value }))}
                                    className="w-full bg-white/5 border border-white/10 p-3 rounded text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
                                  >
                                     <option value="ALL">All Monitored Devices ({devices.length})</option>
                                     <option value="CRITICAL">High Risk Only</option>
                                     <option value="SEGMENT">Specific Segment...</option>
                                  </select>
                               </div>

                               <div className="space-y-3 pt-6 border-t border-white/5">
                                  <div className="flex flex-col gap-3">
                                     <div className="flex flex-col gap-1">
                                        <span className="text-[8px] text-text-dim uppercase font-black tracking-widest">Analyst Name</span>
                                        <input 
                                          type="text" 
                                          value={reportConfig.analyst}
                                          onChange={(e) => setReportConfig(prev => ({ ...prev, analyst: e.target.value }))}
                                          className="bg-white/2 border border-white/5 p-2 rounded text-[10px] text-white font-mono"
                                        />
                                     </div>
                                     <div className="flex flex-col gap-1">
                                        <span className="text-[8px] text-text-dim uppercase font-black tracking-widest">Organisation</span>
                                        <input 
                                          type="text" 
                                          value={reportConfig.org}
                                          onChange={(e) => setReportConfig(prev => ({ ...prev, org: e.target.value }))}
                                          className="bg-white/2 border border-white/5 p-2 rounded text-[10px] text-white font-mono"
                                        />
                                     </div>
                                  </div>
                               </div>
                            </div>
                         </div>

                         <div className="space-y-3">
                            <label className="text-[10px] text-text-dim uppercase font-black tracking-widest">Report Composition</label>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                               {Object.entries(reportConfig.sections).map(([key, enabled]) => (
                                  <button 
                                    key={key}
                                    onClick={() => setReportConfig(prev => ({ ...prev, sections: { ...prev.sections, [key]: !enabled } }))}
                                    className={cn(
                                       "flex items-center gap-2 p-2.5 rounded border text-[9px] font-bold transition-all",
                                       enabled ? "bg-blue-600/10 border-blue-500/50 text-white" : "bg-white/2 border-white/5 text-text-dim"
                                    )}
                                  >
                                     <div className={cn("w-2.5 h-2.5 rounded flex items-center justify-center border", enabled ? "bg-blue-600 border-blue-400" : "bg-white/5 border-white/10")}>
                                        {enabled && <Check size={8} className="text-white" />}
                                     </div>
                                     {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                                  </button>
                               ))}
                            </div>
                         </div>
                      </div>

                      <div className="mt-8 pt-8 border-t border-white/5 flex-shrink-0">
                         <button 
                           onClick={() => {
                              setIsGeneratingReport(true);
                              setTimeout(() => {
                                 const newReport: GeneratedReport = {
                                    id: `rep-${Date.now()}`,
                                    title: `${reportConfig.type} Analysis Report`,
                                    timestamp: new Date().toLocaleString(),
                                    analyst: reportConfig.analyst,
                                    org: reportConfig.org,
                                    period: reportConfig.range === '7D' ? 'May 11 - May 18, 2026' : 'Last 24 Hours',
                                    classification: 'CONFIDENTIAL',
                                    summary: {
                                       text: `During the period monitored, DRIFTWATCH NDR analyzed ${devices?.length || 0} devices on the local segment. ${alerts?.length || 0} security alerts were generated. Key finding: Host Dev-Laptop exhibited definitive exfiltration patterns (3.4GB+) to a non-domestic C2 infrastructure.`,
                                       metrics: [
                                          { label: 'Devices', value: devices?.length?.toString() || '0' },
                                          { label: 'Alerts', value: alerts?.length?.toString() || '0' },
                                          { label: 'Critical', value: alerts?.filter?.(a => a.severity === 'HIGH').length?.toString() || '0' },
                                          { label: 'Actions', value: actions?.length?.toString() || '0' },
                                          { label: 'Score', value: '14%' }
                                       ]
                                    },
                                    deviceRisk: devices.slice(0, 5).map(d => ({
                                       device: d.name,
                                       ip: d.ip,
                                       score: d.name === 'Dev-Laptop' ? 92 : d.name === 'WorkStation-01' ? 45 : 12,
                                       highestAlert: d.name === 'Dev-Laptop' ? 'EXFILTRATION_INDICATOR' : d.name === 'WorkStation-01' ? 'BEACONING' : 'None',
                                       status: d.name === 'Dev-Laptop' ? 'ISOLATED' : d.name === 'WorkStation-01' ? 'WATCHED' : 'CLEAN',
                                       recommendation: d.name === 'Dev-Laptop' ? 'Disk forensic imaging required' : 'Monitor traffic volume'
                                    })),
                                    activeThreats: alerts.slice(0, 3),
                                    killChains: (Object.entries(deviceKillChains) as [string, KillChainData][]).slice(0, 2).map(([id, data]) => ({
                                       deviceId: id,
                                       hostname: devices.find(dev => dev.id === id)?.name || 'Unknown',
                                       data: data as KillChainData
                                    })),
                                    baselines: [],
                                    beacons: [
                                       { device: 'WorkStation-01', dest: '103.22.44.15', interval: '300s', confidence: 0.88 }
                                    ],
                                    auditTrail: actions.slice(0, 5),
                                    recommendations: [
                                       "Isolate WorkStation-01 pending C2 investigation.",
                                       "Investigate Dev-Laptop upload behaviour immediately.",
                                       "Permanently block 185.220.101.47 (TOR node).",
                                       "Review privilege escalation indicators on segment 0x4."
                                    ]
                                 };
                                 setCurrentReport(newReport);
                                 setReportHistory(prev => [{
                                    id: newReport.id,
                                    date: newReport.timestamp,
                                    type: reportConfig.type,
                                    analyst: reportConfig.analyst,
                                    devices: devices.length,
                                    actions: actions.length,
                                    config: reportConfig
                                 }, ...prev]);
                                 setIsGeneratingReport(false);
                              }, 2000);
                           }}
                           disabled={isGeneratingReport}
                           className={cn(
                             "w-full py-4 rounded font-black text-xs uppercase tracking-widest transition-all",
                             isGeneratingReport ? "bg-blue-900 text-blue-400 animate-pulse cursor-not-allowed" : "bg-blue-600 hover:bg-blue-500 text-white shadow-xl shadow-blue-900/20"
                           )}
                         >
                            {isGeneratingReport ? 'Compiling Intelligent Data...' : 'Generate Intelligence Report'}
                         </button>
                      </div>
                   </div>

                   {/* History Panel */}
                   <div className="bg-card border border-border p-5 rounded-lg flex flex-col overflow-hidden">
                      <div className="flex items-center justify-between mb-6 flex-shrink-0">
                         <h3 className="text-[10px] font-black uppercase text-text-dim tracking-widest">Report History</h3>
                         <History size={12} className="text-text-dim cursor-pointer hover:text-white" />
                      </div>
                      
                      <div className="space-y-2 overflow-y-auto custom-scrollbar flex-grow pr-1 text-left">
                         {reportHistory.map(h => (
                            <div key={h.id} className="group bg-white/2 border border-white/5 p-4 rounded hover:bg-white/5 hover:border-white/10 transition-all cursor-default relative">
                               <div className="flex justify-between items-start mb-2">
                                  <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 uppercase tracking-widest">
                                     {h.type}
                                  </span>
                                  <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-all">
                                     <button className="p-1 hover:bg-white/10 rounded text-text-dim hover:text-white transition-all"><FileText size={12} /></button>
                                     <button className="p-1 hover:bg-white/10 rounded text-text-dim hover:text-white transition-all"><Printer size={12} /></button>
                                     <button className="p-1 hover:bg-white/10 rounded text-text-dim hover:text-red-400 transition-all"><Trash2 size={12} /></button>
                                  </div>
                               </div>
                               <h4 className="text-[11px] font-bold text-white mb-1">DRIFTWATCH Security Analysis</h4>
                               <div className="text-[9px] text-text-dim font-mono mb-3">{h.date}</div>
                               <div className="flex items-center gap-3 text-[9px] text-text-dim font-mono pt-3 border-t border-white/5">
                                  <div className="flex items-center gap-1"><Monitor size={8} /> {h.devices}</div>
                                  <div className="flex items-center gap-1"><Shield size={8} /> {h.actions}</div>
                                  <div className="flex items-center gap-1 ml-auto text-blue-400 italic">Analyst: {h.analyst.split(' ').pop()}</div>
                               </div>
                            </div>
                         ))}
                         {reportHistory.length === 0 && (
                            <div className="h-full flex flex-col items-center justify-center text-center p-8 opacity-20">
                               <FileText size={48} className="mb-4" />
                               <p className="text-[10px] font-bold uppercase tracking-widest">No reports archived</p>
                            </div>
                         )}
                      </div>
                   </div>
                </div>
              )}
            </motion.div>
          )}

          {activeTab === 'system' && (
            <motion.div 
               key="system"
               initial={{ opacity: 0 }}
               animate={{ opacity: 1 }}
               exit={{ opacity: 0 }}
               className="h-full p-6 overflow-y-auto custom-scrollbar"
            >
              <div className="max-w-6xl mx-auto space-y-8 pb-12">
                 {/* 1. DETECTION ENGINE STATUS PANEL */}
                 <section className="space-y-4">
                    <div className="flex items-center gap-2 mb-2">
                       <Activity size={16} className="text-blue-400" />
                       <h2 className="text-xs font-black uppercase tracking-widest text-white">Detection Engine Status</h2>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-left">
                       {/* Card 1 — GMM ADAPTIVE BASELINE */}
                       <div className="bg-card border border-border p-4 rounded-lg flex flex-col gap-3">
                          <div className="flex justify-between items-center">
                             <h3 className="text-[10px] font-black uppercase text-text-dim">GMM Adaptive Baseline</h3>
                             <span className={cn(
                                "px-1.5 py-0.5 rounded text-[8px] font-black uppercase tracking-widest",
                                systemStatus?.engines?.gmm?.status === 'ACTIVE' ? "bg-green-500/20 text-green-400" : "bg-amber-500/20 text-amber-400"
                             )}>
                                {systemStatus?.engines?.gmm?.status}
                             </span>
                          </div>
                          <div className="space-y-1 text-left">
                             <div className="flex justify-between text-[9px] font-mono">
                                <span className="text-text-dim">Training Progress</span>
                                <span className="text-white">Day {systemStatus?.engines?.gmm?.day} of 14</span>
                             </div>
                             <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                                <div className="h-full bg-amber-500 transition-all duration-1000" style={{ width: `${systemStatus?.engines?.gmm?.progress}%` }} />
                             </div>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-[9px] font-mono pt-2 border-t border-white/5 text-left">
                             <div className="flex flex-col">
                                <span className="text-text-dim uppercase text-[8px]">K-Components</span>
                                <span className="text-white">{systemStatus?.engines?.gmm?.components} Optimized</span>
                             </div>
                             <div className="flex flex-col">
                                <span className="text-text-dim uppercase text-[8px]">Decay λ</span>
                                <span className="text-white">{systemStatus?.engines?.gmm?.decay}</span>
                             </div>
                             <div className="flex flex-col">
                                <span className="text-text-dim uppercase text-[8px]">Baseline Devices</span>
                                <span className="text-white">{systemStatus?.engines?.gmm?.devices}</span>
                             </div>
                             <div className="flex flex-col">
                                <span className="text-text-dim uppercase text-[8px]">Anomalies (Today)</span>
                                <span className="text-white">{systemStatus?.engines?.gmm?.anomalies_today}</span>
                             </div>
                          </div>
                          <div className="mt-auto text-[8px] text-text-dim italic text-left">Last update: {systemStatus?.engines?.gmm?.last_update ? new Date(systemStatus.engines.gmm.last_update).toLocaleTimeString() : 'N/A'}</div>
                       </div>

                       {/* Card 2 — KDE GLOBAL DENSITY */}
                       <div className="bg-card border border-border p-4 rounded-lg flex flex-col gap-3">
                          <div className="flex justify-between items-center">
                             <h3 className="text-[10px] font-black uppercase text-text-dim">KDE Global Density</h3>
                             <span className="px-1.5 py-0.5 rounded bg-green-500/20 text-green-400 text-[8px] font-black uppercase tracking-widest">
                                {systemStatus?.engines?.kde?.status}
                             </span>
                          </div>
                          <div className="grid grid-cols-1 gap-2 text-[9px] font-mono text-left">
                             <div className="flex justify-between">
                                <span className="text-text-dim">Training Window</span>
                                <span className="text-white">{systemStatus?.engines?.kde?.window}</span>
                             </div>
                             <div className="flex flex-col mt-1">
                                <span className="text-text-dim uppercase text-[8px]">Last Full Retrain</span>
                                <span className="text-white">{systemStatus?.engines?.kde?.last_retrain ? new Date(systemStatus.engines.kde.last_retrain).toLocaleString() : 'N/A'}</span>
                             </div>
                             <div className="flex flex-col">
                                <span className="text-text-dim uppercase text-[8px]">Bandwidth Selection</span>
                                <span className="text-white">{systemStatus?.engines?.kde?.bandwidth}</span>
                             </div>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-[9px] font-mono pt-2 border-t border-white/5 text-left">
                             <div className="flex flex-col">
                                <span className="text-text-dim uppercase text-[8px]">Observations</span>
                                <span className="text-white">{systemStatus?.engines?.kde?.observations?.toLocaleString() || '0'}</span>
                             </div>
                             <div className="flex flex-col">
                                <span className="text-text-dim uppercase text-[8px]">KDE Alerts (Today)</span>
                                <span className="text-white">{systemStatus?.engines?.kde?.alerts_today}</span>
                             </div>
                          </div>
                       </div>

                       {/* Card 4 — DECISION FUSION ENGINE */}
                       <div className="bg-card border border-border p-4 rounded-lg flex flex-col gap-3">
                          <div className="flex justify-between items-center">
                             <h3 className="text-[10px] font-black uppercase text-text-dim">Decision Fusion Engine</h3>
                             <span className="px-1.5 py-0.5 rounded bg-blue-600/20 text-blue-400 text-[8px] font-black uppercase tracking-widest">
                                {systemStatus?.engines?.fusion?.status}
                             </span>
                          </div>
                          <div className="space-y-1 text-left">
                             <span className="text-[8px] text-text-dim uppercase font-bold">Fusion Weights ω</span>
                             <div className="flex items-center gap-1">
                                {Object.entries(systemStatus?.engines?.fusion?.weights || {}).map(([k, v]) => (
                                   <div key={k} className="flex-grow text-center py-1 bg-white/5 border border-white/5 rounded text-[8px] font-mono text-white">
                                      {k.toUpperCase()}={(v as number).toFixed(2)}
                                   </div>
                                ))}
                             </div>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-[9px] font-mono pt-2 border-t border-white/5 text-left">
                             <div className="flex flex-col">
                                <span className="text-text-dim uppercase text-[8px]">Composite Today</span>
                                <span className="text-white">{systemStatus?.engines?.fusion?.composite_today?.toLocaleString() || '0'}</span>
                             </div>
                             <div className="flex flex-col">
                                <span className="text-text-dim uppercase text-[8px]">Alerts Fired</span>
                                <span className="text-white text-red-400 font-bold">{systemStatus?.engines?.fusion?.alerts?.high}H / {systemStatus?.engines?.fusion?.alerts?.med}M</span>
                             </div>
                          </div>
                          <div className="text-[7px] text-text-dim font-mono flex gap-2 overflow-hidden truncate">
                             Thresholds: L={systemStatus?.engines?.fusion?.thresholds?.low} M={systemStatus?.engines?.fusion?.thresholds?.med} H={systemStatus?.engines?.fusion?.thresholds?.high}
                          </div>
                       </div>
                    </div>
                 </section>

                 <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 text-left">
                    {/* 2. SYSTEM METRICS panel */}
                    <div className="lg:col-span-2 space-y-4">
                       <div className="flex items-center gap-2 mb-2">
                          <Gauge size={16} className="text-blue-400" />
                          <h2 className="text-xs font-black uppercase tracking-widest text-white">Advanced System Telemetry</h2>
                       </div>
                       <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                          {[
                             { label: 'Backend Uptime', value: systemStatus ? `${Math.floor(systemStatus.uptime / 3600)}h ${Math.floor((systemStatus.uptime % 3600) / 60)}m` : '0h 0m', icon: Clock },
                             { label: 'Total Packets', value: systemStatus?.packets_total?.toLocaleString() || '0', icon: Hash },
                             { label: 'Packets/Sec', value: systemStatus?.packets_per_sec?.toLocaleString() || '0', icon: Zap, live: true },
                             { label: 'Flows Tracked', value: systemStatus?.flows_tracked?.toLocaleString() || '0', icon: Activity },
                             { label: 'Devices Discovered', value: systemStatus?.devices_discovered?.toLocaleString() || '0', icon: Monitor },
                             { label: 'Database size', value: `${systemStatus?.db_size_mb || 0} MB`, icon: Database },
                             { label: 'Redis Buffer', value: `${systemStatus?.redis_buffer_fill || 0}%`, icon: HardDrive, warning: (systemStatus?.redis_buffer_fill || 0) > 80 },
                             { label: 'API Response Time', value: `${systemStatus?.api_latency_ms || 0} ms`, icon: Zap },
                             { label: 'WS Clients', value: systemStatus?.ws_clients?.toString() || '0', icon: User }
                          ].map(m => (
                             <div key={m.label} className="bg-card border border-border p-4 rounded flex flex-col justify-center relative overflow-hidden group">
                                {m.live && <div className="absolute top-2 right-2 w-1 h-1 bg-green-500 rounded-full animate-ping" />}
                                <div className="text-[8px] text-text-dim uppercase font-black tracking-widest mb-1 text-left">{m.label}</div>
                                <div className={cn("text-lg font-mono font-bold text-white text-left", m.warning && "text-red-400")}>{m.value}</div>
                                <m.icon size={24} className="absolute -bottom-2 -right-2 text-white/5" />
                             </div>
                          ))}
                       </div>

                       {/* 4. ADVERSARIAL DRIFT SENTINEL (ADS) status */}
                       <div className="pt-6 border-t border-white/5 space-y-4">
                          <div className="flex items-center gap-2 mb-2">
                             <Shield size={16} className="text-blue-400" />
                             <h2 className="text-xs font-black uppercase tracking-widest text-white">Adversarial Drift Sentinel (ADS) — Ch 3.3.7</h2>
                          </div>
                          <div className="bg-card border border-border p-6 rounded-lg grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
                             <div className="md:col-span-4 space-y-4 text-left">
                                <div className="flex flex-col gap-1">
                                   <span className="text-[9px] text-text-dim uppercase font-black tracking-widest">Sentinel Status</span>
                                   <div className={cn(
                                      "text-xl font-black uppercase tracking-tight",
                                      systemStatus?.ads?.status === 'MONITORING' ? "text-green-400" : "text-red-500"
                                   )}>
                                      {systemStatus?.ads?.status}
                                   </div>
                                </div>
                                <div className="grid grid-cols-2 gap-4 text-[10px] font-mono">
                                   <div>
                                      <span className="text-text-dim block text-[8px] uppercase">Anchor Snapshot</span>
                                      <span className="text-white">{systemStatus?.ads?.last_anchor}</span>
                                   </div>
                                   <div>
                                      <span className="text-text-dim block text-[8px] uppercase">Total Parameters</span>
                                      <span className="text-white">128 Sentinel Hooks</span>
                                   </div>
                                </div>
                                <div className="space-y-2">
                                   <div className="flex justify-between text-[11px] font-bold">
                                      <span className="text-text-dim uppercase tracking-widest">Global Drift Magnitude</span>
                                      <span className={cn(
                                        "font-mono", 
                                        (systemStatus?.ads?.drift || 0) > (systemStatus?.ads?.threshold || 0) ? "text-red-500" : "text-blue-400"
                                      )}>{systemStatus?.ads?.drift}%</span>
                                   </div>
                                   <div className="h-2 bg-white/5 border border-white/5 rounded-full overflow-hidden relative">
                                      <div className="absolute top-0 left-1/4 h-full w-[1px] bg-white/20 z-10" />
                                      <motion.div 
                                        className={cn("h-full transition-all duration-500", (systemStatus?.ads?.drift || 0) > (systemStatus?.ads?.threshold || 0) ? "bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]" : "bg-blue-600")}
                                        style={{ width: `${(systemStatus?.ads?.drift || 0) * 4}%` }} 
                                      />
                                   </div>
                                   <div className="flex justify-between text-[8px] text-text-dim font-mono">
                                      <span>0% STABLE</span>
                                      <span>LIMIT {systemStatus?.ads?.threshold}%</span>
                                   </div>
                                </div>
                                {(systemStatus?.ads?.drift || 0) > (systemStatus?.ads?.threshold || 0) && (
                                   <div className="bg-red-500/10 border border-red-500/30 p-2 rounded text-[9px] text-red-500 font-bold uppercase animate-pulse flex items-center gap-2">
                                      <AlertTriangle size={12} />
                                      POSSIBLE BASELINE POISONING DETECTED
                                   </div>
                                )}
                             </div>
                             <div className="md:col-span-8 h-48">
                                <ResponsiveContainer width="100%" height="100%">
                                   <AreaChart data={systemStatus?.ads?.history || []}>
                                      <defs>
                                         <linearGradient id="driftGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                                            <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                                         </linearGradient>
                                      </defs>
                                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                                      <XAxis dataKey="time" hide />
                                      <YAxis hide domain={[0, 40]} />
                                      <Tooltip 
                                        contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', fontSize: '9px' }}
                                        labelFormatter={() => 'T-Interval'}
                                      />
                                      <Area type="monotone" dataKey="drift" stroke="#ef4444" fillOpacity={1} fill="url(#driftGrad)" strokeWidth={2} isAnimationActive={false} />
                                   </AreaChart>
                                </ResponsiveContainer>
                                <div className="text-center text-[8px] text-text-dim border-t border-white/5 pt-2 uppercase tracking-widest font-bold">Sentinel Parameter Drift over T-Interval (Dissertation Ch 3.3)</div>
                             </div>
                          </div>
                       </div>
                    </div>

                    {/* Left Column: False Positive Tracker & Capabilities */}
                    <div className="space-y-8 text-left">
                       {/* 3. FALSE POSITIVE TRACKER */}
                       <section className="space-y-4">
                          <div className="flex items-center gap-2 mb-2">
                             <Trash2 size={16} className="text-blue-400" />
                             <h2 className="text-xs font-black uppercase tracking-widest text-white">Evaluation Evidence (False Positives)</h2>
                          </div>
                          <div className="bg-card border border-border p-5 rounded-lg space-y-6">
                             <div className="grid grid-cols-2 gap-4">
                                <div className="flex flex-col">
                                   <span className="text-[10px] font-black uppercase text-text-dim mb-1">True Positive Rate</span>
                                   <span className="text-2xl font-black text-white">84.2%</span>
                                   <span className="text-[8px] text-green-500 font-mono">+2.4% this week</span>
                                </div>
                                <div className="flex flex-col">
                                   <span className="text-[10px] font-black uppercase text-text-dim mb-1">Total FP Count</span>
                                   <span className="text-2xl font-black text-amber-500">{falsePositives.length}</span>
                                   <span className="text-[8px] text-text-dim font-mono">Archive Volume</span>
                                </div>
                             </div>
                             
                             <div className="h-40 flex items-center justify-center relative">
                                <div className="w-24 h-24 rounded-full border-4 border-white/5 flex items-center justify-center relative">
                                   <div className="absolute inset-[-4px] border-4 border-blue-500 rounded-full" style={{ clipPath: 'polygon(0 0, 84% 0, 84% 100%, 0 100%)' }} />
                                   <div className="text-[10px] font-black text-white">TP / FP</div>
                                </div>
                                <div className="absolute right-0 space-y-2 text-left">
                                   <div className="flex items-center gap-2 text-[9px] font-bold">
                                      <div className="w-2 h-2 bg-blue-500 rounded" />
                                      <span className="text-white">TP (142)</span>
                                   </div>
                                   <div className="flex items-center gap-2 text-[9px] font-bold">
                                      <div className="w-2 h-2 bg-amber-500 rounded" />
                                      <span className="text-white">FP ({falsePositives.length})</span>
                                   </div>
                                   <div className="flex items-center gap-2 text-[9px] font-bold">
                                      <div className="w-2 h-2 bg-white/10 rounded" />
                                      <span className="text-blue-400">Unreviewed (12)</span>
                                   </div>
                                </div>
                             </div>

                             <div className="pt-4 border-t border-white/5 space-y-1 text-[8px] font-mono text-text-dim flex justify-between uppercase">
                                <span>GMM FP: 12%</span>
                                <span>KDE FP: 4%</span>
                                <span>LOWESS FP: 18%</span>
                             </div>
                          </div>

                          <div className="max-h-[300px] overflow-y-auto custom-scrollbar pr-1 bg-white/2 border border-border border-dashed rounded p-3 text-left">
                             {falsePositives.map(fp => (
                                <div key={fp.id} className="mb-3 pb-3 border-b border-white/5 last:border-0 last:pb-0">
                                   <div className="flex justify-between items-start mb-1 text-left">
                                      <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-blue-600/10 text-blue-400 border border-blue-500/20">{fp.layer} LAYER</span>
                                      <span className="text-[8px] text-text-dim font-mono">{fp.timestamp}</span>
                                   </div>
                                   <div className="text-[10px] text-white font-bold mb-1 leading-tight text-left">{fp.originalAlert}</div>
                                   <div className="text-[9px] text-text-dim leading-relaxed text-left">
                                      <span className="text-blue-400 font-bold italic">REASON:</span> {fp.reason}
                                   </div>
                                   <div className="mt-1 text-[8px] text-text-dim/60 italic text-left">— Marked by {fp.markedBy}</div>
                                </div>
                             ))}
                          </div>
                       </section>

                       {/* 5. CAPABILITIES CHECK */}
                       <section className="space-y-4">
                          <div className="flex items-center gap-2 mb-2">
                             <Database size={16} className="text-blue-400" />
                             <h2 className="text-xs font-black uppercase tracking-widest text-white">Backend Capabilities Hub</h2>
                          </div>
                          <div className="bg-card border border-border p-1 rounded-lg overflow-hidden">
                             <table className="w-full text-left font-mono text-[10px] border-collapse">
                                <thead>
                                   <tr className="bg-white/5 text-text-dim uppercase text-[8px] font-black tracking-widest text-left">
                                      <th className="p-3">Capability</th>
                                      <th className="p-3 text-center">Status</th>
                                   </tr>
                                </thead>
                                <tbody>
                                   {[
                                      { label: 'REST API Infrastructure', key: 'rest_api', detail: 'Core data exchange service' },
                                      { label: 'WebSocket Live Feed', key: 'websocket', detail: 'Bi-directional stream' },
                                      { label: 'Promiscuous Mode', key: 'promiscuous_mode', detail: 'Raw packet ingestion (requires Root)' },
                                      { label: 'PostgreSQL TimeScaleDB', key: 'postgresql', detail: 'Structured long-term storage' },
                                      { label: 'Redis Event Buffer', key: 'redis', detail: 'Memory-mapped flow cache' },
                                      { label: 'GMM Detection Engine', key: 'gmm_engine', detail: 'Local density adaptive layer' },
                                      { label: 'KDE Analysis Layer', key: 'kde_engine', detail: 'Global density mapping' },
                                      { label: 'LOWESS Drift Engine', key: 'lowess_engine', detail: 'Temporal trend sentinels' }
                                   ].map(cap => (
                                      <tr key={cap.key} className="border-b border-white/5 hover:bg-white/2 group text-left">
                                         <td className="p-3">
                                            <div className="text-white font-bold">{cap.label}</div>
                                            <div className="text-[8px] text-text-dim group-hover:text-blue-400 transition-colors">{cap.detail}</div>
                                         </td>
                                         <td className="p-3 text-center">
                                            {capabilities?.[cap.key as keyof Capabilities] ? (
                                               <div className="mx-auto w-5 h-5 bg-green-500/20 text-green-500 border border-green-500/40 rounded flex items-center justify-center">
                                                  <Check size={12} />
                                               </div>
                                            ) : (
                                               <div className="mx-auto w-5 h-5 bg-white/5 text-text-dim/20 border border-white/10 rounded flex items-center justify-center">
                                                  <Plus size={12} className="rotate-45" />
                                               </div>
                                            )}
                                         </td>
                                      </tr>
                                   ))}
                                </tbody>
                             </table>
                          </div>
                       </section>
                    </div>
                 </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'cases' && (
            <motion.div 
               key="cases"
               initial={{ opacity: 0 }}
               animate={{ opacity: 1 }}
               exit={{ opacity: 0 }}
               className="h-full"
            >
              {!selectedCaseId ? (
                <div className="h-full flex flex-col">
                  {/* Header & Filter Bar */}
                  <div className="p-6 border-b border-border bg-card/50 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                    <div>
                        <h1 className="text-2xl font-black text-white tracking-tight uppercase">Investigation Cases</h1>
                        <p className="text-xs text-text-dim font-mono uppercase tracking-widest mt-1">
                          {cases.length} Total Records / {cases.filter(c => c.status !== CaseStatus.CLOSED).length} Active Investigations
                        </p>
                    </div>
                    <div className="flex items-center gap-3">
                       <div className="flex bg-white/5 border border-white/5 p-1 rounded-lg">
                          {[
                            { id: 'ALL', label: 'All' },
                            { id: CaseStatus.OPEN, label: 'Open' },
                            { id: CaseStatus.IN_PROGRESS, label: 'In Progress' },
                            { id: CaseStatus.ESCALATED, label: 'Escalated' },
                            { id: CaseStatus.CLOSED, label: 'Closed' }
                          ].map(f => (
                            <button 
                              key={f.id}
                              onClick={() => setCaseFilter(f.id as any)}
                              className={cn(
                                "px-3 py-1.5 text-[10px] font-bold uppercase tracking-widest rounded transition-all",
                                caseFilter === f.id ? "bg-blue-600 text-white shadow-lg" : "text-text-dim hover:bg-white/5"
                              )}
                            >
                               {f.label}
                            </button>
                          ))}
                       </div>
                       <button 
                        onClick={() => setIsNewCaseModalOpen(true)}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-[4px] text-[10px] font-black uppercase tracking-widest transition-all shadow-[0_0_15px_rgba(37,99,235,0.2)]"
                       >
                          <Plus size={14} />
                          New Case
                       </button>
                    </div>
                  </div>

                  {/* Grid View */}
                  <div className="flex-grow p-6 overflow-y-auto custom-scrollbar">
                    <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                      {cases
                        .filter(c => caseFilter === 'ALL' || c.status === caseFilter)
                        .map(c => (
                        <div 
                          key={c.id} 
                          onClick={() => setSelectedCaseId(c.id)}
                          className="bg-card border border-border rounded-lg p-5 flex flex-col gap-4 hover:border-gray-600 cursor-pointer transition-all group relative overflow-hidden"
                        >
                          {/* Severity Flag */}
                          <div className={cn(
                             "absolute top-0 right-0 w-12 h-12 flex items-center justify-center rotate-45 translate-x-6 -translate-y-6",
                             c.severity === CaseSeverity.CRITICAL ? "bg-red-600" : 
                             c.severity === CaseSeverity.HIGH ? "bg-orange-600" :
                             c.severity === CaseSeverity.MEDIUM ? "bg-blue-600" : "bg-gray-600"
                          )}>
                             <span className="text-[8px] font-black text-white uppercase -rotate-45 -translate-y-2">{c.severity}</span>
                          </div>

                          <div className="space-y-1">
                             <div className="text-[10px] font-mono text-blue-400 font-bold tracking-tighter">{c.id}</div>
                             <h3 className="text-md font-black text-white group-hover:text-blue-400 transition-colors">{c.title}</h3>
                          </div>

                          <p className="text-xs text-text-dim line-clamp-2 leading-relaxed">
                             {c.summary}
                          </p>

                          <div className="flex flex-wrap gap-2 mt-auto">
                             <div className={cn(
                                "px-2 py-0.5 rounded text-[8px] font-black uppercase tracking-widest",
                                c.status === CaseStatus.OPEN ? "bg-blue-500/20 text-blue-400" :
                                c.status === CaseStatus.IN_PROGRESS ? "bg-amber-500/20 text-amber-400" :
                                c.status === CaseStatus.ESCALATED ? "bg-red-500/20 text-red-500" : "bg-green-500/20 text-green-400"
                             )}>
                                {c.status.replace('_', ' ')}
                             </div>
                             <div className="px-2 py-0.5 bg-white/5 rounded text-[8px] font-mono text-text-dim flex items-center gap-1">
                                <Monitor size={8} /> {c.deviceIds.length}
                             </div>
                             <div className="px-2 py-0.5 bg-white/5 rounded text-[8px] font-mono text-text-dim flex items-center gap-1">
                                <AlertTriangle size={8} /> {c.alertIds.length}
                             </div>
                          </div>

                          <div className="pt-4 border-t border-white/5 flex justify-between items-center text-[9px] font-mono">
                             <div className="flex items-center gap-2">
                                <div className="w-5 h-5 rounded-full bg-blue-600/20 flex items-center justify-center text-[10px] text-blue-400 font-bold border border-blue-500/20">
                                   {c.assignedTo.charAt(0)}
                                </div>
                                <span className="text-text-dim">{c.assignedTo}</span>
                             </div>
                             <span className="text-text-dim/60 italic">{c.updatedAt}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="h-full flex flex-col bg-background">
                  {/* Case Detail Header */}
                  <div className="px-6 py-4 border-b border-border bg-card flex items-center justify-between">
                     <div className="flex items-center gap-4">
                        <button 
                          onClick={() => setSelectedCaseId(null)}
                          className="p-2 hover:bg-white/5 rounded-full transition-all text-text-dim hover:text-white"
                        >
                           <ArrowLeft size={20} />
                        </button>
                        <div>
                           <div className="flex items-center gap-3">
                              <span className="text-[10px] font-mono text-blue-400">{selectedCaseId}</span>
                              <div className={cn(
                                "px-2 py-0.5 rounded text-[8px] font-black uppercase tracking-widest",
                                cases.find(c => c.id === selectedCaseId)?.status === CaseStatus.OPEN ? "bg-blue-500/20 text-blue-400" :
                                cases.find(c => c.id === selectedCaseId)?.status === CaseStatus.IN_PROGRESS ? "bg-amber-500/20 text-amber-400" :
                                cases.find(c => c.id === selectedCaseId)?.status === CaseStatus.ESCALATED ? "bg-red-500/20 text-red-500" : "bg-green-500/20 text-green-400"
                              )}>
                                 {cases.find(c => c.id === selectedCaseId)?.status.replace('_', ' ')}
                              </div>
                              <span className={cn(
                                "text-[10px] font-bold uppercase",
                                cases.find(c => c.id === selectedCaseId)?.severity === CaseSeverity.CRITICAL ? "text-red-500" : 
                                cases.find(c => c.id === selectedCaseId)?.severity === CaseSeverity.HIGH ? "text-orange-500" : "text-blue-400"
                              )}>{cases.find(c => c.id === selectedCaseId)?.severity} SEVERITY</span>
                           </div>
                           <h2 className="text-lg font-black text-white">{cases.find(c => c.id === selectedCaseId)?.title}</h2>
                        </div>
                     </div>
                     <div className="flex items-center gap-3">
                        {cases.find(c => c.id === selectedCaseId)?.status !== CaseStatus.CLOSED ? (
                          <button 
                            onClick={() => {
                              const note = prompt("Enter closing notes (min 30 chars):");
                              if (note && note.length >= 30) {
                                handleUpdateCaseStatus(selectedCaseId!, CaseStatus.CLOSED);
                                handleAddNote(selectedCaseId!, `Case closed with resolution. Notes: ${note}`, 'RECOMMENDATION');
                              } else if (note) {
                                alert("Closing notes must be at least 30 characters.");
                              }
                            }}
                            className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-[4px] text-[10px] font-black uppercase tracking-widest transition-all"
                          >
                             Close Case
                          </button>
                        ) : (
                          <div className="text-[10px] font-black text-green-400 uppercase border border-green-500/30 px-3 py-1.5 rounded bg-green-500/5">
                             Case Resolved
                          </div>
                        )}
                        <button className="p-2 hover:bg-white/5 rounded-full transition-all text-text-dim">
                           <MoreHorizontal size={20} />
                        </button>
                     </div>
                  </div>

                  <div className="flex-grow flex overflow-hidden">
                    {/* Left Panel: Metadata */}
                    <div className="w-80 border-r border-border p-6 space-y-8 overflow-y-auto custom-scrollbar">
                       <section className="space-y-4">
                          <label className="text-[10px] font-black uppercase tracking-widest text-text-dim block">Management</label>
                          <div className="space-y-4">
                             <div className="space-y-1">
                                <span className="text-[9px] text-text-dim uppercase font-bold">Assigned Analyst</span>
                                <div className="flex items-center gap-3 p-3 bg-white/2 border border-white/5 rounded-lg">
                                   <div className="w-8 h-8 rounded-full bg-blue-600/30 flex items-center justify-center text-blue-400 font-bold border border-blue-500/20">
                                      {cases.find(c => c.id === selectedCaseId)?.assignedTo.charAt(0)}
                                   </div>
                                   <div className="text-sm font-bold text-white">{cases.find(c => c.id === selectedCaseId)?.assignedTo}</div>
                                </div>
                             </div>
                             <div className="space-y-1">
                                <span className="text-[9px] text-text-dim uppercase font-bold">Status Controls</span>
                                <select 
                                  value={cases.find(c => c.id === selectedCaseId)?.status}
                                  onChange={(e) => handleUpdateCaseStatus(selectedCaseId!, e.target.value as CaseStatus)}
                                  className="w-full bg-black/50 border border-border p-2.5 rounded-lg text-white text-xs font-bold font-mono focus:outline-none focus:border-blue-500"
                                >
                                   {Object.values(CaseStatus).map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
                                </select>
                             </div>
                             <div className="space-y-1">
                                <span className="text-[9px] text-text-dim uppercase font-bold">Severity Override</span>
                                <select 
                                  value={cases.find(c => c.id === selectedCaseId)?.severity}
                                  onChange={(e) => handleUpdateCaseSeverity(selectedCaseId!, e.target.value as CaseSeverity)}
                                  className="w-full bg-black/50 border border-border p-2.5 rounded-lg text-white text-xs font-bold font-mono focus:outline-none focus:border-blue-500"
                                >
                                   {Object.values(CaseSeverity).map(s => <option key={s} value={s}>{s}</option>)}
                                </select>
                             </div>
                          </div>
                       </section>

                       <section className="space-y-4">
                          <label className="text-[10px] font-black uppercase tracking-widest text-text-dim block border-t border-white/5 pt-6">Chronology</label>
                          <div className="space-y-2 text-[10px] font-mono">
                             <div className="flex justify-between">
                                <span className="text-text-dim">Opened</span>
                                <span className="text-white">{cases.find(c => c.id === selectedCaseId)?.createdAt}</span>
                             </div>
                             <div className="flex justify-between">
                                <span className="text-text-dim">Modified</span>
                                <span className="text-white">{cases.find(c => c.id === selectedCaseId)?.updatedAt}</span>
                             </div>
                          </div>
                       </section>

                       <section className="pt-6 border-t border-white/5">
                          <p className="text-[11px] text-text-dim leading-relaxed italic">
                             "{cases.find(c => c.id === selectedCaseId)?.description}"
                          </p>
                       </section>
                    </div>

                    {/* Center Panel: Timeline Feed */}
                    <div className="flex-grow border-r border-border flex flex-col bg-card/20">
                       <div className="p-4 border-b border-border flex items-center justify-between">
                          <h3 className="text-[11px] font-black uppercase tracking-widest text-white">Investigation Timeline</h3>
                          <div className="flex items-center gap-4 text-[9px] font-bold text-text-dim">
                             <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-red-500" /> ALERTS</div>
                             <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-amber-500" /> ACTIONS</div>
                             <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-blue-500" /> NOTES</div>
                          </div>
                       </div>
                       <div className="flex-grow overflow-y-auto p-6 space-y-6 custom-scrollbar">
                          {/* Case Beginning */}
                          <div className="relative pl-8 border-l border-white/10 pb-4">
                             <div className="absolute top-0 left-[-4.5px] w-2 h-2 rounded-full bg-white/20" />
                             <div className="text-[9px] text-text-dim font-mono mb-1">{cases.find(c => c.id === selectedCaseId)?.createdAt}</div>
                             <div className="text-[11px] font-bold text-white uppercase tracking-tight">Case Container Initialized</div>
                             <div className="text-[10px] text-text-dim mt-1">Manual investigation record created by {cases.find(c => c.id === selectedCaseId)?.assignedTo}</div>
                          </div>

                          {/* Linked Alerts */}
                          {cases.find(c => c.id === selectedCaseId)?.alertIds.map(aid => {
                             const alert = alerts.find(a => a.id === aid);
                             if (!alert) return null;
                             return (
                               <div key={aid} className="relative pl-8 border-l border-white/10">
                                  <div className="absolute top-0 left-[-4.5px] w-2 h-2 rounded-full bg-red-500" />
                                  <div className="text-[9px] text-red-500/70 font-mono mb-1">{alert.timestamp}</div>
                                  <div className="bg-red-500/10 border border-red-500/20 p-3 rounded-lg space-y-2">
                                     <div className="flex justify-between items-start">
                                        <div className="text-[11px] font-black text-white uppercase">{alert.title}</div>
                                        <span className="text-[8px] bg-red-500/20 text-red-400 px-1.5 rounded">{alert.type}</span>
                                     </div>
                                     <p className="text-[10px] text-text-dim">{alert.description}</p>
                                  </div>
                               </div>
                             );
                          })}

                          {/* Analyst Notes */}
                          {cases.find(c => c.id === selectedCaseId)?.notes.map(note => (
                             <div key={note.id} className="relative pl-8 border-l border-white/10">
                                <div className="absolute top-0 left-[-4.5px] w-2 h-2 rounded-full bg-blue-500" />
                                <div className="text-[9px] text-blue-400 font-mono mb-1">{note.timestamp}</div>
                                <div className="bg-white/5 border border-white/10 p-3 rounded-lg">
                                   <div className="flex items-center gap-2 mb-2">
                                      <span className="text-[10px] font-black text-white uppercase">{note.analyst}</span>
                                      {note.tag && (
                                        <span className="text-[8px] font-bold border border-blue-500/30 text-blue-400 px-1.5 py-0.5 rounded uppercase">
                                           {note.tag}
                                        </span>
                                      )}
                                   </div>
                                   <p className="text-[11px] text-text-dim leading-relaxed">{note.content}</p>
                                </div>
                             </div>
                          ))}
                       </div>
                       
                       {/* Note Input */}
                       <div className="p-4 border-t border-border bg-card">
                          <div className="flex gap-4">
                             <div className="flex-grow relative">
                                <textarea 
                                  placeholder="Add evidence observation, hypothesis, or recommendation..."
                                  className="w-full bg-black/50 border border-border p-3 rounded-lg text-xs text-white focus:outline-none focus:border-blue-500 resize-none h-20 custom-scrollbar"
                                  id="caseNoteInput"
                                  onKeyDown={(e) => {
                                    if (e.key === 'Enter' && e.ctrlKey) {
                                      const el = e.currentTarget;
                                      if (el.value.trim()) {
                                        handleAddNote(selectedCaseId!, el.value.trim());
                                        el.value = '';
                                      }
                                    }
                                  }}
                                />
                                <div className="absolute bottom-2 right-2 text-[8px] text-text-dim font-mono">CTRL + ENTER TO SUBMIT</div>
                             </div>
                             <div className="flex flex-col gap-2">
                                <button 
                                  onClick={() => {
                                    const el = document.getElementById('caseNoteInput') as HTMLTextAreaElement;
                                    if (el && el.value.trim()) {
                                      handleAddNote(selectedCaseId!, el.value.trim());
                                      el.value = '';
                                    }
                                  }}
                                  className="px-4 h-full bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-[10px] font-black uppercase tracking-widest transition-all"
                                >
                                   Add Note
                                </button>
                             </div>
                          </div>
                       </div>
                    </div>

                    {/* Right Panel: Evidence & Connected Assets */}
                    <div className="w-96 p-6 space-y-8 overflow-y-auto custom-scrollbar">
                       {/* Evidence Section */}
                       <section className="space-y-4">
                          <div className="flex items-center justify-between">
                             <label className="text-[10px] font-black uppercase tracking-widest text-text-dim flex items-center gap-2">
                                <Link size={12} className="text-blue-400" /> Linked Alerts
                             </label>
                             <button className="text-[9px] font-bold text-blue-400 hover:underline uppercase tracking-tight">+ Link Alert</button>
                          </div>
                          <div className="space-y-3">
                             {cases.find(c => c.id === selectedCaseId)?.alertIds.map(aid => {
                                const alert = alerts.find(a => a.id === aid);
                                if (!alert) return null;
                                return (
                                  <div key={aid} className="bg-card border border-border p-3 rounded group">
                                     <div className="flex justify-between items-start mb-1">
                                        <div className="text-[9px] font-mono text-text-dim">{alert.timestamp}</div>
                                        <button className="opacity-0 group-hover:opacity-100 p-1 hover:bg-white/5 rounded transition-all">
                                           <Trash2 size={10} className="text-text-dim hover:text-red-500" />
                                        </button>
                                     </div>
                                     <div className="text-[10px] font-bold text-white mb-2 leading-tight">{alert.title}</div>
                                     <div className="flex justify-between items-center text-[8px] font-mono">
                                        <span className="text-text-dim">{alert.deviceId}</span>
                                        <span className={cn(
                                          "px-1 rounded",
                                          alert.severity === 'high' ? "text-red-500 bg-red-500/10" : "text-amber-500 bg-amber-500/10"
                                        )}>{alert.severity.toUpperCase()}</span>
                                     </div>
                                  </div>
                                );
                             })}
                          </div>
                       </section>

                       {/* Assets Section */}
                       <section className="space-y-4">
                          <div className="flex items-center justify-between pt-6 border-t border-white/5">
                             <label className="text-[10px] font-black uppercase tracking-widest text-text-dim flex items-center gap-2">
                                <Monitor size={12} className="text-blue-400" /> Impacted Devices
                             </label>
                             <button className="text-[9px] font-bold text-blue-400 hover:underline uppercase tracking-tight">+ Add Device</button>
                          </div>
                          <div className="space-y-3">
                             {cases.find(c => c.id === selectedCaseId)?.deviceIds.map(did => {
                                const device = devices.find(d => d.id === did);
                                if (!device) return null;
                                return (
                                  <div 
                                    key={did} 
                                    onClick={() => { setActiveTab('devices'); setSelectedDeviceId(did); }}
                                    className="bg-card border border-border p-3 rounded flex items-center justify-between hover:bg-white/2 cursor-pointer transition-all"
                                  >
                                     <div className="flex items-center gap-3">
                                        <div className="w-2 h-2 rounded-full bg-green-500" />
                                        <div>
                                           <div className="text-[11px] font-bold text-white">{device.hostname}</div>
                                           <div className="text-[9px] text-text-dim font-mono">{device.ip}</div>
                                        </div>
                                     </div>
                                     <ArrowUpRight size={14} className="text-text-dim" />
                                  </div>
                                );
                             })}
                          </div>
                       </section>
                    </div>
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>

        {/* New Case Modal */}
        <AnimatePresence>
          {isNewCaseModalOpen && (
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
            >
              <motion.div 
                initial={{ scale: 0.95, y: 20 }}
                animate={{ scale: 1, y: 0 }}
                className="bg-card border border-border w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden"
              >
                <div className="p-6 border-b border-border flex items-center justify-between bg-white/2">
                   <div className="flex items-center gap-3">
                      <Briefcase className="text-blue-400" />
                      <h2 className="text-xl font-black text-white tracking-widest uppercase">Create New Investigation</h2>
                   </div>
                   <button onClick={() => setIsNewCaseModalOpen(false)} className="text-text-dim hover:text-white transition-all"><X size={20} /></button>
                </div>
                <div className="p-8 space-y-6 overflow-y-auto max-h-[70vh] custom-scrollbar">
                   <div className="space-y-2">
                      <label className="text-[10px] font-black uppercase tracking-widest text-text-dim block">Investigation Title</label>
                      <input 
                        type="text" 
                        placeholder="e.g. Lateral Movement detected on WS-04 Segment"
                        className="w-full bg-white/2 border border-border p-3 rounded-lg text-sm text-white focus:outline-none focus:border-blue-500 transition-all font-bold"
                        id="newCaseTitle"
                      />
                   </div>

                   <div className="grid grid-cols-2 gap-6">
                      <div className="space-y-2">
                         <label className="text-[10px] font-black uppercase tracking-widest text-text-dim block">Initial Severity</label>
                         <select id="newCaseSeverity" className="w-full bg-white/2 border border-border p-3 rounded-lg text-sm text-white font-bold focus:outline-none focus:border-blue-500">
                            {Object.values(CaseSeverity).map(s => <option key={s} value={s}>{s}</option>)}
                         </select>
                      </div>
                      <div className="space-y-2">
                         <label className="text-[10px] font-black uppercase tracking-widest text-text-dim block">Assigned Analyst</label>
                         <input 
                           type="text" 
                           defaultValue={username}
                           className="w-full bg-white/2 border border-border p-3 rounded-lg text-sm text-text-dim font-bold cursor-not-allowed opacity-50"
                           disabled
                         />
                      </div>
                   </div>

                   <div className="space-y-2">
                      <label className="text-[10px] font-black uppercase tracking-widest text-text-dim block">Full Abstract / Description</label>
                      <textarea 
                        placeholder="Detail the hypothesis and initial evidence observed (min 20 chars)..."
                        className="w-full bg-white/2 border border-border p-3 rounded-lg text-sm text-white h-32 focus:outline-none focus:border-blue-500 transition-all resize-none custom-scrollbar"
                        id="newCaseDesc"
                      />
                   </div>

                   <div className="grid grid-cols-2 gap-6">
                      <div className="space-y-2">
                         <label className="text-[10px] font-black uppercase tracking-widest text-text-dim block">Link Assets (Search IP/Hostname)</label>
                         <div className="max-h-32 overflow-y-auto border border-border rounded-lg bg-white/2 p-2 custom-scrollbar">
                            {devices.slice(0, 10).map(d => (
                               <label key={d.id} className="flex items-center gap-2 p-1.5 hover:bg-white/5 rounded cursor-pointer group">
                                  <input type="checkbox" className="case-device-check" value={d.id} />
                                  <span className="text-[10px] font-bold text-white group-hover:text-blue-400">{d.hostname}</span>
                                  <span className="text-[9px] text-text-dim font-mono ml-auto">{d.ip}</span>
                               </label>
                            ))}
                         </div>
                      </div>
                      <div className="space-y-2">
                         <label className="text-[10px] font-black uppercase tracking-widest text-text-dim block">Link Pivot Alerts</label>
                         <div className="max-h-32 overflow-y-auto border border-border rounded-lg bg-white/2 p-2 custom-scrollbar">
                            {alerts.slice(0, 10).map(a => (
                               <label key={a.id} className="flex items-center gap-2 p-1.5 hover:bg-white/5 rounded cursor-pointer group">
                                  <input type="checkbox" className="case-alert-check" value={a.id} />
                                  <span className="text-[10px] font-bold text-white truncate w-32 group-hover:text-blue-400">{a.title}</span>
                                  <span className="text-[8px] bg-red-500/10 text-red-500 px-1 rounded ml-auto">{a.id}</span>
                                </label>
                            ))}
                         </div>
                      </div>
                   </div>
                </div>
                <div className="p-6 bg-white/2 border-t border-border flex gap-3">
                   <button 
                     onClick={() => setIsNewCaseModalOpen(false)}
                     className="flex-grow py-3 px-4 bg-white/5 hover:bg-white/10 text-text-dim text-[10px] font-black uppercase tracking-widest rounded-lg transition-all"
                   >
                      Discard Draft
                   </button>
                   <button 
                     onClick={() => {
                        const title = (document.getElementById('newCaseTitle') as HTMLInputElement).value;
                        const desc = (document.getElementById('newCaseDesc') as HTMLTextAreaElement).value;
                        const severity = (document.getElementById('newCaseSeverity') as HTMLSelectElement).value as CaseSeverity;
                        
                        if (!title || desc.length < 20) {
                           alert("Please provide a title and a description (min 20 chars).");
                           return;
                        }

                        const deviceIds = Array.from(document.querySelectorAll('.case-device-check:checked')).map(el => (el as HTMLInputElement).value);
                        const alertIds = Array.from(document.querySelectorAll('.case-alert-check:checked')).map(el => (el as HTMLInputElement).value);

                        handleCreateCase({
                           title,
                           description: desc,
                           severity,
                           deviceIds,
                           alertIds
                        });
                        setIsNewCaseModalOpen(false);
                     }}
                     className="flex-[2] py-3 px-4 bg-blue-600 hover:bg-blue-700 text-white text-[10px] font-black uppercase tracking-widest rounded-lg transition-all shadow-[0_0_20px_rgba(37,99,235,0.3)]"
                   >
                      Initialize Investigation Workflow
                   </button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Action Confirmation Modal */}
        <ActionConfirmModal 
          config={actionModal} 
          onClose={() => setActionModal({ ...actionModal, show: false })}
          onConfirm={(reason, duration, severity) => {
            const actionId = actions.find(a => a.target === actionModal.target && a.status === 'PENDING')?.id || `act-${Math.random().toString(36).substr(2, 9)}`;
            
            // If it doesn't exist in actions yet (e.g. from alert), add it
            if (!actions.find(a => a.id === actionId)) {
               setActions(prev => [{
                 id: actionId,
                 type: actionModal.type,
                 target: actionModal.target,
                 triggeredBy: actionModal.triggeredBy,
                 triggeredAt: Date.now(),
                 reason,
                 severity,
                 status: 'PENDING'
               }, ...prev]);
            }

            handleActionConfirm(actionId, reason, duration, severity);
            setActionModal({ ...actionModal, show: false });
          }}
        />

        {/* Undo Toasts */}
        <div className="fixed bottom-16 right-4 z-[200] flex flex-col gap-2">
           {toasts.map(toast => (
             <motion.div
               key={toast.id}
               initial={{ x: 100, opacity: 0 }}
               animate={{ x: 0, opacity: 1 }}
               exit={{ x: 100, opacity: 0 }}
               className="bg-card border border-blue-500 shadow-lg p-4 rounded-lg w-80 relative overflow-hidden"
             >
                <div className="absolute bottom-0 left-0 h-1 bg-blue-500 transition-all" style={{ width: `${(toast.timeLeft / 10) * 100}%` }} />
                <div className="flex justify-between items-center">
                   <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2 text-green-500 font-bold text-xs">
                         <CheckCircle2 size={14} />
                         <span>Action Applied</span>
                      </div>
                      <p className="text-[10px] text-white line-clamp-2">{toast.message}</p>
                   </div>
                   <button 
                     onClick={() => undoAction(toast.id, toast.actionId)}
                     className="px-3 py-1 bg-white/10 hover:bg-white/20 text-white rounded text-[10px] font-bold uppercase transition-all"
                   >
                      Undo ({toast.timeLeft}s)
                   </button>
                </div>
             </motion.div>
           ))}
           {notifications.map(notif => (
             <motion.div
               key={notif.id}
               initial={{ x: 100, opacity: 0 }}
               animate={{ x: 0, opacity: 1 }}
               exit={{ x: 100, opacity: 0 }}
               className={cn(
                 "bg-card border shadow-xl p-4 rounded-lg w-80 relative overflow-hidden",
                 notif.severity === 'HIGH' ? "border-red-500 shadow-red-500/10" : "border-amber-500 shadow-amber-500/10"
               )}
             >
                <div className="flex justify-between items-start mb-2">
                   <div className={cn(
                     "text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded",
                     notif.severity === 'HIGH' ? "bg-red-500 text-white" : "bg-amber-500 text-white"
                   )}>
                      {notif.title}
                   </div>
                   <button 
                     onClick={() => setNotifications(prev => prev.filter(n => n.id !== notif.id))}
                     className="text-text-dim hover:text-white"
                   >
                      <X size={14} />
                   </button>
                </div>
                <p className="text-[11px] text-white font-medium mb-1 leading-tight">{notif.message}</p>
                <div className="text-[8px] text-text-dim font-mono uppercase tracking-tighter">
                   {notif.timestamp} • DRIFTWATCH SENSOR DETECT
                </div>
                {notif.severity === 'HIGH' && (
                  <div className="absolute -right-4 -top-4 opacity-10 rotate-12">
                     <AlertTriangle size={48} />
                  </div>
                )}
             </motion.div>
           ))}
        </div>
      </main>

      <footer className="mt-auto px-4 py-2 border-t border-border flex justify-between items-center text-[10px] text-text-dim font-mono bg-card overflow-hidden">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1">
            <Zap size={12} className="text-blue-500" />
            <span>Telemetry: {isConnected ? "Live stream active" : "Polling-only"}</span>
          </div>
          <div className="hidden sm:block opacity-30">|</div>
          <div className="hidden sm:block">Devices tracked: {mode === 'network' ? devices.length : 1}</div>
        </div>
        <div className="flex items-center gap-4">
           <div className="flex items-center gap-1">
             <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
             <span>DRIFTWATCH NDR v1.0</span>
           </div>
           <div className="hidden sm:flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
              <span>System Stable</span>
           </div>
        </div>
      </footer>
      
      {!isConnected && (
        <div className="fixed top-20 right-4 z-50 bg-amber-500/10 border border-amber-500/50 text-amber-500 px-4 py-2 rounded text-[10px] font-bold uppercase tracking-widest backdrop-blur-md">
           DEMO MODE ACTIVE — BACKEND UNREACHABLE
        </div>
      )}

      {/* SENTINEL MODE Modal */}
      <AnimatePresence>
        {showSetupModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-card border border-border max-w-lg w-full rounded-lg shadow-2xl overflow-hidden"
            >
              <div className="p-6">
                <div className="flex items-center gap-3 mb-6">
                  <div className="bg-blue-500/20 p-2 rounded-lg">
                    <Network className="text-blue-400" size={24} />
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-white tracking-tight">SENTINEL MODE REQUIREMENTS</h2>
                    <p className="text-xs text-text-dim">Configure your environment for full segment capture</p>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="p-4 bg-white/5 rounded-lg border border-border">
                    <div className="flex items-start gap-4">
                      <CheckCircle2 size={18} className="text-green-500 flex-shrink-0 mt-0.5" />
                      <div>
                        <h4 className="text-sm font-bold text-white mb-1">RECOMMENDED: Bridged Adapter</h4>
                        <p className="text-xs text-text-dim">Makes your VM appear as a true network node. Allows the sensor to see traffic from your host, phones, and other devices.</p>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 bg-white/5 rounded-lg border border-border">
                    <div className="flex items-start gap-4">
                      <div className="w-[18px] h-[18px] border-2 border-amber-500/50 rounded-full flex-shrink-0 mt-0.5" />
                      <div>
                        <h4 className="text-sm font-bold text-white mb-1">ALTERNATIVE: NAT + Promiscuous</h4>
                        <p className="text-xs text-text-dim">Functional, but may suffer from partial visibility. Host-only networking will NOT work for sentinel monitoring.</p>
                      </div>
                    </div>
                  </div>
                  
                  {capabilities && !capabilities.promiscuous_mode && (
                    <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3">
                       <AlertCircle size={16} className="text-red-400" />
                       <span className="text-[10px] text-red-400 font-bold uppercase tracking-wide">Backend: Non-root privileges detected. Capture depth may be limited.</span>
                    </div>
                  )}
                </div>

                <div className="mt-8 flex gap-3">
                  <button 
                    onClick={() => { setShowSetupModal(false); setHasDismissedSetupModal(true); }}
                    className="flex-grow py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded text-xs uppercase tracking-widest transition-colors"
                  >
                    Got it, start monitoring
                  </button>
                  <button 
                    onClick={() => { setShowSetupModal(false); setMode('local'); }}
                    className="px-6 py-3 border border-border hover:bg-white/5 text-text-dim font-bold rounded text-xs uppercase tracking-widest transition-colors"
                  >
                    Not now
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
