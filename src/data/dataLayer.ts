import { CONFIG } from "../config";

// Essential Types (Matching App.tsx where possible)
export interface Device {
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

export interface Flow {
  sourceIp: string;
  destIp: string;
  destHostname: string;
  port: number;
  protocol: string;
  bytes: number;
  timestamp?: string;
}

export interface Alert {
  id: string;
  type: string;
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

export interface Metrics {
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
  devices_discovered?: number;
  active_alerts?: number;
}

export interface KillChainStage {
  stage: string;
  status: 'CLEAN' | 'SUSPECTED' | 'CONFIRMED' | 'CLEARED';
  confidence: number;
  indicators: string[];
  mitre_techniques: string[];
  detection_layer: string;
  first_detected?: string;
}

export interface KillChainData {
  stages: KillChainStage[];
  current_stage: string | 'NONE';
  overall_risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface BaselineData {
  established: boolean;
  learningProgress: number;
  summary: any;
  history: any[];
  deviations: any[];
  params: any;
  anchor: any;
}

export class DataLayer {
  private static instance: DataLayer;
  mode: 'live' | 'demo' = 'demo';
  private initialized = false;

  private constructor() {}

  static getInstance(): DataLayer {
    if (!DataLayer.instance) {
      DataLayer.instance = new DataLayer();
    }
    return DataLayer.instance;
  }

  async initialize() {
    if (this.initialized) return;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      const res = await fetch(`${CONFIG.API_BASE}/api/health`, { signal: controller.signal });
      clearTimeout(timeoutId);
      
      const data = await res.json();
      if (data.status === 'ok') {
        this.mode = 'live';
      } else {
        this.mode = 'demo';
      }
    } catch (e) {
      this.mode = 'demo';
    }
    this.initialized = true;
    console.log(`[DRIFTWATCH] DataLayer initialized in ${this.mode} mode`);
  }

  private async safeFetch(url: string) {
    try {
      const res = await fetch(url);
      const text = await res.text();
      
      if (!res.ok) {
        if (text.includes("Rate exceeded")) {
          console.warn(`[DRIFTWATCH] Rate exceeded for ${url}`);
        } else {
          console.error(`[DRIFTWATCH] HTTP Error ${res.status} for ${url}: ${text.slice(0, 100)}`);
        }
        return null;
      }

      try {
        return JSON.parse(text);
      } catch (e) {
        if (text.includes("Rate exceeded")) {
          console.warn(`[DRIFTWATCH] Rate exceeded (masked as 200) for ${url}`);
        } else {
          console.error(`DataLayer: JSON parse failed for ${url}`, e, "Body prefix:", text.slice(0, 50));
        }
        return null;
      }
    } catch (e) {
      console.error(`DataLayer: fetch failed for ${url}`, e);
      return null;
    }
  }

  async getDevices(): Promise<Device[]> {
    if (this.mode === 'live') {
      const data = await this.safeFetch(`${CONFIG.API_BASE}/api/devices`);
      return data || [];
    }
    return [];
  }

  async getFlows(): Promise<Flow[]> {
    if (this.mode === 'live') {
      const data = await this.safeFetch(`${CONFIG.API_BASE}/api/flows`);
      return data || [];
    }
    return [];
  }

  async getMetrics(): Promise<Metrics | null> {
    if (this.mode === 'live') {
      return await this.safeFetch(`${CONFIG.API_BASE}/api/metrics`);
    }
    return null;
  }

  async getAlerts(): Promise<Alert[]> {
    if (this.mode === 'live') {
      const data = await this.safeFetch(`${CONFIG.API_BASE}/api/alerts`);
      return data || [];
    }
    return [];
  }

  async getDeviceDetail(id: string): Promise<Device | null> {
    if (this.mode === 'live') {
      return await this.safeFetch(`${CONFIG.API_BASE}/api/devices/${id}`);
    }
    return null;
  }

  async getKillChain(id: string): Promise<KillChainData | null> {
    if (this.mode === 'live') {
      return await this.safeFetch(`${CONFIG.API_BASE}/api/devices/${id}/killchain`);
    }
    return null;
  }

  async getBaseline(id: string): Promise<BaselineData | null> {
    if (this.mode === 'live') {
      return await this.safeFetch(`${CONFIG.API_BASE}/api/devices/${id}/baseline`);
    }
    return null;
  }

  async getConnections(id: string): Promise<any[]> {
    if (this.mode === 'live') {
      const data = await this.safeFetch(`${CONFIG.API_BASE}/api/devices/${id}/connections`);
      return data || [];
    }
    return [];
  }

  async getReconData(id: string): Promise<any> {
    if (this.mode === 'live') {
      return await this.safeFetch(`${CONFIG.API_BASE}/api/devices/${id}/recon`);
    }
    return null;
  }

  async getCapabilities(): Promise<any> {
    if (this.mode === 'live') {
      return await this.safeFetch(`${CONFIG.API_BASE}/api/capabilities`);
    }
    return null;
  }

  async getMatrix(): Promise<any | null> {
    if (this.mode === 'live') {
      return await this.safeFetch(`${CONFIG.API_BASE}/api/matrix`);
    }
    return null;
  }

  async getVMs(): Promise<any[]> {
    if (this.mode === 'live') {
      const data = await this.safeFetch(`${CONFIG.API_BASE}/api/vms`);
      return data || [];
    }
    return [];
  }

  async getDeepDive(): Promise<any | null> {
    if (this.mode === 'live') {
      return await this.safeFetch(`${CONFIG.API_BASE}/api/system/deep-dive`);
    }
    return null;
  }

  async postAction(action: any) {
    if (this.mode === 'live') {
      return fetch(`${CONFIG.API_BASE}/api/actions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(action)
      });
    }
  }
}
