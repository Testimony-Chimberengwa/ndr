"""
DRIFTWATCH NDR — Backend Sensor Engine
Run with: sudo python sensor.py
Requires: pip install fastapi uvicorn psutil scapy requests
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import psutil
import socket
import threading
import asyncio
import json
import time
from datetime import datetime
from collections import defaultdict, deque
import ipaddress

app = FastAPI(title="DRIFTWATCH NDR", version="1.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], 
  allow_methods=["*"], allow_headers=["*"])

# ============================================================
# GLOBAL STATE
# ============================================================

# All discovered devices: mac → device dict
devices = {}

# Recent flows: list of flow dicts (rolling 10000)
flows = deque(maxlen=10000)

# Alerts: list of alert dicts
alerts = []

# Packet buffer for analysis
packet_buffer = deque(maxlen=50000)

# Connection tracking: (src_ip, dst_ip, dst_port) → stats
connection_tracker = defaultdict(lambda: {
  'count': 0, 'bytes': 0, 'first_seen': None, 'last_seen': None,
  'timestamps': deque(maxlen=100)
})

# Port scan detection: src_ip → set of dst_ports contacted
port_contacts = defaultdict(lambda: defaultdict(set))

# DNS cache: ip → hostname
dns_cache = {}
dns_cache_time = {}
DNS_CACHE_TTL = 60

# Network I/O tracking for per-second rates
last_io = psutil.net_io_counters()
last_io_time = time.time()

# ============================================================
# DEVICE DISCOVERY
# ============================================================

VM_MAC_PREFIXES = {
  '00:0c:29': ('VMware', 'vm'),
  '00:50:56': ('VMware', 'vm'),
  '08:00:27': ('VirtualBox', 'vm'),
  '0a:00:27': ('VirtualBox', 'vm'),
  '00:15:5d': ('Hyper-V', 'vm'),
  '52:54:00': ('QEMU/KVM', 'vm'),
}

APPLE_PREFIXES = ['00:03:93','00:05:02','00:0a:27','00:0a:95',
  'ac:de:48','b8:27:eb','dc:a6:32','e4:5f:01']

def get_mac_vendor(mac: str) -> tuple:
  """Returns (vendor_name, device_type) from MAC prefix"""
  if not mac:
    return ('Unknown', 'unknown')
  prefix = mac[:8].lower()
  if prefix in VM_MAC_PREFIXES:
    return VM_MAC_PREFIXES[prefix]
  for ap in APPLE_PREFIXES:
    if mac.lower().startswith(ap):
      return ('Apple', 'apple')
  return ('Unknown', 'unknown')

def reverse_dns(ip: str) -> str:
  """Cached reverse DNS lookup"""
  now = time.time()
  if ip in dns_cache:
    if now - dns_cache_time.get(ip, 0) < DNS_CACHE_TTL:
      return dns_cache[ip]
  try:
    hostname = socket.gethostbyaddr(ip)[0]
    dns_cache[ip] = hostname
    dns_cache_time[ip] = now
    return hostname
  except:
    dns_cache[ip] = ip
    dns_cache_time[ip] = now
    return ip

def detect_os_from_ttl(ttl: int) -> str:
  """Estimate OS from TTL value"""
  if ttl >= 128:
    return 'Windows'
  elif ttl >= 64:
    return 'Linux/macOS'
  elif ttl >= 255:
    return 'Network Device'
  return 'Unknown'

def get_device_type_from_hostname(hostname: str) -> str:
  h = hostname.lower()
  if any(x in h for x in ['android','samsung','xiaomi','pixel']):
    return 'android'
  if any(x in h for x in ['iphone','ipad','ipod']):
    return 'ios'
  if any(x in h for x in ['macbook','imac','mac-mini']):
    return 'mac'
  if any(x in h for x in ['kali','ubuntu','debian','linux','-vm']):
    return 'linux-vm'
  if h.startswith('desktop-') or h.startswith('laptop-'):
    return 'windows'
  if any(x in h for x in ['router','gateway','mikrotik','openwrt']):
    return 'router'
  return 'unknown'

def update_device(ip: str, mac: str = None, 
                  bytes_sent: int = 0, bytes_recv: int = 0,
                  protocol: str = None, ttl: int = None,
                  dst_port: int = None, src_ip: str = None):
  """Update or create a device entry"""
  key = ip
  now = datetime.utcnow().isoformat()
  
  if key not in devices:
    hostname = reverse_dns(ip)
    vendor, dev_type = get_mac_vendor(mac or '')
    if dev_type == 'unknown':
      dev_type = get_device_type_from_hostname(hostname)
    
    devices[key] = {
      'id': key,
      'ip': ip,
      'mac': mac or 'Unknown',
      'hostname': hostname,
      'vendor': vendor,
      'device_type': dev_type,
      'os': detect_os_from_ttl(ttl) if ttl else 'Unknown',
      'first_seen': now,
      'last_seen': now,
      'bytes_sent': 0,
      'bytes_recv': 0,
      'protocols': set(),
      'ports_contacted': set(),
      'threat_score': 0,
      'beacon_score': 0,
      'drift_score': 0,
      'recon_score': 0,
      'exfil_score': 0,
      'baseline_status': 'LEARNING',
      'is_watched': False,
      'is_armed': False,
      'is_blocked': False,
      'active_alerts': [],
      'is_vm': dev_type == 'vm',
      'hypervisor': vendor if dev_type == 'vm' else None,
      'activity': [0] * 10 # Activity sparkline mock
    }
  
  d = devices[key]
  d['last_seen'] = now
  d['bytes_sent'] += bytes_sent
  d['bytes_recv'] += bytes_recv
  if protocol:
    d['protocols'].add(protocol)
  if dst_port:
    d['ports_contacted'].add(dst_port)
  if mac and mac != 'Unknown':
    d['mac'] = mac
  
  # Simple activity update
  d['activity'] = d['activity'][1:] + [bytes_sent + bytes_recv]

def check_port_scan(src_ip: str, dst_ip: str, dst_port: int):
  """Detect nmap and port scanning behaviour"""
  port_contacts[src_ip][dst_ip].add(dst_port)
  unique_ports = len(port_contacts[src_ip][dst_ip])
  
  if unique_ports >= 15:
    # Port scan detected
    severity = 'HIGH' if unique_ports > 50 else 'MEDIUM'
    alert = {
      'id': f'alert-{time.time()}',
      'device_id': src_ip,
      'alert_type': 'PORT_SCAN',
      'severity': severity,
      'mitre_technique_id': 'T1046',
      'mitre_technique_name': 'Network Service Discovery',
      'kill_chain_stage': 'RECONNAISSANCE',
      'detection_layer': 'RULE_ENGINE',
      'confidence_score': min(100, unique_ports * 2),
      'description': (
        f'{src_ip} has contacted {unique_ports} unique ports '
        f'on {dst_ip}. Possible nmap or port scanner active.'
      ),
      'src_ip': src_ip,
      'dst_ip': dst_ip,
      'is_read': False,
      'created_at': datetime.utcnow().isoformat(),
      'recommended_action': 'INVESTIGATE',
    }
    # Only add if not already alerted recently
    recent = [a for a in alerts[-20:] 
              if a['device_id'] == src_ip 
              and a['alert_type'] == 'PORT_SCAN']
    if not recent:
      alerts.append(alert)
      # Update device threat score
      if src_ip in devices:
        devices[src_ip]['recon_score'] = min(100, unique_ports * 1.5)
        devices[src_ip]['threat_score'] = devices[src_ip]['recon_score']

def check_beaconing(src_ip: str, dst_ip: str, dst_port: int):
  """Detect regular interval beaconing (C2 activity)"""
  key = (src_ip, dst_ip, dst_port)
  now = time.time()
  connection_tracker[key]['timestamps'].append(now)
  connection_tracker[key]['count'] += 1
  
  timestamps = list(connection_tracker[key]['timestamps'])
  if len(timestamps) >= 5:
    intervals = [timestamps[i+1] - timestamps[i] 
                 for i in range(len(timestamps)-1)]
    if intervals:
      mean_interval = sum(intervals) / len(intervals)
      if mean_interval > 0:
        cv = (sum((x - mean_interval)**2 
                  for x in intervals) / len(intervals))**0.5
        cv = cv / mean_interval  # coefficient of variation
        
        if cv < 0.15 and mean_interval < 300:
          # Very regular intervals = beaconing
          beacon_score = int((1 - cv) * 100)
          alert = {
            'id': f'alert-beacon-{time.time()}',
            'device_id': src_ip,
            'alert_type': 'BEACONING',
            'severity': 'HIGH',
            'mitre_technique_id': 'T1071.001',
            'mitre_technique_name': 'Application Layer Protocol: Web',
            'kill_chain_stage': 'COMMAND_AND_CONTROL',
            'detection_layer': 'RULE_ENGINE',
            'confidence_score': beacon_score,
            'description': (
              f'{src_ip} is making regular callbacks to '
              f'{dst_ip}:{dst_port} every '
              f'{mean_interval:.1f}s (variance: {cv:.2f}). '
              f'Consistent with C2 beaconing.'
            ),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'is_read': False,
            'created_at': datetime.utcnow().isoformat(),
            'recommended_action': 'BLOCK',
          }
          recent = [a for a in alerts[-20:]
                    if a['device_id'] == src_ip
                    and a['alert_type'] == 'BEACONING']
          if not recent:
            alerts.append(alert)
          if src_ip in devices:
            devices[src_ip]['beacon_score'] = beacon_score

# ============================================================
# PACKET CAPTURE (runs in background thread)
# ============================================================

def start_packet_capture():
  """
  Try scapy packet capture first.
  Falls back to psutil net_connections if no root.
  """
  try:
    from scapy.all import sniff, IP, TCP, UDP, ARP, Ether
    
    def process_packet(pkt):
      try:
        # ARP → device discovery
        if ARP in pkt:
          ip = pkt[ARP].psrc
          mac = pkt[ARP].hwsrc
          if ip and ip != '0.0.0.0':
            update_device(ip, mac=mac)
        
        # IP packets → traffic tracking
        if IP in pkt:
          src_ip = pkt[IP].src
          dst_ip = pkt[IP].dst
          ttl = pkt[IP].ttl
          size = len(pkt)
          
          # Skip localhost
          if src_ip == '127.0.0.1' or dst_ip == '127.0.0.1':
            return
          
          protocol = 'TCP' if TCP in pkt else \
                     'UDP' if UDP in pkt else 'OTHER'
          
          src_mac = pkt[Ether].src if Ether in pkt else None
          
          # Update device records
          update_device(src_ip, mac=src_mac, 
                       bytes_sent=size, ttl=ttl,
                       protocol=protocol)
          update_device(dst_ip, bytes_recv=size, 
                       protocol=protocol)
          
          # Track flows
          dst_port = None
          if TCP in pkt:
            dst_port = pkt[TCP].dport
          elif UDP in pkt:
            dst_port = pkt[UDP].dport
          
          if dst_port:
            update_device(src_ip, dst_port=dst_port)
            
            # Port scan detection
            check_port_scan(src_ip, dst_ip, dst_port)
            
            # Beaconing detection
            check_beaconing(src_ip, dst_ip, dst_port)
            
            # Record flow
            flows.append({
              'timestamp': datetime.utcnow().isoformat(),
              'src_ip': src_ip,
              'dst_ip': dst_ip,
              'src_mac': src_mac,
              'dst_port': dst_port,
              'protocol': protocol,
              'size': size,
              'ttl': ttl,
            })
      except Exception as e:
        pass  # Never crash on a single packet
    
    print("[DRIFTWATCH] Starting promiscuous packet capture...")
    sniff(prn=process_packet, store=False, 
          filter="ip or arp")
          
  except PermissionError:
    print("[DRIFTWATCH] No root — using psutil fallback")
    start_psutil_monitor()
  except ImportError:
    print("[DRIFTWATCH] Scapy not installed — using psutil")
    start_psutil_monitor()

def start_psutil_monitor():
  """Fallback: use psutil to monitor connections"""
  while True:
    try:
      conns = psutil.net_connections(kind='inet')
      for conn in conns:
        if conn.raddr and conn.laddr:
          src_ip = conn.laddr.address
          dst_ip = conn.raddr.address
          dst_port = conn.raddr.port
          
          if dst_ip and dst_ip != '127.0.0.1':
            try:
              proc = psutil.Process(conn.pid)
              proc_name = proc.name()
            except:
              proc_name = 'Unknown'
            
            update_device(src_ip, protocol='TCP')
            update_device(dst_ip, protocol='TCP')
            check_port_scan(src_ip, dst_ip, dst_port)
            check_beaconing(src_ip, dst_ip, dst_port)
            
    except Exception as e:
      pass
    time.sleep(1)

# ============================================================
# ARP SCAN — active device discovery
# ============================================================

def arp_scan_local_network():
  """
  Scan local network to discover all devices including 
  VMs, phones on hotspot, other laptops on LAN.
  Runs every 30 seconds.
  """
  while True:
    try:
      from scapy.all import ARP, Ether, srp
      
      # Get local subnet
      for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
          if addr.family == socket.AF_INET:
            ip = addr.address
            netmask = addr.netmask
            if ip.startswith('192.168') or ip.startswith('10.'):
              # Craft ARP request for entire subnet
              try:
                network = ipaddress.IPv4Network(
                  f'{ip}/{netmask}', strict=False)
                target = str(network)
                
                arp_req = Ether(dst='ff:ff:ff:ff:ff:ff') / \
                          ARP(pdst=target)
                answered, _ = srp(arp_req, timeout=2, 
                                   verbose=False)
                
                for sent, received in answered:
                  disc_ip = received.psrc
                  disc_mac = received.hwsrc
                  update_device(disc_ip, mac=disc_mac)
                  print(f"[DISCOVER] {disc_ip} ({disc_mac})")
              except:
                pass
    except:
      # Scapy not available or no permissions
      pass
    
    time.sleep(30)

# ============================================================
# API ENDPOINTS
# ============================================================

def serialize_device(d: dict) -> dict:
  """Convert sets to lists for JSON serialization"""
  return {
    **d,
    'protocols': list(d.get('protocols', [])),
    'ports_contacted': list(d.get('ports_contacted', []))[:50],
  }

@app.get("/api/health")
async def health():
  return {
    "status": "ok",
    "mode": "live",
    "version": "1.0.0",
    "uptime": time.time(),
    "capabilities": {
      "promiscuous_mode": True,  # update based on actual capture mode
      "arp_scan": True,
      "packet_capture": True,
    }
  }

@app.get("/api/capabilities")  
async def capabilities():
  return {
    "promiscuous_mode": True,
    "arp_scan": True,
    "packet_capture": True,
    "database": False,
    "redis": False,
    "gmm_engine": False,
    "kde_engine": False,
    "lowess_engine": False,
  }

@app.get("/api/devices")
async def get_devices():
  return [serialize_device(d) for d in devices.values()]

@app.get("/api/devices/{device_id}")
async def get_device(device_id: str):
  d = devices.get(device_id)
  if not d:
    return {"error": "Device not found"}
  return serialize_device(d)

@app.get("/api/devices/{device_id}/connections")
async def get_device_connections(device_id: str):
  device_flows = [f for f in flows 
                  if f.get('src_ip') == device_id][-100:]
  result = []
  for f in device_flows:
    result.append({
      **f,
      'hostname': reverse_dns(f.get('dst_ip', '')),
      'process': 'Unknown',
    })
  return result

@app.get("/api/devices/{device_id}/recon")
async def get_recon_data(device_id: str):
  ports_map = port_contacts.get(device_id, {})
  all_ports = set()
  for p in ports_map.values():
    all_ports.update(p)
  
  d = devices.get(device_id, {})
  return {
    'recon_score': d.get('recon_score', 0),
    'unique_ports_contacted': len(all_ports),
    'unique_ips_contacted': len(port_contacts.get(device_id, {})),
    'sequential_scan_detected': len(all_ports) > 15,
    'ports': sorted(list(all_ports))[:100],
  }

@app.get("/api/flows")
async def get_flows():
  recent = list(flows)[-500:]
  result = []
  for f in recent:
    result.append({
      **f,
      'src_hostname': reverse_dns(f.get('src_ip','')),
      'dst_hostname': reverse_dns(f.get('dst_ip','')),
    })
  return result

@app.get("/api/alerts")
async def get_alerts():
  return list(reversed(alerts[-200:]))

@app.get("/api/metrics")
async def get_metrics():
  global last_io, last_io_time
  
  current_io = psutil.net_io_counters()
  current_time = time.time()
  elapsed = current_time - last_io_time + 0.00001
  
  sent_rate = (current_io.bytes_sent - last_io.bytes_sent) / elapsed
  recv_rate = (current_io.bytes_recv - last_io.bytes_recv) / elapsed
  
  last_io = current_io
  last_io_time = current_time
  
  return {
    'cpu': psutil.cpu_percent(interval=0.1),
    'ram': psutil.virtual_memory().percent,
    'ram_total': psutil.virtual_memory().total,
    'ram_used': psutil.virtual_memory().used,
    'bytes_sent': current_io.bytes_sent,
    'bytes_recv': current_io.bytes_recv,
    'bytes_sent_per_sec': max(0, sent_rate),
    'bytes_recv_per_sec': max(0, recv_rate),
    'timestamp': current_time,
    'devices_discovered': len(devices),
    'active_alerts': len([a for a in alerts 
                          if not a.get('is_read')]),
  }

# ============================================================
# WEBSOCKET LIVE FEED
# ============================================================

connected_clients = set()

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
  await websocket.accept()
  connected_clients.add(websocket)
  try:
    while True:
      current_io = psutil.net_io_counters()
      
      update = {
        'type': 'full_update',
        'timestamp': datetime.utcnow().isoformat(),
        'devices': [serialize_device(d) 
                    for d in devices.values()],
        'flows': list(flows)[-50:],
        'alerts': list(reversed(alerts[-20:])),
        'metrics': {
          'cpu': psutil.cpu_percent(interval=0.1),
          'ram': psutil.virtual_memory().percent,
          'bytes_sent': current_io.bytes_sent,
          'bytes_recv': current_io.bytes_recv,
          'devices_count': len(devices),
        },
        'new_alerts': [a for a in alerts[-5:] 
                       if not a.get('is_read')],
      }
      
      await websocket.send_text(json.dumps(update))
      await asyncio.sleep(2)
      
  except WebSocketDisconnect:
    connected_clients.discard(websocket)

# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():
  # Start packet capture in background thread
  capture_thread = threading.Thread(
    target=start_packet_capture, daemon=True)
  capture_thread.start()
  
  # Start ARP scanner in background thread
  arp_thread = threading.Thread(
    target=arp_scan_local_network, daemon=True)
  arp_thread.start()
  
  print(\"\"\"
  ██████╗ ██████╗ ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
  ██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
  ██║  ██║██████╔╝██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
  ██║  ██║██╔══██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
  ██████╔╝██║  ██║██║██║        ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
  NDR — Adversarial Drift Detection Engine v1.0
  
  Backend running at http://0.0.0.0:8001
  Frontend should connect to ws://localhost:8001/ws/live
  \"\"\")

if __name__ == "__main__":
  import uvicorn
  uvicorn.run(app, host="0.0.0.0", port=8001)
