# DRIFTWATCH NDR — Setup Guide

## Quick Start (Local Machine)

### Requirements
- Python 3.11+
- Node.js 18+
- A machine with VirtualBox/VMware VMs OR other devices 
  on the same WiFi/LAN

### Step 1 — Backend

```bash
pip install fastapi uvicorn psutil scapy requests
sudo python backend/sensor.py
```

**Must run with sudo** for promiscuous packet capture and 
ARP scanning to see other devices.

### Step 2 — Frontend

```bash
npm install
npm run dev
```

Open http://localhost:5173

### Step 3 — See your devices

The system will automatically discover:
- VMs running in VirtualBox (MAC prefix 08:00:27)
- VMs running in VMware (MAC prefix 00:0C:29)
- Phones connected to your hotspot
- Other laptops on the same WiFi
- Your router/gateway

### For your VM to show up:
Set the VM network adapter to BRIDGED mode in VirtualBox:
Settings → Network → Adapter 1 → Attached to: Bridged Adapter

This gives the VM a real IP on your network so DRIFTWATCH 
can see its traffic.

### Demo: Trigger nmap detection

Inside your Kali VM run:
```bash
nmap -sS -T2 192.168.1.1/24
```

DRIFTWATCH will detect the port scan within seconds and 
create a HIGH alert: "PORT_SCAN — T1046 Network Service 
Discovery" on the scanning device's card.

### Demo: Trigger beaconing detection

Inside any VM run:
```bash
while true; do curl -s http://example.com > /dev/null; sleep 30; done
```

After 5+ connections at regular intervals DRIFTWATCH will 
flag this as potential C2 beaconing.

## Production Deployment (Docker)

```bash
docker-compose up -d
```

See DRIFTWATCH_NDR_MASTER.md for full deployment guide.
