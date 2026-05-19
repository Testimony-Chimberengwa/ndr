/// <reference types="vite/client" />
export const CONFIG = {
  // Use relative paths to talk to the same server
  API_BASE: '', 
  WS_BASE: `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`,
  
  // Polling intervals
  DEVICE_POLL_MS: 3000,      // poll /api/devices every 3 seconds
  FLOW_POLL_MS: 2000,        // poll /api/flows every 2 seconds  
  METRICS_POLL_MS: 1000,     // poll /api/metrics every 1 second
  ALERT_POLL_MS: 5000,       // poll /api/alerts every 5 seconds
}
