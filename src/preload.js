/**
 * GuardianAI Preload Script
 * Exposes safe IPC bridge to renderer
 */
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("guardian", {
  getConfig: () => ipcRenderer.invoke("get-config"),
  saveConfig: (config) => ipcRenderer.invoke("save-config", config),
  scanText: (text, scanType) => ipcRenderer.invoke("scan-text", { text, scanType }),
  getStats: () => ipcRenderer.invoke("get-stats"),
  startMonitoring: () => ipcRenderer.invoke("start-monitoring"),
  stopMonitoring: () => ipcRenderer.invoke("stop-monitoring"),

  // Event listeners
  onScanResult: (cb) => ipcRenderer.on("scan-result", (_, data) => cb(data)),
  onClipboardThreat: (cb) => ipcRenderer.on("clipboard-threat", (_, data) => cb(data)),
  onMonitoringStatus: (cb) => ipcRenderer.on("monitoring-status", (_, status) => cb(status)),
});
