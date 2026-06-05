/**
 * GuardianAI Desktop — Main Process
 * System-level AI security monitoring
 */

const { app, BrowserWindow, Tray, Menu, ipcMain, Notification, nativeImage } = require("electron");
const path = require("path");
const https = require("https");
const http = require("http");

const API_BASE = "https://guardianai-api-6b1d.onrender.com";
let mainWindow = null;
let tray = null;
let isMonitoring = false;
let config = {
  api_key: "",
  protection_enabled: true,
  use_semantic: false,
  scanned_count: 0,
  blocked_count: 0,
};

// ── Store (simple JSON file) ──────────────────────────────────────────────
const Store = require("electron-store");
const store = new Store({ name: "guardianai-config" });

function loadConfig() {
  const saved = store.get("config");
  if (saved) config = { ...config, ...saved };
}

function saveConfig() {
  store.set("config", config);
}

// ── Window ────────────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 680,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true,
    },
    title: "GuardianAI",
    show: false,
    backgroundColor: "#f8f7f4",
  });

  mainWindow.loadFile(path.join(__dirname, "../ui/index.html"));

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
  });

  mainWindow.on("close", (e) => {
    e.preventDefault();
    mainWindow.hide();
  });
}

// ── System Tray ───────────────────────────────────────────────────────────
function createTray() {
  const icon = nativeImage.createEmpty();
  tray = new Tray(icon);

  updateTrayMenu();
  tray.on("click", () => {
    if (mainWindow?.isVisible()) {
      mainWindow.hide();
    } else {
      mainWindow?.show();
    }
  });
}

function updateTrayMenu() {
  const menu = Menu.buildFromTemplate([
    {
      label: `GuardianAI — ${isMonitoring ? "Protected" : "Inactive"}`,
      enabled: false,
    },
    { type: "separator" },
    {
      label: `Scanned: ${config.scanned_count}`,
      enabled: false,
    },
    {
      label: `Blocked: ${config.blocked_count}`,
      enabled: false,
    },
    { type: "separator" },
    {
      label: isMonitoring ? "Pause protection" : "Start protection",
      click: toggleMonitoring,
    },
    {
      label: "Open dashboard",
      click: () => mainWindow?.show(),
    },
    { type: "separator" },
    {
      label: "Quit GuardianAI",
      click: () => app.exit(0),
    },
  ]);

  tray.setContextMenu(menu);
  tray.setToolTip(`GuardianAI — ${isMonitoring ? "Protected" : "Inactive"}`);
}

function toggleMonitoring() {
  isMonitoring = !isMonitoring;
  updateTrayMenu();
  mainWindow?.webContents.send("monitoring-status", isMonitoring);
}

// ── API Scanner ───────────────────────────────────────────────────────────
async function scanText(text, scanType = "input") {
  if (!config.api_key || !config.protection_enabled) return null;

  return new Promise((resolve) => {
    const endpoint = scanType === "input" ? "/v1/scan/input" : "/v1/scan/output";
    const body = JSON.stringify(
      scanType === "input"
        ? { text, use_semantic: config.use_semantic }
        : { text, auto_redact: true }
    );

    const options = {
      hostname: "guardianai-api-6b1d.onrender.com",
      path: endpoint,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${config.api_key}`,
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => data += chunk);
      res.on("end", () => {
        try {
          const result = JSON.parse(data);
          config.scanned_count++;
          if (!result.is_safe) config.blocked_count++;
          saveConfig();
          updateTrayMenu();
          mainWindow?.webContents.send("scan-result", { result, text: text.substring(0, 100), scanType });

          // Desktop notification for threats
          if (!result.is_safe) {
            const level = (result.threat_level || "").toString().toLowerCase();
            if (level.includes("critical") || level.includes("high")) {
              showThreatNotification(result.threats?.[0]?.type || "threat", scanType);
            }
          }

          resolve(result);
        } catch {
          resolve(null);
        }
      });
    });

    req.on("error", () => resolve(null));
    req.setTimeout(10000, () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

function showThreatNotification(threatType, scanType) {
  if (Notification.isSupported()) {
    new Notification({
      title: "⚠️ GuardianAI — Threat Detected",
      body: `${scanType === "input" ? "Prompt" : "Response"} blocked: ${threatType.replace(/_/g, " ")}`,
      urgency: "critical",
    }).show();
  }
}

// ── Network Monitor (Proxy approach) ─────────────────────────────────────
// Intercepts HTTP traffic to AI APIs on localhost proxy
let proxyServer = null;

function startNetworkProxy() {
  const AI_HOSTS = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.groq.com",
    "api.cohere.ai",
    "api.together.xyz",
    "api.replicate.com",
    "api.stability.ai",
    "api.elevenlabs.io",
  ];

  proxyServer = http.createServer(async (req, res) => {
    let body = "";
    req.on("data", (chunk) => body += chunk);
    req.on("end", async () => {
      // Scan request body if it contains AI prompt
      if (body && body.length > 0) {
        try {
          const parsed = JSON.parse(body);
          const prompt = extractPrompt(parsed);
          if (prompt) {
            const result = await scanText(prompt, "input");
            if (result && !result.is_safe) {
              res.writeHead(403, { "Content-Type": "application/json" });
              res.end(JSON.stringify({
                error: "GuardianAI blocked this request",
                threat: result.threats?.[0]?.type,
                confidence: result.threats?.[0]?.confidence,
              }));
              return;
            }
          }
        } catch { /* not JSON, pass through */ }
      }

      // Forward request to actual API
      forwardRequest(req, res, body);
    });
  });

  proxyServer.listen(8877, "127.0.0.1", () => {
    console.log("[GuardianAI] Network proxy running on 127.0.0.1:8877");
    isMonitoring = true;
    updateTrayMenu();
  });
}

function extractPrompt(body) {
  // OpenAI/Anthropic format
  if (body?.messages?.length > 0) {
    const last = body.messages[body.messages.length - 1];
    if (typeof last?.content === "string") return last.content;
    if (Array.isArray(last?.content)) {
      return last.content.find(c => c.type === "text")?.text || null;
    }
  }
  // Generic prompt field
  return body?.prompt || body?.input || body?.text || null;
}

function forwardRequest(req, res, body) {
  // Simple passthrough — in production would route to actual API host
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ forwarded: true }));
}

// ── Clipboard Monitor ─────────────────────────────────────────────────────
const { clipboard } = require("electron");
let lastClipboard = "";
let clipboardInterval = null;

function startClipboardMonitor() {
  clipboardInterval = setInterval(async () => {
    if (!config.protection_enabled || !config.api_key) return;

    const current = clipboard.readText();
    if (current !== lastClipboard && current.length > 20 && current.length < 5000) {
      lastClipboard = current;
      // Scan clipboard content in background
      const result = await scanText(current, "input");
      if (result && !result.is_safe) {
        mainWindow?.webContents.send("clipboard-threat", {
          result,
          preview: current.substring(0, 100),
        });
      }
    }
  }, 2000);
}

// ── IPC Handlers ──────────────────────────────────────────────────────────
ipcMain.handle("get-config", () => config);

ipcMain.handle("save-config", (_, newConfig) => {
  config = { ...config, ...newConfig };
  saveConfig();
  updateTrayMenu();
  return config;
});

ipcMain.handle("scan-text", async (_, { text, scanType }) => {
  return await scanText(text, scanType);
});

ipcMain.handle("get-stats", () => ({
  scanned: config.scanned_count,
  blocked: config.blocked_count,
  monitoring: isMonitoring,
  proxy_port: 8877,
}));

ipcMain.handle("start-monitoring", () => {
  startNetworkProxy();
  startClipboardMonitor();
  return true;
});

ipcMain.handle("stop-monitoring", () => {
  proxyServer?.close();
  if (clipboardInterval) clearInterval(clipboardInterval);
  isMonitoring = false;
  updateTrayMenu();
  return true;
});

// ── App Lifecycle ─────────────────────────────────────────────────────────
app.whenReady().then(() => {
  loadConfig();
  createWindow();
  createTray();
  startNetworkProxy();
  startClipboardMonitor();
});

app.on("window-all-closed", () => {
  // Keep running in background (tray)
});

app.on("before-quit", () => {
  proxyServer?.close();
  if (clipboardInterval) clearInterval(clipboardInterval);
  saveConfig();
});
