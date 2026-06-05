# GuardianAI Desktop

**System-level AI Security for Windows, macOS, and Linux**

by Neuronium Engineers · Frankfurt am Main

## Features

- 🌐 **Network Proxy** — intercepts ALL AI API traffic (OpenAI, Anthropic, Gemini, Mistral, ElevenLabs, Stability AI, and more)
- 📋 **Clipboard Monitor** — scans copied AI content in real-time
- 🔍 **Layer 1 Pattern** — 19 threat patterns, <5ms
- 🧠 **Layer 2 Semantic** — LLM-powered analysis, ~50ms
- 🖥️ **System Tray** — runs in background, always protected
- 🔔 **Desktop Notifications** — instant alerts on critical threats
- 📊 **Threat Dashboard** — full scan history and statistics

## Monitored AI APIs

OpenAI · Anthropic · Google Gemini · Mistral · Groq · Cohere · Together AI · Replicate · Stability AI · ElevenLabs · and more

## Installation

### Prerequisites
- Node.js 18+
- npm 9+

### Development
```bash
npm install
npm start
```

### Build
```bash
npm run build:win    # Windows (.exe)
npm run build:mac    # macOS (.dmg)
npm run build:linux  # Linux (.AppImage)
```

## Setup

1. Install and launch GuardianAI
2. Go to **Settings** → enter your API key (`gai_live_xxx`)
3. Get your key at [guardianai-self.vercel.app/keys](https://guardianai-self.vercel.app/keys)
4. Network proxy starts automatically on `127.0.0.1:8877`

## How it works

GuardianAI runs a local HTTP proxy on port 8877. All traffic routed through it is scanned before reaching AI APIs. Critical threats are blocked and you receive an instant desktop notification.

## License

Apache 2.0
