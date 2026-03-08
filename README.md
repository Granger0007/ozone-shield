<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0b0b0d,50:1a1a2e,100:00d4ff&height=180&section=header&text=OZONE%20Shield&fontSize=52&fontColor=ffffff&fontAlignY=38&desc=AI-Powered%20Scam%20Message%20Detector&descSize=18&descAlignY=58&descColor=00d4ff" />

[![Live](https://img.shields.io/badge/Status-Live%20%26%20Production%20Ready-00d4ff?style=for-the-badge)](https://ozone-shield.netlify.app)
[![Netlify](https://img.shields.io/badge/Hosted%20on-Netlify-00C7B7?style=for-the-badge&logo=netlify&logoColor=white)](https://ozone-shield.netlify.app)
[![Anthropic](https://img.shields.io/badge/Powered%20by-Claude%20AI-EE3124?style=for-the-badge)](https://anthropic.com)

[![Try It](https://img.shields.io/badge/▶%20Try%20It%20Now-ozone--shield.netlify.app-00d4ff?style=for-the-badge)](https://ozone-shield.netlify.app)

</div>



## What It Does

Paste any suspicious message — email, SMS, WhatsApp, or letter — and receive an instant AI-powered verdict with a confidence percentage, severity rating, specific reasons tied to the actual message, and a plain-English action guide.

No account. No download. No technical knowledge required.



## Verdict System

| Verdict | Meaning | Action |
|:-------:|---------|--------|
| ✅ **SAFE** | No meaningful scam signals detected | Verified — proceed with appropriate caution |
| ⚠️ **SUSPICIOUS** | 1–3 signals present | Told exactly what to check before responding |
| 🚨 **SCAM** | Multiple high-confidence signals | Do not click, do not call back — report to Action Fraud: 0300 123 2040 |
| ❌ **INVALID** | Input was not a real message | Prompted to paste a genuine message |

Each result includes:
- **Confidence** — 0–100%, calibrated to signal strength
- **Severity** — Low / Medium / Critical
- **Reasons** — up to 3 specific reasons tied to the actual message content
- **What to do** — one clear action instruction written for a non-technical person



## Architecture

```
Browser (index.html)
       │
       │  POST /api/analyse
       │  { message: "..." }
       ▼
Netlify Serverless Function (analyse.js)
       │  API key stored server-side — never exposed to browser
       │
       │  POST /v1/messages
       ▼
Anthropic API (claude-sonnet-4-5)
       │
       │  Structured JSON verdict
       ▼
Browser renders result
```

**Stack:**
- Frontend — single static HTML file, zero external dependencies
- Backend — Netlify serverless function (Node.js)
- AI — Claude claude-sonnet-4-5 via Anthropic API
- Hosting — Netlify (GitHub-connected auto-deploy)
- Version control — GitHub



## Security

| Control | Implementation |
|---------|---------------|
| API key storage | Netlify environment variable — never in code, never in browser |
| CORS | Requests accepted only from `ozone-shield.netlify.app` and `localhost` |
| Rate limiting | 10 requests per IP per minute — blocks bots and abuse |
| Input sanitisation | Strips null bytes and control characters before processing |
| Request size limit | 16KB maximum — blocks oversized payloads |
| Content-Type enforcement | Only `application/json` accepted |
| Request timeout | 25 seconds on all Anthropic API calls |
| CSP headers | Prevents XSS, clickjacking, and injection attacks |
| HSTS | Forces HTTPS for 1 year — no HTTP downgrade possible |
| Error sanitisation | Internal error details never exposed to the browser |



## Detection Signal Categories

The system prompt analyses messages across five signal categories:

1. **Payment red flags** — gift cards, cryptocurrency, wire transfers, time-limited financial requests
2. **Psychological manipulation** — urgency, fear, greed, authority impersonation, curiosity hooks
3. **URL and identity anomalies** — typosquatting, character substitution, mismatched sender identity
4. **Language and obfuscation signals** — deliberate misspellings, inconsistent grammar, generic greetings
5. **Structural scam patterns** — requests for credentials, OTP codes, instructions to act outside official channels



## Repository Structure

```
ozone-shield/
├── index.html                    ← Complete frontend — UI, styling, API calls
├── netlify/
│   └── functions/
│       └── analyse.js            ← Serverless proxy — security, sanitisation, AI call
├── netlify.toml                  ← Security headers, CSP policy, function config
└── README.md                     ← This file
```



## Build Summary

| Phase | Description | Status |
|:-----:|-------------|:------:|
| 1 | Environment setup — VS Code, Git, GitHub, Anthropic API | ✅ |
| 2 | System prompt engineering — signal categories, JSON schema, test cases | ✅ |
| 3 | HTML frontend — dark theme, textarea, result rendering, cooldown | ✅ |
| 3B | Design overhaul — shield logo, typography, layout | ✅ |
| 4 | Netlify deployment — GitHub-connected auto-deploy, live URL | ✅ |
| 5 | End-to-end testing — live scam and safe message tests | ✅ |
| 6 | API key security — serverless proxy, key moved to environment variables | ✅ |
| 7 | Security hardening — rate limiting, CORS, CSP, input sanitisation | ✅ |



## The Problem It Solves

Over 3.4 billion phishing messages are sent every day. Most people lack the tools or knowledge to quickly assess whether a message is genuine. Existing solutions are either too technical, buried in government websites, or require checking multiple sources.

OZONE Shield reduces the assessment to one action: paste the message, get the verdict.



## Roadmap

- [ ] Custom domain — ozonesecurity.ai
- [ ] Anthropic API spending limit
- [ ] URL scanner — analyse suspicious links as well as text
- [ ] Mobile app — React Native (iOS and Android)
- [ ] Browser extension — right-click any message to scan instantly
- [ ] API endpoint — allow third-party integration of OZONE Shield verdicts
- [ ] OZONE Security product suite — expand into broader AI threat protection



## Built By

**Bhargav Baranda** — OZONE Security  
[linkedin.com/in/bhargav-baranda](https://linkedin.com/in/bhargav-baranda) · [youtube.com/@Granger-Security](https://youtube.com/@Granger-Security)



<div align="center">

*Built from zero to production in a single session.*  
*Live. Secured. Ready.*

[![Try OZONE Shield](https://img.shields.io/badge/▶%20Try%20It-ozone--shield.netlify.app-00d4ff?style=for-the-badge)](https://ozone-shield.netlify.app)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00d4ff,50:1a1a2e,100:0b0b0d&height=100&section=footer"/>

</div>
