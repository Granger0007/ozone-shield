<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0b0b0d,50:1a1a2e,100:00d4ff&height=180&section=header&text=OZONE%20Shield&fontSize=52&fontColor=ffffff&fontAlignY=38&desc=AI-Powered%20Scam%20Message%20Detector&descSize=18&descAlignY=58&descColor=00d4ff" />

[![Live](https://img.shields.io/badge/Status-Live%20%26%20Production%20Ready-00d4ff?style=for-the-badge)](https://ozone-shield.bbaranda055.workers.dev)
[![Cloudflare Workers](https://img.shields.io/badge/Hosted%20on-Cloudflare%20Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://ozone-shield.bbaranda055.workers.dev)
[![Anthropic](https://img.shields.io/badge/Powered%20by-Claude%20AI-EE3124?style=for-the-badge)](https://anthropic.com)

[![Try It](https://img.shields.io/badge/▶%20Try%20It%20Now-ozone--shield.bbaranda055.workers.dev-00d4ff?style=for-the-badge)](https://ozone-shield.bbaranda055.workers.dev)

</div>

---

## What It Does

Paste any suspicious message — email, SMS, WhatsApp, or letter — and receive an instant AI-powered verdict with a confidence percentage, severity rating, specific reasons tied to the actual message, and a plain-English action guide.

No account. No download. No technical knowledge required.

---

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

---

## Architecture

```
Browser (index.html)
       │  hosted on Cloudflare Workers static assets
       │
       │  POST { message: "..." }
       ▼
Cloudflare Worker — ozone-analyse
       │  API key stored as encrypted Worker secret — never exposed to browser
       │  KV-persistent rate limiting (survives cold starts)
       │
       │  POST via Cloudflare AI Gateway
       ▼
AI Gateway (gateway.ai.cloudflare.com) → Anthropic API (claude-sonnet-4-6)
       │
       │  Structured JSON verdict
       ▼
Browser renders result
```

**Stack:**
- Frontend — single static HTML file, served via Cloudflare Workers static assets, zero external dependencies
- Backend — Cloudflare Worker (`ozone-analyse`)
- AI routing — Cloudflare AI Gateway (request analytics, logging, cost observability on every call)
- AI model — Claude `claude-sonnet-4-6` via Anthropic API
- Rate limiting — Cloudflare KV (`ozone-rate-limits` namespace), persistent across all Worker instances globally
- Bot protection — Cloudflare Turnstile (configured account-side)
- Hosting — Cloudflare Workers (Git-connected auto-deploy on `main`)
- Version control — GitHub

---

## Security

| Control | Implementation |
|---------|---------------|
| API key storage | Encrypted Cloudflare Worker secret — validated to match expected format before use, never in code, never in browser |
| CORS | Requests accepted only from explicit allow-list: production origin + local dev origins |
| Rate limiting | 10 requests per IP per minute — KV-backed, persists across Worker cold starts (previous in-memory version reset on every cold start) |
| Input sanitisation | Strips null bytes and control characters before processing |
| Message length bounds | Minimum 10 characters, maximum 4,000 characters |
| Request size limit | 16KB maximum — blocks oversized payloads |
| Content-Type enforcement | Only `application/json` accepted |
| Request timeout | 25 seconds on all Anthropic API calls, via `AbortController` |
| Security headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer` |
| AI Gateway | All model calls routed and logged through Cloudflare AI Gateway for observability |
| Error sanitisation | Internal error details never exposed to the browser |

---

## Detection Signal Categories

The system prompt analyses messages across six signal categories:

1. **Payment red flags** — gift cards, cryptocurrency, wire transfers, "safe account" requests, small customs/delivery fee scams
2. **Psychological manipulation** — urgency, fear, greed, authority impersonation, curiosity hooks, guilt/sympathy pressure
3. **URL and identity anomalies** — typosquatting, character substitution, mismatched sender identity, shortened URLs
4. **Language and obfuscation signals** — deliberate misspellings, inconsistent grammar, generic greetings, unnatural phrasing
5. **Structural scam patterns** — credential/OTP requests, off-channel instructions, too-good-to-be-true offers, remote access requests
6. **UK-specific scam patterns** *(high priority — weighted heavily)* — "Hi Mum/Dad" WhatsApp fraud, safe account fraud, courier fraud, HMRC impersonation, DVLA vehicle tax scams, Royal Mail/Parcel Force delivery scams, NHS impersonation, investment/crypto scams, romance scams, energy rebate scams

---

## Repository Structure

```
ozone-shield/
├── index.html                        ← Frontend — UI, styling, API calls
├── cloudflare/
│   └── ozone-analyse/
│       └── worker.js                 ← Backend Worker — system prompt, security, AI Gateway call
├── README.md                         ← This file
└── legacy/
    └── netlify/                      ← Retired Netlify implementation, kept for history
```

---

## Build Summary

| Phase | Description | Status |
|:-----:|-------------|:------:|
| 1 | Environment setup — VS Code, Git, GitHub, Anthropic API | ✅ |
| 2 | System prompt engineering — 6 signal categories, UK-specific scam patterns, JSON schema | ✅ |
| 3 | HTML frontend — dark theme, textarea, result rendering, cooldown | ✅ |
| 4 | Initial deployment — Netlify (later retired after credit limit reached) | ✅ |
| 5 | Migration to Cloudflare Workers — static assets + Worker backend | ✅ |
| 6 | Security hardening — KV-persistent rate limiting, input sanitisation, CORS, security headers | ✅ |
| 7 | Observability — Cloudflare AI Gateway integration for request logging and cost tracking | ✅ |
| 8 | Bot protection — Cloudflare Turnstile configured | 🔄 verifying enforcement |

---

## The Problem It Solves

Over 3.4 billion phishing messages are sent every day. Most people lack the tools or knowledge to quickly assess whether a message is genuine. Existing solutions are either too technical, buried in government websites, or require checking multiple sources.

OZONE Shield reduces the assessment to one action: paste the message, get the verdict.

---

## Roadmap

- [ ] Custom domain — ozonesecurity.ai
- [ ] Confirm and complete Turnstile server-side verification
- [ ] URL scanner — analyse suspicious links as well as text
- [ ] Mobile app — React Native (iOS and Android)
- [ ] Browser extension — right-click any message to scan instantly
- [ ] API endpoint — allow third-party integration of OZONE Shield verdicts
- [ ] OZONE Security product suite — expand into broader AI threat protection

---

## Built By

**Bhargav Baranda** — OZONE Security
[linkedin.com/in/bhargav-baranda](https://linkedin.com/in/bhargav-baranda) · [youtube.com/@Granger-Security](https://youtube.com/@Granger-Security)

<div align="center">

*Built from zero to production. Migrated, hardened, and still improving.*

[![Try OZONE Shield](https://img.shields.io/badge/▶%20Try%20It-ozone--shield.bbaranda055.workers.dev-00d4ff?style=for-the-badge)](https://ozone-shield.bbaranda055.workers.dev)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00d4ff,50:1a1a2e,100:0b0b0d&height=100&section=footer"/>

</div>
