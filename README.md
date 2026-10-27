<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0b0b0d,50:1a1a2e,100:00d4ff&height=180&section=header&text=OZONE%20Shield&fontSize=52&fontColor=ffffff&fontAlignY=38&desc=AI-Powered%20Scam%20Message%20Detector&descSize=18&descAlignY=58&descColor=00d4ff" />

[![Live](https://img.shields.io/badge/Status-Live-00d4ff?style=for-the-badge)](https://ozone-shield.bbaranda055.workers.dev)
[![Cloudflare Workers](https://img.shields.io/badge/Hosted%20on-Cloudflare%20Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://ozone-shield.bbaranda055.workers.dev)
[![Anthropic](https://img.shields.io/badge/Powered%20by-Claude%20AI-EE3124?style=for-the-badge)](https://anthropic.com)

[![Try It](https://img.shields.io/badge/▶%20Try%20It%20Now-ozone--shield.bbaranda055.workers.dev-00d4ff?style=for-the-badge)](https://ozone-shield.bbaranda055.workers.dev)

</div>

---

## What It Does

Paste any suspicious message — email, SMS, WhatsApp, or letter — and get an instant verdict with a confidence percentage, a severity rating, specific reasons tied to the actual message, and a plain-English action guide.

No account. No download. No technical knowledge required.

> **What this tool is, and isn't.** OZONE Shield is **guidance, not a guarantee.** It reads the text of a message and tells you what the warning signs look like. It cannot verify who really sent something, check whether a link is live, or know your circumstances. A **SAFE** verdict means *no obvious scam signals in the words* — it does not mean the message is genuine. **Never treat it as the final word on anything involving your money, your accounts or your identity.** If something feels wrong, contact the organisation directly using a number you already have, not one from the message.

---

## Verdict System

| Verdict | Meaning | Action |
|:-------:|---------|--------|
| ✅ **SAFE** | No meaningful scam signals in the message text | Still proceed with normal caution — see the limitation note above |
| ⚠️ **SUSPICIOUS** | 1–3 signals present | Told exactly what to check before responding |
| 🚨 **SCAM** | Multiple high-confidence signals | Do not click, do not call back, do not reply — then report it |
| ❌ **INVALID** | Input was not a real message | Prompted to paste a genuine message |

Each result includes:
- **Confidence** — 0–100%, calibrated to signal strength
- **Severity** — Low / Medium / Critical
- **Reasons** — up to 3 specific reasons tied to the actual message content
- **What to do** — one clear action instruction written for a non-technical person

### Reporting a scam in the UK

**Report Fraud** replaced Action Fraud as the UK's official fraud and cybercrime reporting service on **4 December 2025**.

| Where you are | How to report |
|---|---|
| England, Wales, Northern Ireland | [reportfraud.police.uk](https://www.reportfraud.police.uk) · or call **0300 123 2040** |
| Scotland | **Police Scotland on 101** |

If you have lost money or think your bank account is at risk, contact your bank immediately — most UK banks can be reached by dialling **159**.

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
- Bot protection — Cloudflare Turnstile (configured account-side; **server-side enforcement not yet verified** — see Roadmap)
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

## Privacy and Data Protection

People paste their most sensitive messages into a tool like this — bank letters, "Hi Mum" texts, medical appointment scams. That makes privacy a design problem, not a policy afterthought. Here is exactly what happens to what you paste.

### What the service handles

| Data | Why | Where it goes |
|---|---|---|
| **The message text you paste** | It's what gets analysed | Sent to the Anthropic API via Cloudflare AI Gateway. It may contain personal data — names, phone numbers, account references — because real scam messages do |
| **Your IP address** | Rate limiting only, 10 requests per minute | Held in Cloudflare KV against a short expiry. Under UK GDPR an IP address is personal data, so it is treated as such |
| **Request metadata** | Cost and error observability | Logged through Cloudflare AI Gateway |

### Design decisions

- **No account, no sign-up, no tracking.** The tool asks for nothing about you.
- **No analytics or advertising scripts.** The frontend has zero external dependencies.
- **The API key never reaches the browser.** All model calls happen server-side.
- **`Cache-Control: no-store`** on responses, so verdicts aren't cached by intermediaries.
- **Nothing you paste is used to train anything.** This tool stores no message database of its own.

### Before you paste

**Redact what you don't need analysed.** The scam signals live in the structure and language of a message, not in your account number. Replace real card numbers, passwords, one-time codes and account references with `XXXX` before pasting — the verdict will be just as accurate, and you'll have shared less.

### Known gaps — being worked on

Honest disclosure, because a security tool that hides its own limitations isn't one:

- **A full data protection impact assessment (DPIA) is in progress** — data-flow map, lawful basis, retention periods and processor terms, written against the UK Information Commission's guidance. It will be published in this repository.
- **Retention periods for AI Gateway logs and KV rate-limit entries are being documented** rather than assumed.
- **A user-facing privacy notice** will be added to the interface itself, not only to this README.

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
| 8 | Bot protection — Cloudflare Turnstile configured | 🔄 server-side enforcement being verified |
| 9 | Data protection — DPIA, retention documentation, in-app privacy notice | 🔄 in progress |

---

## The Problem It Solves

Scam messages reach people on every channel at once — email, SMS, WhatsApp, and increasingly printed letters. The advice is scattered across bank websites, government pages and news articles, and almost none of it helps in the thirty seconds when someone is standing in their kitchen wondering whether the text about a missed parcel is real.

Most people don't lack judgement. They lack a fast, free second opinion at the moment they need one.

OZONE Shield reduces that to a single action: paste the message, get a verdict and a reason — across any channel, not just one.

---

## Roadmap

- [ ] Complete the DPIA and publish it here
- [ ] Add a user-facing privacy notice to the interface
- [ ] Confirm and complete Turnstile server-side verification
- [ ] Custom domain
- [ ] URL scanner — analyse suspicious links as well as text
- [ ] Browser extension — right-click any message to scan instantly
- [ ] Mobile app — React Native (iOS and Android)
- [ ] API endpoint — allow third-party integration of OZONE Shield verdicts

---

## Built By

**Bhargav Baranda**
MSc Information Security (Royal Holloway, University of London) · CompTIA Security+ certified · ISC² Certified in Cybersecurity (CC)

OZONE Shield is a personal project, built and run solo. It is free to use and always will be.

[linkedin.com/in/bhargav-baranda](https://linkedin.com/in/bhargav-baranda) · [youtube.com/@Granger-Security](https://youtube.com/@Granger-Security) · [github.com/Granger0007](https://github.com/Granger0007) · [Information Security Portfolio](https://github.com/Granger0007/Bhargav-Baranda-Portfolio)

<div align="center">

*Built from zero to production. Migrated, hardened, and still improving.*

[![Try OZONE Shield](https://img.shields.io/badge/▶%20Try%20It-ozone--shield.bbaranda055.workers.dev-00d4ff?style=for-the-badge)](https://ozone-shield.bbaranda055.workers.dev)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00d4ff,50:1a1a2e,100:0b0b0d&height=100&section=footer"/>

</div>
