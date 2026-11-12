<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0b0b0d,50:1a1a2e,100:00d4ff&height=180&section=header&text=OZONE%20Shield&fontSize=52&fontColor=ffffff&fontAlignY=38&desc=AI-Powered%20Scam%20Message%20Detector&descSize=18&descAlignY=58&descColor=00d4ff" />

[![Live](https://img.shields.io/badge/Status-Live-00d4ff?style=for-the-badge)](https://ozone-shield.bbaranda055.workers.dev)
[![Cloudflare Workers](https://img.shields.io/badge/Hosted%20on-Cloudflare%20Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://ozone-shield.bbaranda055.workers.dev)
[![Anthropic](https://img.shields.io/badge/Powered%20by-Claude%20AI-EE3124?style=for-the-badge)](https://anthropic.com)

[![Try It](https://img.shields.io/badge/▶%20Try%20It%20Now-ozone--shield.bbaranda055.workers.dev-00d4ff?style=for-the-badge)](https://ozone-shield.bbaranda055.workers.dev)

</div>



## What It Does

Paste any suspicious message — email, SMS, WhatsApp, or letter — and get an instant verdict with a confidence percentage, a severity rating, specific reasons tied to the actual message, and a plain-English action guide.

No account. No download. No technical knowledge required.

> **What this tool is, and isn't.** OZONE Shield is **guidance, not a guarantee.** It reads the text of a message and tells you what the warning signs look like. It cannot verify who really sent something, check whether a link is live, or know your circumstances. A **SAFE** verdict means *no obvious scam signals in the words* — it does not mean the message is genuine. **Never treat it as the final word on anything involving your money, your accounts or your identity.** If something feels wrong, contact the organisation directly using a number you already have, not one from the message.



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

If you have lost money or think your bank account is at risk, contact your bank immediately. Dial **159** to reach your bank safely: it works for more than 99% of UK retail bank current accounts ([Stop Scams UK](https://stopscamsuk.org.uk/our-programmes/159-phone-number/)).



## Architecture

```
Browser: static site (HTML, CSS, JS, self-hosted font)
       │  Cloudflare Workers static assets, strict security headers
       │  Cloudflare Turnstile issues a one-time bot-check token
       │
       │  POST { message, turnstileToken }
       ▼
Cloudflare Worker: ozone-analyse
       │  Origin allow-list, size and content checks
       │  Rate limiting: Workers Rate Limiting binding, fails closed
       │  Turnstile token verified server-side (Siteverify + hostname check)
       │
       │  POST via Cloudflare AI Gateway (payload logging off)
       ▼
AI Gateway (gateway.ai.cloudflare.com) → Anthropic API (claude-sonnet-4-6)
       │
       │  Structured JSON verdict
       ▼
Browser renders the result
```

**Stack:**
- Frontend: plain HTML, CSS and JavaScript, with no framework and no build step, served by Cloudflare Workers static assets. The font (Atkinson Hyperlegible Next, SIL OFL) is self-hosted.
- Backend: Cloudflare Worker (`ozone-analyse`), documented in [`api/README.md`](api/README.md)
- AI routing: Cloudflare AI Gateway, for request analytics and cost observability, with message payload logging switched off
- AI model: Claude `claude-sonnet-4-6` via the Anthropic API
- Rate limiting: Workers Rate Limiting binding, 10 requests per minute per client
- Bot protection: Cloudflare Turnstile, enforced server-side
- Hosting: Cloudflare Workers, auto-deployed from `main`
- Version control: GitHub



## Security

| Control | Implementation |
|---------|---------------|
| API key storage | Encrypted Cloudflare Worker secret, validated against the expected format before use. Never in code, never in the browser |
| CORS | Requests accepted only from the production origin |
| Rate limiting | 10 requests per minute per client (IPv4 address, or IPv6 /64 so one device can't rotate addresses), using Cloudflare's Workers Rate Limiting binding. If the limiter fails, requests are refused (503) rather than let through |
| Bot protection | Cloudflare Turnstile token checked server-side with Siteverify, and it must have been issued for this site's hostname. Fails closed |
| Input sanitisation | Strips null bytes and control characters before processing |
| Message length bounds | Minimum 10 characters, maximum 4,000 characters |
| Request size limit | 16 KB maximum, which blocks oversized payloads |
| Content-Type enforcement | Only `application/json` accepted |
| Request timeout | 25 seconds on all Anthropic API calls, via `AbortController` |
| API security headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer` |
| Website security headers | Set in [`public/_headers`](public/_headers): a strict Content Security Policy (no inline scripts or styles; the only third-party code allowed is Turnstile, and the game page allows none at all), HSTS, `nosniff`, framing blocked (`frame-ancestors 'none'` and `X-Frame-Options`), `Referrer-Policy`, `Permissions-Policy`, and cross-origin isolation of the window and files (COOP, CORP) |
| AI Gateway | Every model call is routed through Cloudflare AI Gateway for observability, with `cf-aig-collect-log-payload: false` so message text and verdicts are not kept in gateway logs |
| Error sanitisation | Internal error details are never exposed to the browser |
| Vulnerability disclosure | [`security.txt`](public/.well-known/security.txt) (RFC 9116) |



## Privacy and Data Protection

People paste their most sensitive messages into a tool like this — bank letters, "Hi Mum" texts, medical appointment scams. That makes privacy a design problem, not a policy afterthought. Here is exactly what happens to what you paste.

### What the service handles

| Data | Why | Where it goes |
|---|---|---|
| **The message text you paste** | It's what gets analysed | Sent to the Anthropic API via Cloudflare AI Gateway, with gateway payload logging off. Anthropic deletes API inputs and outputs within 30 days unless they are flagged or the law requires otherwise, and may not train models on them. It may contain personal data (names, phone numbers, account references) because real scam messages do |
| **Your IP address** | Rate limiting only, 10 requests per minute | Used as the key in Cloudflare's built-in rate limiter, and not stored by OZONE Shield. Under UK GDPR an IP address is personal data, so it is treated as such |
| **Request metadata** | Cost and error observability | Logged through Cloudflare AI Gateway and Workers logs, without message content |

### Design decisions

- **No account, no sign-up, no tracking.** The tool asks for nothing about you.
- **No analytics or advertising scripts.** The only third-party code on the site is Cloudflare Turnstile, the bot check.
- **The API key never reaches the browser.** All model calls happen server-side.
- **`Cache-Control: no-store`** on responses, so verdicts aren't cached by intermediaries.
- **Nothing you paste is used to train anything.** This tool stores no message database of its own.

### Before you paste

**Redact what you don't need analysed.** The scam signals live in the structure and language of a message, not in your account number. Replace real card numbers, passwords, one-time codes and account references with `XXXX` before pasting — the verdict will be just as accurate, and you'll have shared less.

### Known gaps — being worked on

Honest disclosure, because a security tool that hides its own limitations isn't one:

- **A full data protection impact assessment (DPIA) is in progress** — data-flow map, lawful basis, retention periods and processor terms, written against the UK Information Commission's guidance. It will be published in this repository.
- **The retention period for AI Gateway metadata logs is being documented** rather than assumed.

The privacy notice is live on the site itself, not only in this README.



## Detection Signal Categories

The system prompt analyses messages across six signal categories:

1. **Payment red flags** — gift cards, cryptocurrency, wire transfers, "safe account" requests, small customs/delivery fee scams
2. **Psychological manipulation** — urgency, fear, greed, authority impersonation, curiosity hooks, guilt/sympathy pressure
3. **URL and identity anomalies** — typosquatting, character substitution, mismatched sender identity, shortened URLs
4. **Language and obfuscation signals** — deliberate misspellings, inconsistent grammar, generic greetings, unnatural phrasing
5. **Structural scam patterns** — credential/OTP requests, off-channel instructions, too-good-to-be-true offers, remote access requests
6. **UK-specific scam patterns** *(high priority — weighted heavily)* — "Hi Mum/Dad" WhatsApp fraud, safe account fraud, courier fraud, HMRC impersonation, DVLA vehicle tax scams, Royal Mail/Parcel Force delivery scams, NHS impersonation, investment/crypto scams, romance scams, energy rebate scams



## Repository Structure

```
ozone-shield/
├── public/                           ← The website: the only folder that is served
│   ├── index.html                    ← Message checker, fraud figures, privacy policy
│   ├── spot-the-scam/index.html      ← Spot the Scam training game
│   ├── 404.html                      ← Page shown for unknown addresses
│   ├── css/, js/, fonts/             ← Styles, scripts and the self-hosted font
│   ├── _headers                      ← Security headers for every page
│   └── .well-known/security.txt      ← How to report a vulnerability
├── api/                              ← Backend Worker (ozone-analyse)
│   ├── src/                          ← worker.js, rate-limit key, Turnstile check
│   ├── test/                         ← Unit tests (node --test api/test/*.test.mjs)
│   └── README.md                     ← How a request is handled
├── wrangler.jsonc                    ← Website Worker configuration
└── README.md                         ← This file
```



## Build Summary

| Phase | Description | Status |
|:-----:|-------------|:------:|
| 1 | Environment setup — VS Code, Git, GitHub, Anthropic API | ✅ |
| 2 | System prompt engineering — 6 signal categories, UK-specific scam patterns, JSON schema | ✅ |
| 3 | HTML frontend — dark theme, textarea, result rendering, cooldown | ✅ |
| 4 | Initial deployment — Netlify (later retired after credit limit reached) | ✅ |
| 5 | Migration to Cloudflare Workers — static assets + Worker backend | ✅ |
| 6 | Security hardening — rate limiting, input sanitisation, CORS, API security headers | ✅ |
| 7 | Observability — Cloudflare AI Gateway integration for request logging and cost tracking | ✅ |
| 8 | Bot protection — Cloudflare Turnstile, enforced server-side | ✅ |
| 9 | Data protection — in-app privacy notice ✅, DPIA and retention documentation | 🔄 in progress |
| 10 | Redesign — full-width layout, WCAG AA contrast, zero axe-core violations, every figure checked against its source | ✅ |
| 11 | Spot the Scam — a training game with levels, streaks and badges, progress kept only on the device | ✅ |
| 12 | Website security headers — strict CSP, HSTS, Permissions-Policy, COOP/CORP | ✅ |



## The Problem It Solves

Scam messages reach people on every channel at once — email, SMS, WhatsApp, and increasingly printed letters. The advice is scattered across bank websites, government pages and news articles, and almost none of it helps in the thirty seconds when someone is standing in their kitchen wondering whether the text about a missed parcel is real.

Most people don't lack judgement. They lack a fast, free second opinion at the moment they need one.

OZONE Shield reduces that to a single action: paste the message, get a verdict and a reason — across any channel, not just one.



## Roadmap

- [ ] Complete the DPIA and publish it here
- [ ] Harden the AI step: prompt-injection defences, schema-checked output and an evaluation test set
- [ ] Custom domain
- [ ] URL scanner — analyse suspicious links as well as text
- [ ] Browser extension — right-click any message to scan instantly
- [ ] Mobile app — React Native (iOS and Android)
- [ ] API endpoint — allow third-party integration of OZONE Shield verdicts



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
