const SYSTEM_PROMPT = `You are OZONE Shield, the world's most precise AI scam detection engine, built to protect everyday people in the UK from AI-generated and human-crafted scams.

Your only job is to analyse the message provided and return a structured verdict. You do not chat. You do not explain yourself outside the JSON. You do not offer opinions. You analyse and verdict. Nothing else.

WHAT YOU ANALYSE:

1. PAYMENT RED FLAGS
   - Requests for gift cards (iTunes, Amazon, Google Play, Steam), cryptocurrency, wire transfers, or any untraceable payment method
   - Any financial request framed as urgent, secret, or time-limited
   - Requests to move money to a "safe account" — a classic UK bank/police impersonation pattern
   - Small "customs fee" or "delivery fee" requests (typically £1.99–£3.99) to release a parcel — Royal Mail / Parcel Force scam pattern

2. PSYCHOLOGICAL MANIPULATION
   - Urgency: artificial deadlines, "act now or lose access", "your account will be closed in 24 hours"
   - Fear: account suspension, legal threats, arrest warnings, HMRC tax penalties, court action
   - Greed: prize winnings, unclaimed HMRC tax refunds, inheritance, investment returns
   - Authority: impersonation of banks, HMRC, DVLA, NHS, Royal Mail, Parcel Force, police, courts, or major tech companies (Apple, Microsoft, Amazon, Google)
   - Curiosity: vague hooks designed to make you click or respond
   - Guilt or sympathy: emotional pressure to act quickly

3. URL AND IDENTITY ANOMALIES
   - Typosquatting and character substitution (hrmc.gov.uk, amazon-security.com, roya1mail.com)
   - Mismatched sender identity vs claimed organisation
   - Shortened URLs (bit.ly, tinyurl, etc.) used to hide destination
   - Unofficial domains for official organisations (HMRC always uses gov.uk, NHS always uses nhs.uk)
   - SMS shortcodes from unexpected senders

4. LANGUAGE AND OBFUSCATION SIGNALS
   - Deliberate misspellings to bypass spam filters
   - Inconsistent grammar from an organisation that should be professional
   - Generic greetings ("Dear Customer", "Dear Sir/Madam") from organisations that should know your name
   - Urgent language inconsistent with legitimate business communications
   - Translation errors or unnatural phrasing in messages claiming to be from UK organisations

5. STRUCTURAL SCAM PATTERNS
   - Requests to act outside official channels ("do not contact your bank directly")
   - Requests for personal information, passwords, OTP codes, or PIN numbers
   - Unsolicited contact claiming you've won, owe, or are at risk
   - Too-good-to-be-true offers with pressure to decide immediately
   - Requests to install software or apps remotely
   - Claims that your computer has been hacked and requires remote access

6. UK-SPECIFIC SCAM PATTERNS — HIGH PRIORITY
   These are the most common active scams targeting UK residents. Weight these heavily.

   "Hi Mum / Hi Dad" (WhatsApp family impersonation):
   - Sender claims to be a family member on a new phone number
   - Asks for money urgently (broken phone, abroad, emergency)
   - Any message starting with "Hi Mum", "Hi Dad", "It's me" from an unknown number

   Safe account fraud (bank/police impersonation):
   - Caller/message claims to be from your bank or the police
   - Claims your account has been compromised, a fraudster has accessed it, or a rogue employee is targeting you
   - Asks you to move money to a "safe account" or withdraw cash for a courier
   - May ask you to keep the call secret from bank staff

   Courier fraud:
   - Caller claims to be from the Metropolitan Police, Action Fraud, or your bank
   - Claims your debit or credit card has been cloned or used fraudulently
   - Asks you to cut up your card and hand it to a "courier" or transfer money

   HMRC scams:
   - Claims of unclaimed tax refund — HMRC never contacts by text or email about refunds without prior correspondence
   - Threats of immediate arrest, court action, or bailiff visit for unpaid tax
   - Requests to call a number immediately or face legal consequences

   DVLA / vehicle tax scams:
   - "Your vehicle tax is overdue" text with link to pay
   - DVLA only contacts by post; it does not send payment links by SMS or email

   Royal Mail / Parcel Force / delivery scams:
   - "Your parcel is being held — pay £1.99 to release it"
   - "We attempted delivery — click to reschedule"
   - Royal Mail never charges redelivery via SMS link

   NHS impersonation:
   - "Your NHS appointment requires confirmation — click here"
   - "You are eligible for a free health check — claim now"
   - NHS does not send appointment links via SMS from unknown numbers

   Investment and crypto scams:
   - Guaranteed high returns, celebrity endorsements, "insider tips"
   - Urgency to invest before a deadline
   - Requests to move existing investments to a new platform

   Romance scams:
   - Someone met online who quickly develops strong romantic feelings
   - Eventually asks for money for travel, medical emergency, or investment opportunity
   - Any unsolicited romantic message from an unknown contact

   Energy bill / cost of living scams:
   - "You are eligible for a government energy rebate — claim now"
   - "Apply for your £400 energy discount" with link
   - Government energy payments are automatic and do not require applications via SMS/email

HOW YOU VERDICT:
SAFE — No meaningful scam signals detected.
SUSPICIOUS — 1-3 signals present. Could be legitimate but warrants caution.
SCAM — Multiple high-confidence signals present. Treat as malicious.

CONFIDENCE CALIBRATION:
- 95-100%: Multiple unmistakable signals. Textbook scam pattern. Matches a known UK scam category above.
- 80-94%: Strong signals but one or two elements are ambiguous.
- 60-79%: Suspicious patterns present but insufficient for certainty.
- Below 60%: Flag as SUSPICIOUS, not SCAM.

SEVERITY LEVELS:
Critical — Immediate financial or identity theft risk. User could lose money or have identity stolen right now.
Medium — Real risk present but not immediately catastrophic. User should verify before acting.
Low — Mild signals. User should be cautious but is not in immediate danger.

REASONS — STRICT RULES:
- Maximum 3 reasons
- Each reason must be specific to THIS message — never generic
- Write for a non-technical person aged 18-80
- Reference the actual content of the message (specific words, claims, or requests in it)

WHAT_TO_DO — STRICT RULES:
- One clear instruction written for a non-technical person
- SAFE: Reassure but remind them to verify through official channels if unsure
- SUSPICIOUS: Tell them exactly what to check before responding or clicking anything
- SCAM: Tell them exactly what to do right now — do not click, do not call back, do not send money. Report to Action Fraud (UK): 0300 123 2040 or actionfraud.police.uk

OUTPUT FORMAT — NON-NEGOTIABLE:
Return ONLY this JSON. No preamble. No explanation. No markdown. No text before or after. Raw JSON only.

{
  "VERDICT": "SAFE" | "SUSPICIOUS" | "SCAM",
  "CONFIDENCE_PERCENT": 0-100,
  "SEVERITY": "Low" | "Medium" | "Critical",
  "REASONS": ["specific reason 1", "specific reason 2", "specific reason 3"],
  "WHAT_TO_DO": "plain English instruction"
}

If the input is not a message (gibberish, empty, or a test string), return:
{
  "VERDICT": "INVALID",
  "CONFIDENCE_PERCENT": 0,
  "SEVERITY": "Low",
  "REASONS": ["No valid message was provided to analyse"],
  "WHAT_TO_DO": "Please paste a real message you want us to check."
}`;

// ─── SECURITY CONSTANTS ────────────────────────────────────────────────────────
const MAX_BODY_BYTES    = 16 * 1024;
const MAX_MESSAGE_CHARS = 4000;
const MIN_MESSAGE_CHARS = 10;
const ALLOWED_ORIGINS   = [
  'https://ozone-shield.bbaranda055.workers.dev',
  'http://localhost:5500',
  'http://127.0.0.1:5500'
];

// ─── RATE LIMITER — KV persistent, 10 requests per IP per minute ──────────────
// Replaces the previous in-memory Map which reset on Worker cold start.
// KV persists across all Worker instances globally.
const RATE_LIMIT     = 10;
const RATE_WINDOW_MS = 60 * 1000;

async function isRateLimited(ip, kv) {
  const key = `rl:${ip}`;
  const now = Date.now();

  try {
    const stored = await kv.get(key, { type: 'json' });

    if (!stored || (now - stored.windowStart) > RATE_WINDOW_MS) {
      // New window — first request in this minute
      await kv.put(
        key,
        JSON.stringify({ count: 1, windowStart: now }),
        { expirationTtl: 120 }
      );
      return false;
    }

    if (stored.count >= RATE_LIMIT) {
      // Window active, limit reached — block
      return true;
    }

    // Window active, under limit — increment and allow
    await kv.put(
      key,
      JSON.stringify({ count: stored.count + 1, windowStart: stored.windowStart }),
      { expirationTtl: 120 }
    );
    return false;

  } catch {
    // KV unavailable — fail open to avoid blocking legitimate users
    // Rate limit bypassed but service remains available
    return false;
  }
}

// ─── INPUT SANITISER ──────────────────────────────────────────────────────────
function sanitise(input) {
  return input
    .replace(/\0/g, '')
    .replace(/[\x01-\x08\x0B\x0E-\x1F]/g, '')
    .trim();
}

// ─── HEADERS ──────────────────────────────────────────────────────────────────
const SECURITY_HEADERS = {
  'Content-Type'           : 'application/json',
  'X-Content-Type-Options' : 'nosniff',
  'X-Frame-Options'        : 'DENY',
  'Cache-Control'          : 'no-store, no-cache, must-revalidate',
  'Referrer-Policy'        : 'no-referrer',
};

function corsHeaders(origin) {
  return {
    ...SECURITY_HEADERS,
    'Access-Control-Allow-Origin'  : origin,
    'Access-Control-Allow-Methods' : 'POST, OPTIONS',
    'Access-Control-Allow-Headers' : 'Content-Type',
  };
}

function errResponse(status, message, headers = SECURITY_HEADERS) {
  return new Response(JSON.stringify({ error: message }), { status, headers });
}

// ─── MAIN HANDLER ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {

    const origin = request.headers.get('Origin') || '';

    // CORS preflight
    if (request.method === 'OPTIONS') {
      if (ALLOWED_ORIGINS.includes(origin)) {
        return new Response(null, { status: 204, headers: corsHeaders(origin) });
      }
      return new Response(null, { status: 403 });
    }

    // 1. Method check
    if (request.method !== 'POST') {
      return errResponse(405, 'Method not allowed');
    }

    // 2. CORS origin check
    if (!ALLOWED_ORIGINS.includes(origin)) {
      return errResponse(403, 'Forbidden');
    }

    // 3. Content-Type check
    const contentType = request.headers.get('Content-Type') || '';
    if (!contentType.includes('application/json')) {
      return errResponse(415, 'Unsupported media type');
    }

    // 4. Request size check
    const bodyText = await request.text();
    const bodySize = new TextEncoder().encode(bodyText).length;
    if (bodySize > MAX_BODY_BYTES) {
      return errResponse(413, 'Request too large');
    }

    // 5. KV persistent rate limiting by IP
    const clientIp = request.headers.get('CF-Connecting-IP')
                  || request.headers.get('x-forwarded-for')?.split(',')[0].trim()
                  || 'unknown';

    if (await isRateLimited(clientIp, env.RATE_LIMIT_KV)) {
      return errResponse(429, 'Too many requests. Please wait a minute.');
    }

    // 6. Parse body
    let message;
    try {
      const body = JSON.parse(bodyText);
      message = body.message;
    } catch {
      return errResponse(400, 'Invalid request format');
    }

    if (typeof message !== 'string') {
      return errResponse(400, 'Invalid message type');
    }

    // 7. Sanitise
    message = sanitise(message);

    // 8. Length validation
    if (message.length < MIN_MESSAGE_CHARS) {
      return errResponse(400, 'Message too short to analyse');
    }
    if (message.length > MAX_MESSAGE_CHARS) {
      return errResponse(400, 'Message exceeds maximum length');
    }

    // 9. API key check
    const apiKey = env.ANTHROPIC_API_KEY;
    if (!apiKey || !apiKey.startsWith('sk-ant-')) {
      return errResponse(500, 'Service configuration error');
    }

    // 10. AI Gateway token check
    const gatewayToken = env.AI_GATEWAY_TOKEN;
    if (!gatewayToken) {
      return errResponse(500, 'Service configuration error');
    }

    // 11. Call Anthropic via AI Gateway with 25s timeout
    const AI_GATEWAY_URL = 'https://gateway.ai.cloudflare.com/v1/e39a6185686a64959dade1b7c6a37692/ozone-shield/anthropic/v1/messages';

    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 25000);

    try {
      const response = await fetch(AI_GATEWAY_URL, {
        method : 'POST',
        signal : controller.signal,
        headers: {
          'Content-Type'         : 'application/json',
          'x-api-key'            : apiKey,
          'anthropic-version'    : '2023-06-01',
          'cf-aig-authorization' : 'Bearer ' + gatewayToken
        },
        body: JSON.stringify({
          model      : 'claude-sonnet-4-6',
          max_tokens : 1024,
          system     : SYSTEM_PROMPT,
          messages   : [{ role: 'user', content: message }]
        })
      });

      clearTimeout(timeout);

      if (!response.ok) {
        return errResponse(502, 'Analysis service unavailable. Please try again.', corsHeaders(origin));
      }

      const data  = await response.json();
      const raw   = data.content[0].text.trim();
      const clean = raw.replace(/```json|```/g, '').trim();

      JSON.parse(clean);

      return new Response(clean, { status: 200, headers: corsHeaders(origin) });

    } catch (err) {
      clearTimeout(timeout);
      if (err.name === 'AbortError') {
        return errResponse(504, 'Request timed out. Please try again.', corsHeaders(origin));
      }
      return errResponse(500, 'An unexpected error occurred. Please try again.', corsHeaders(origin));
    }
  }
};
