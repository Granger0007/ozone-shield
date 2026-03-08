const SYSTEM_PROMPT = `You are OZONE Shield, the world's most precise AI scam detection engine, built to protect everyday people from AI-generated and human-crafted scams.

Your only job is to analyse the message provided and return a structured verdict. You do not chat. You do not explain yourself outside the JSON. You do not offer opinions. You analyse and verdict. Nothing else.

WHAT YOU ANALYSE:

1. PAYMENT RED FLAGS
   - Requests for gift cards, cryptocurrency, wire transfers, or any untraceable payment method
   - Any financial request framed as urgent, secret, or time-limited

2. PSYCHOLOGICAL MANIPULATION
   - Urgency: artificial deadlines, "act now or lose access"
   - Fear: account suspension, legal threats, arrest warnings
   - Greed: prize winnings, unclaimed refunds, investment opportunities
   - Authority: impersonation of banks, delivery services, government bodies, or major tech companies
   - Curiosity: vague hooks designed to make you click or respond

3. URL AND IDENTITY ANOMALIES
   - Typosquatting and character substitution
   - Mismatched sender identity vs claimed organisation
   - Shortened URLs used to hide destination

4. LANGUAGE AND OBFUSCATION SIGNALS
   - Deliberate misspellings to bypass spam filters
   - Inconsistent grammar from an organisation that should be professional
   - Generic greetings from organisations that should know your name

5. STRUCTURAL SCAM PATTERNS
   - Requests to act outside official channels
   - Requests for personal information, passwords, or OTP codes
   - Unsolicited contact claiming you've won, owe, or are at risk
   - Too-good-to-be-true offers with pressure to decide immediately

HOW YOU VERDICT:
SAFE — No meaningful scam signals detected.
SUSPICIOUS — 1-3 signals present. Could be legitimate but warrants caution.
SCAM — Multiple high-confidence signals present. Treat as malicious.

CONFIDENCE CALIBRATION:
- 95-100%: Multiple unmistakable signals. Textbook scam pattern.
- 80-94%: Strong signals but one or two elements are ambiguous.
- 60-79%: Suspicious patterns present but insufficient for certainty.
- Below 60%: Flag as SUSPICIOUS, not SCAM.

SEVERITY LEVELS:
Critical — Immediate financial or identity theft risk.
Medium — Real risk present but not immediately catastrophic.
Low — Mild signals. User should be cautious but is not in immediate danger.

REASONS — STRICT RULES:
- Maximum 3 reasons
- Each reason must be specific to THIS message — never generic
- Write for a non-technical person aged 18-80

WHAT_TO_DO — STRICT RULES:
- One clear instruction written for a non-technical person
- SAFE: Reassure but remind them to verify through official channels
- SUSPICIOUS: Tell them exactly what to check before responding
- SCAM: Tell them exactly what to do right now — do not click, do not call back, report to Action Fraud (UK): 0300 123 2040

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

// SECURITY CONSTANTS
const MAX_BODY_BYTES    = 16 * 1024;
const MAX_MESSAGE_CHARS = 4000;
const MIN_MESSAGE_CHARS = 10;
const ALLOWED_ORIGINS   = [
  'https://ozone-shield.netlify.app',
  'http://localhost:5500',
  'http://127.0.0.1:5500'
];

// RATE LIMITER — 10 requests per IP per minute
const rateLimitStore = new Map();
const RATE_LIMIT     = 10;
const RATE_WINDOW_MS = 60 * 1000;

function isRateLimited(ip) {
  const now   = Date.now();
  const entry = rateLimitStore.get(ip);
  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    rateLimitStore.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count++;
  return entry.count > RATE_LIMIT;
}

// INPUT SANITISER
function sanitise(input) {
  return input
    .replace(/\0/g, '')
    .replace(/[\x01-\x08\x0B\x0E-\x1F]/g, '')
    .trim();
}

// SECURITY HEADERS
const SECURITY_HEADERS = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store, no-cache, must-revalidate',
};

exports.handler = async (event) => {

  // 1. Method check
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  // 2. CORS origin check
  const origin = event.headers['origin'] || event.headers['Origin'] || '';
  if (!ALLOWED_ORIGINS.includes(origin)) {
    return { statusCode: 403, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Forbidden' }) };
  }

  // 3. Content-Type check
  const contentType = event.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    return { statusCode: 415, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Unsupported media type' }) };
  }

  // 4. Request size check
  const bodySize = Buffer.byteLength(event.body || '', 'utf8');
  if (bodySize > MAX_BODY_BYTES) {
    return { statusCode: 413, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Request too large' }) };
  }

  // 5. Rate limiting by IP
  const clientIp = (event.headers['x-forwarded-for'] || '').split(',')[0].trim()
                || event.headers['client-ip']
                || 'unknown';
  if (isRateLimited(clientIp)) {
    return { statusCode: 429, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Too many requests. Please wait a minute.' }) };
  }

  // 6. Parse body
  let message;
  try {
    const body = JSON.parse(event.body);
    message = body.message;
  } catch {
    return { statusCode: 400, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Invalid request format' }) };
  }

  if (typeof message !== 'string') {
    return { statusCode: 400, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Invalid message type' }) };
  }

  // 7. Sanitise
  message = sanitise(message);

  // 8. Length validation
  if (message.length < MIN_MESSAGE_CHARS) {
    return { statusCode: 400, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Message too short to analyse' }) };
  }
  if (message.length > MAX_MESSAGE_CHARS) {
    return { statusCode: 400, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Message exceeds maximum length' }) };
  }

  // 9. API key check
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey || !apiKey.startsWith('sk-ant-')) {
    return { statusCode: 500, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Service configuration error' }) };
  }

  // 10. Call Anthropic with 25s timeout
  const controller = new AbortController();
  const timeout    = setTimeout(() => controller.abort(), 25000);

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-5',
        max_tokens: 1024,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: message }]
      })
    });

    clearTimeout(timeout);

    if (!response.ok) {
      return { statusCode: 502, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Analysis service unavailable. Please try again.' }) };
    }

    const data  = await response.json();
    const raw   = data.content[0].text.trim();
    const clean = raw.replace(/```json|```/g, '').trim();

    // Validate response is valid JSON before returning
    JSON.parse(clean);

    return {
      statusCode: 200,
      headers: { ...SECURITY_HEADERS, 'Access-Control-Allow-Origin': origin },
      body: clean
    };

  } catch (err) {
    clearTimeout(timeout);
    if (err.name === 'AbortError') {
      return { statusCode: 504, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'Request timed out. Please try again.' }) };
    }
    return { statusCode: 500, headers: SECURITY_HEADERS, body: JSON.stringify({ error: 'An unexpected error occurred. Please try again.' }) };
  }
};