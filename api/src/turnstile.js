/**
 * Cloudflare Turnstile server-side validation.
 * https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
 *
 * Returns one of:
 *   'ok'              token valid and issued on our own hostname
 *   'invalid'         missing, malformed, expired, reused or foreign token
 *   'error'           Siteverify unreachable or returned a non-200
 *   'missing-secret'  TURNSTILE_SECRET_KEY isn't configured
 */
export const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
export const EXPECTED_HOSTNAME = 'ozone-shield.bbaranda055.workers.dev';
const MAX_TOKEN_LENGTH = 2048;

export async function verifyTurnstile(token, ip, secret, fetchImpl = fetch) {
  if (!secret) return { result: 'missing-secret', codes: [] };
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
    return { result: 'invalid', codes: ['missing-or-malformed-token'] };
  }

  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);

  let res;
  try {
    res = await fetchImpl(SITEVERIFY_URL, { method: 'POST', body: form });
  } catch {
    return { result: 'error', codes: ['siteverify-unreachable'] };
  }
  if (!res.ok) return { result: 'error', codes: [`siteverify-http-${res.status}`] };

  let out;
  try {
    out = await res.json();
  } catch {
    return { result: 'error', codes: ['siteverify-bad-json'] };
  }

  const codes = Array.isArray(out['error-codes']) ? out['error-codes'] : [];
  if (out.success !== true) return { result: 'invalid', codes };
  if (out.hostname !== EXPECTED_HOSTNAME) return { result: 'invalid', codes: [`wrong-hostname:${out.hostname}`] };
  return { result: 'ok', codes: [] };
}
