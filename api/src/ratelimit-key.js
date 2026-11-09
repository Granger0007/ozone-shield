/**
 * Build the rate-limit key for a client IP address.
 *
 * IPv4: the address itself.
 * IPv6: the /64 prefix. A single home or mobile connection usually controls a
 * whole /64, so keying on the full address would let one person rotate
 * through billions of addresses and never hit the limit.
 */
export function rateLimitKey(ip) {
  if (!ip) return 'unknown';
  if (ip.includes('.')) return ip.slice(ip.lastIndexOf(':') + 1); // IPv4, incl. IPv4-mapped IPv6
  if (!ip.includes(':')) return ip;

  const [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t];
  return groups.slice(0, 4).map((g) => g.toLowerCase().padStart(4, '0')).join(':') + '::/64';
}
