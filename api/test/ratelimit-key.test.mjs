import test from 'node:test';
import assert from 'node:assert/strict';
import { rateLimitKey } from '../src/ratelimit-key.js';

test('IPv4 is used as-is', () => {
  assert.equal(rateLimitKey('203.0.113.7'), '203.0.113.7');
});

test('IPv4-mapped IPv6 is treated as IPv4', () => {
  assert.equal(rateLimitKey('::ffff:203.0.113.7'), '203.0.113.7');
});

test('IPv6 addresses in the same /64 share one key', () => {
  const a = rateLimitKey('2001:db8:abcd:12:1111:2222:3333:4444');
  const b = rateLimitKey('2001:db8:abcd:12::99');
  assert.equal(a, '2001:0db8:abcd:0012::/64');
  assert.equal(a, b);
});

test('different /64s get different keys', () => {
  assert.notEqual(rateLimitKey('2001:db8:abcd:12::1'), rateLimitKey('2001:db8:abcd:13::1'));
});

test('compressed forms expand correctly', () => {
  assert.equal(rateLimitKey('2001:db8::1'), '2001:0db8:0000:0000::/64');
  assert.equal(rateLimitKey('::1'), '0000:0000:0000:0000::/64');
  assert.equal(rateLimitKey('2001:DB8:ABCD:12::'), '2001:0db8:abcd:0012::/64');
});

test('missing IP falls back to a shared key', () => {
  assert.equal(rateLimitKey(''), 'unknown');
  assert.equal(rateLimitKey(undefined), 'unknown');
});
