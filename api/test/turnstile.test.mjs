import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyTurnstile, SITEVERIFY_URL, EXPECTED_HOSTNAME } from '../src/turnstile.js';

const reply = (body, status = 200) => async () => new Response(JSON.stringify(body), { status });

test('valid token from our hostname is accepted, and the right fields are sent', async () => {
  let seen;
  const fetchImpl = async (url, init) => { seen = { url, form: init.body }; return new Response(JSON.stringify({ success: true, hostname: EXPECTED_HOSTNAME })); };
  const r = await verifyTurnstile('tok', '203.0.113.7', 'sec', fetchImpl);
  assert.equal(r.result, 'ok');
  assert.equal(seen.url, SITEVERIFY_URL);
  assert.equal(seen.form.get('secret'), 'sec');
  assert.equal(seen.form.get('response'), 'tok');
  assert.equal(seen.form.get('remoteip'), '203.0.113.7');
});

test('remoteip is omitted when the IP is unknown', async () => {
  let form;
  await verifyTurnstile('tok', '', 'sec', async (u, i) => { form = i.body; return new Response(JSON.stringify({ success: true, hostname: EXPECTED_HOSTNAME })); });
  assert.equal(form.has('remoteip'), false);
});

test('token issued on another hostname is rejected', async () => {
  const r = await verifyTurnstile('tok', '', 'sec', reply({ success: true, hostname: 'example.com' }));
  assert.equal(r.result, 'invalid');
  assert.deepEqual(r.codes, ['wrong-hostname:example.com']);
});

test('Siteverify failure codes are passed through', async () => {
  const r = await verifyTurnstile('tok', '', 'sec', reply({ success: false, 'error-codes': ['timeout-or-duplicate'] }));
  assert.equal(r.result, 'invalid');
  assert.deepEqual(r.codes, ['timeout-or-duplicate']);
});

test('missing, empty, non-string and oversized tokens never reach Siteverify', async () => {
  let called = false;
  const spy = async () => { called = true; return new Response('{}'); };
  for (const t of [undefined, '', 42, 'x'.repeat(2049)]) {
    assert.equal((await verifyTurnstile(t, '', 'sec', spy)).result, 'invalid');
  }
  assert.equal(called, false);
});

test('missing secret is reported as a configuration problem', async () => {
  assert.equal((await verifyTurnstile('tok', '', undefined, reply({}))).result, 'missing-secret');
});

test('network failure, HTTP error and bad JSON are errors, not passes', async () => {
  assert.equal((await verifyTurnstile('tok', '', 'sec', async () => { throw new Error('down'); })).result, 'error');
  assert.equal((await verifyTurnstile('tok', '', 'sec', reply({}, 500))).result, 'error');
  assert.equal((await verifyTurnstile('tok', '', 'sec', async () => new Response('not json'))).result, 'error');
});
