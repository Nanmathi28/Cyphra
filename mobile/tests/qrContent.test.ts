import assert from 'node:assert/strict';
import { test } from 'node:test';

import { NivaraApiError, analyzeUrl } from '../src/api/nivaraApi';
import { analyzeQrOnlyIfUrl, classifyQrContent } from '../src/qr/qrContent';

test('classifies an HTTP URL for backend analysis', async () => {
  const qr = classifyQrContent('https://example.com/path');
  assert.equal(qr.kind, 'url');
  assert.equal(qr.url, 'https://example.com/path');
  let requested = '';
  const result = await analyzeQrOnlyIfUrl(qr, async (url) => { requested = url; return 'analyzed'; });
  assert.equal(result, 'analyzed');
  assert.equal(requested, 'https://example.com/path');
});

test('classifies and safely parses UPI payment fields', () => {
  const qr = classifyQrContent('upi://pay?pa=merchant%40bank&pn=Shop&am=125.50&cu=INR');
  assert.equal(qr.kind, 'upi');
  assert.equal(qr.fields.find((field) => field.label === 'Payee name')?.value, 'Shop');
  assert.match(qr.fields.find((field) => field.label === 'UPI ID')?.value || '', /^me\*+/);
  assert.equal(qr.fields.find((field) => field.label === 'Amount')?.value, 'INR 125.50');
  assert.match(qr.message || '', /cannot independently verify/i);
});

test('classifies Wi-Fi QR content and masks its password', () => {
  const qr = classifyQrContent('WIFI:T:WPA;S:Office;P:secretpass;;');
  assert.equal(qr.kind, 'wifi');
  assert.equal(qr.fields.find((field) => field.label === 'Network name')?.value, 'Office');
  assert.notEqual(qr.fields.find((field) => field.label === 'Password')?.value, 'secretpass');
});

test('Wi-Fi QR escaped separators stay within their field', () => {
  const qr = classifyQrContent('WIFI:T:WPA;S:Office\\;Guest;P:p\\;ass;;');
  assert.equal(qr.fields.find((field) => field.label === 'Network name')?.value, 'Office;Guest');
  assert.notEqual(qr.fields.find((field) => field.label === 'Password')?.value, 'p;ass');
});

test('classifies vCard contacts and masks phone/email values', () => {
  const qr = classifyQrContent('BEGIN:VCARD\nVERSION:3.0\nFN:Jane Example\nEMAIL:jane@example.org\nTEL:+15551234567\nEND:VCARD');
  assert.equal(qr.kind, 'contact');
  assert.equal(qr.fields.find((field) => field.label === 'Name')?.value, 'Jane Example');
  assert.notEqual(qr.fields.find((field) => field.label === 'Email')?.value, 'jane@example.org');
  assert.notEqual(qr.fields.find((field) => field.label === 'Telephone')?.value, '+15551234567');
});

test('classifies plain text without interpreting or opening embedded links', () => {
  const qr = classifyQrContent('Please review https://example.com');
  assert.equal(qr.kind, 'text');
  assert.equal(qr.raw, 'Please review https://example.com');
});

test('classifies email, telephone, and SMS payloads for review only', () => {
  assert.equal(classifyQrContent('mailto:user@example.org?subject=Hello').kind, 'email');
  assert.equal(classifyQrContent('tel:+15551234567').kind, 'telephone');
  assert.equal(classifyQrContent('SMSTO:+15551234567:Hello').kind, 'sms');
});

test('malformed UPI data remains a payment review with an explicit warning', () => {
  const qr = classifyQrContent('upi://pay?pa=not-a-valid-id&am=not-an-amount');
  assert.equal(qr.kind, 'upi');
  assert.match(qr.message || '', /missing or malformed/i);
});

test('unsupported URI schemes are not treated as web URLs', () => {
  for (const value of ['ftp://files.example/file', 'javascript:alert(1)', 'intent://pay']) {
    assert.equal(classifyQrContent(value).kind, 'unsupported');
  }
});

test('non-URL QR formats never invoke the backend callback', async () => {
  const inputs = [
    'upi://pay?pa=shop@bank',
    'WIFI:T:WPA;S:Office;P:secret;;',
    'BEGIN:VCARD\nFN:Jane\nEND:VCARD',
    'hello world',
    'mailto:user@example.com',
    'tel:+15551234567',
    'sms:+15551234567:hello',
    'ftp://files.example/file',
  ];
  let calls = 0;
  for (const input of inputs) {
    await analyzeQrOnlyIfUrl(classifyQrContent(input), async () => { calls += 1; });
  }
  assert.equal(calls, 0);
});

test('API timeout during request or response is mapped to timeout', async () => {
  const fetchImpl: typeof fetch = (_input, init) => new Promise((_resolve, reject) => {
    init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
  });
  await assert.rejects(
    analyzeUrl('https://example.com/', false, { baseUrl: 'http://localhost:8000', timeoutMs: 5, fetchImpl }),
    (error: unknown) => error instanceof NivaraApiError && error.kind === 'timeout',
  );
  const responseBodyTimeoutFetch: typeof fetch = async (_input, init) => ({
    ok: true,
    status: 200,
    text: () => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
    }),
  } as Response);
  await assert.rejects(
    analyzeUrl('https://example.com/', false, { baseUrl: 'http://localhost:8000', timeoutMs: 5, fetchImpl: responseBodyTimeoutFetch }),
    (error: unknown) => error instanceof NivaraApiError && error.kind === 'timeout',
  );
});

test('API connection failure has an actionable network error', async () => {
  const fetchImpl: typeof fetch = async () => { throw new TypeError('offline'); };
  await assert.rejects(
    analyzeUrl('https://example.com/', false, { baseUrl: 'http://localhost:8000', timeoutMs: 100, fetchImpl }),
    (error: unknown) => error instanceof NivaraApiError && error.kind === 'network' && /http:\/\/localhost:8000/.test(error.message),
  );
});
