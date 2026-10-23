import { describe, expect, it } from 'vitest';
import { createMasker, runTier1, validateEvent, type UnmaskedEvent } from '../src/index.js';

const KEY = 'test-pseudonym-key-0123456789';
const masker = createMasker({ pseudonymKey: KEY });
const mask = (text: string) => masker.maskText(text);

// Secret-looking values are built at runtime so no scanner mistakes this file for a leak.
const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: 'user-1' })}.${'s'.repeat(12)}`;
const awsKey = `AKIA${'IOSFODNN7'}${'EXAMPLE'}`;
const ghToken = `ghp_${'a1'.repeat(20)}`;
const privateKey = [
  `-----BEGIN ${'RSA PRIVATE KEY'}-----`,
  'MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu',
  `-----END ${'RSA PRIVATE KEY'}-----`,
].join('\n');

function event(attrs: UnmaskedEvent['attrs'], overrides: Partial<UnmaskedEvent> = {}): UnmaskedEvent {
  return {
    id: 'evt-1',
    ts: '2026-10-23T10:15:00Z',
    layer: 'application',
    service: 'shop-web',
    kind: 'http.request',
    attrs,
    ...overrides,
  };
}

describe('maskText: secrets', () => {
  it.each([
    ['a bearer token', 'Authorization: Bearer abcdef0123456789xyz', 'abcdef0123456789xyz'],
    ['a JWT', `session ${jwt} ended`, jwt],
    ['a cloud access key', `key=${awsKey}`, awsKey],
    ['a service token', `pushed with ${ghToken}`, ghToken],
    ['a private key block', `body:\n${privateKey}\nend`, 'MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu'],
    ['credentials in a URL', 'fetching https://deploy:s3cr3t-pass@git.example.invalid/repo.git', 's3cr3t-pass'],
    ['a secret in a query string', 'GET /cb?token=abc123def&user=7', 'abc123def'],
    ['a quoted JSON secret', '{"password":"hunter2-long","ok":true}', 'hunter2-long'],
    ['a secret with a colon', 'api_key: 9f8e7d6c5b4a', '9f8e7d6c5b4a'],
  ])('removes %s', (_name, input, secret) => {
    const { text, report } = mask(input);
    expect(text).not.toContain(secret);
    expect(Object.values(report).reduce((a, b) => a + b, 0)).toBeGreaterThan(0);
  });

  it('removes a private key that is cut off before its end marker', () => {
    const { text } = mask(`${privateKey.split('\n').slice(0, 2).join('\n')}`);
    expect(text).not.toContain('MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu');
  });

  it('keeps the surrounding text readable', () => {
    expect(mask('GET /cb?token=abc123def&user=7').text).toBe('GET /cb?token=[redacted]&user=7');
    expect(mask('Authorization: Bearer abcdef0123456789xyz').text).toBe('Authorization: Bearer [redacted]');
  });

  it('never puts masked values in the report', () => {
    const { report } = mask(`${jwt} ${awsKey} ${ghToken} bob@example.com`);
    const serialised = JSON.stringify(report);
    for (const secret of [jwt, awsKey, ghToken, 'bob@example.com']) expect(serialised).not.toContain(secret);
  });
});

describe('maskText: personal data', () => {
  it('masks email addresses', () => {
    expect(mask('contact bob.smith+tag@example.com now').text).toBe('contact [email] now');
  });

  it('masks card numbers that pass the Luhn check, with or without separators', () => {
    expect(mask('card 4111111111111111 used').text).toBe('card [card] used');
    expect(mask('card 4111 1111 1111 1111 used').text).toBe('card [card] used');
    expect(mask('card 4111-1111-1111-1111 used').text).toBe('card [card] used');
  });

  it('leaves long numbers that are not card numbers alone', () => {
    expect(mask('order 4111111111111112 shipped').text).toBe('order 4111111111111112 shipped');
    expect(mask('request took 1234567 ms').text).toBe('request took 1234567 ms');
  });
});

describe('maskText: IP pseudonyms', () => {
  it('replaces an IPv4 address with a stable pseudonym that hides the address', () => {
    const a = mask('client 198.51.100.23 asked');
    const b = mask('again from 198.51.100.23');
    expect(a.text).not.toContain('198.51.100.23');
    const pseudonym = /ip_[0-9a-f]{12}/.exec(a.text)?.[0];
    expect(pseudonym).toBeDefined();
    expect(b.text).toContain(pseudonym!);
  });

  it('gives different addresses different pseudonyms, and different keys different pseudonyms', () => {
    const one = mask('198.51.100.23').text;
    const two = mask('198.51.100.24').text;
    const other = createMasker({ pseudonymKey: 'another-key-0123456789abcdef' }).maskText('198.51.100.23').text;
    expect(one).not.toBe(two);
    expect(one).not.toBe(other);
  });

  it('handles IPv6 and leaves clock times and invalid addresses alone', () => {
    expect(mask('from 2001:db8::1 ok').text).toMatch(/^from ip_[0-9a-f]{12} ok$/);
    expect(mask('at 10:15:00 then 999.1.1.1').text).toBe('at 10:15:00 then 999.1.1.1');
  });

  it('keeps addresses when asked to, as it does for destination hosts', () => {
    expect(masker.maskText('203.0.113.7', { keepIps: true }).text).toBe('203.0.113.7');
  });
});

describe('maskText: behaviour', () => {
  const composite = `u=bob@example.com ip=198.51.100.23 card=4111111111111111 ${jwt} ?token=abc123def Bearer abcdef0123456789xyz`;

  it('is idempotent', () => {
    const once = mask(composite).text;
    expect(mask(once).text).toBe(once);
  });

  it('truncates long values and says so', () => {
    const { text, report } = mask('x'.repeat(5000));
    expect(text).toHaveLength(2048);
    expect(report.truncated).toBe(1);
  });

  it('stays fast on hostile input', () => {
    const hostile = [
      '-----BEGIN PRIVATE KEY-----'.repeat(5000),
      '1 '.repeat(40_000),
      '1'.repeat(200_000),
      'a@'.repeat(40_000),
      ':'.repeat(100_000),
      `${'1.'.repeat(30_000)}1`,
    ];
    for (const input of hostile) {
      const started = performance.now();
      masker.maskText(input);
      expect(performance.now() - started).toBeLessThan(3000);
    }
  });
});

describe('createMasker', () => {
  it('refuses a short pseudonym key', () => {
    expect(() => createMasker({ pseudonymKey: 'short' })).toThrow(RangeError);
  });
});

describe('maskEvent', () => {
  it('attests masking only after producing a schema-valid event', () => {
    const { event: masked } = masker.maskEvent(event({ path: '/login' }));
    expect(masked.masked).toBe(true);
    expect(validateEvent(masked).ok).toBe(true);
  });

  it('redacts whole values for sensitive attribute names, whatever their type', () => {
    const { event: masked, report } = masker.maskEvent(
      event({ Authorization: 'Bearer x', 'x-api-key': 'k', cookie: 'a=b', password: 12345, 'Set-Cookie': 'sid=1', path: '/ok' }),
    );
    expect(masked.attrs).toEqual({
      Authorization: '[redacted]',
      'x-api-key': '[redacted]',
      cookie: '[redacted]',
      password: '[redacted]',
      'Set-Cookie': '[redacted]',
      path: '/ok',
    });
    expect(report['key-redacted']).toBe(5);
  });

  it('pseudonymises client IPs but keeps destination hosts', () => {
    const { event: masked } = masker.maskEvent(
      event({ client_ip: '198.51.100.23', host: '203.0.113.7', note: 'from 198.51.100.23' }, { kind: 'net.outbound' }),
    );
    expect(masked.attrs['host']).toBe('203.0.113.7');
    expect(String(masked.attrs['client_ip'])).toMatch(/^ip_[0-9a-f]{12}$/);
    expect(String(masked.attrs['note'])).not.toContain('198.51.100.23');
  });

  it('keeps ids, service and trace id, and passes numbers and booleans through', () => {
    const { event: masked } = masker.maskEvent(event({ status: 403, blocked: true }, { traceId: 'trace-abc' }));
    expect(masked).toMatchObject({ id: 'evt-1', service: 'shop-web', traceId: 'trace-abc', attrs: { status: 403, blocked: true } });
  });

  it('throws, without echoing values, when the event cannot be made valid', () => {
    const tooMany = Object.fromEntries(Array.from({ length: 70 }, (_, i) => [`k${i}`, `secret-value-${i}`]));
    let message = '';
    try {
      masker.maskEvent(event(tooMany));
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      message = (error as Error).message;
    }
    expect(message).not.toBe('');
    expect(message).not.toContain('secret-value');
  });

  it('does not change the input event', () => {
    const input = event({ path: '/cb?token=abc123def' });
    masker.maskEvent(input);
    expect(input.attrs['path']).toBe('/cb?token=abc123def');
  });

  it('keeps what tier 1 needs: masked events still trigger the same rules', () => {
    const raw: UnmaskedEvent[] = [
      event({ path: '/var/www/html/uploads/x.php', actor: 'www-data', client_ip: '198.51.100.23' }, { id: 'a', kind: 'file.created' }),
      event({ host: '203.0.113.7', actor: 'node', url: 'http://203.0.113.7/?token=abc123def' }, { id: 'b', kind: 'net.outbound' }),
      event({ parent: '/usr/sbin/php-fpm8.3', child: '/bin/sh' }, { id: 'c', kind: 'process.spawned' }),
    ];
    const rawAsEvents = raw.map((e) => ({ ...e, masked: true as const }));
    const before = runTier1(rawAsEvents).hits.map((h) => `${h.ruleId}:${h.severity}`).sort();
    const after = runTier1(raw.map((e) => masker.maskEvent(e).event)).hits.map((h) => `${h.ruleId}:${h.severity}`).sort();
    expect(after).toEqual(before);
    expect(after).toHaveLength(3);
  });
});
