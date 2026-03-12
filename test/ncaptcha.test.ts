import test from 'node:test';
import assert from 'node:assert/strict';
import { createChallenge, verifyChallenge } from '../src/index.js';

const SECRET = 'unit-test-secret-for-ncaptcha-v2';

function readPngDimensions(buffer: Buffer): { width: number; height: number } {
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
}

test('createChallenge returns token, png buffer, mime type and expiration', () => {
  const challenge = createChallenge({
    secret: SECRET,
    text: 'AB29KD',
    length: 6,
    width: 320,
    height: 120,
  });

  assert.equal(typeof challenge.token, 'string');
  assert.equal(challenge.mimeType, 'image/png');
  assert.ok(Buffer.isBuffer(challenge.imageBuffer));
  assert.ok(challenge.imageBuffer.length > 5000);
  assert.ok(challenge.expiresAt instanceof Date);

  const pngSignature = challenge.imageBuffer.subarray(0, 8);
  assert.equal(pngSignature.toString('hex'), '89504e470d0a1a0a');

  const dims = readPngDimensions(challenge.imageBuffer);
  assert.equal(dims.width, 320);
  assert.equal(dims.height, 120);
});

test('verifyChallenge succeeds with correct answer', () => {
  const challenge = createChallenge({
    secret: SECRET,
    text: 'QW78RT',
    length: 6,
    ttlSeconds: 120,
  });

  const result = verifyChallenge({
    secret: SECRET,
    token: challenge.token,
    answer: 'qw78rt',
  });

  assert.deepEqual(result, { ok: true });
});

test('verifyChallenge fails with mismatch for wrong answer', () => {
  const challenge = createChallenge({
    secret: SECRET,
    text: 'ZX98CV',
    length: 6,
  });

  const result = verifyChallenge({
    secret: SECRET,
    token: challenge.token,
    answer: 'WRONG1',
  });

  assert.deepEqual(result, { ok: false, reason: 'mismatch' });
});

test('verifyChallenge fails with expired token when now is after exp', () => {
  const challenge = createChallenge({
    secret: SECRET,
    text: 'MN45OP',
    length: 6,
    ttlSeconds: 60,
  });

  const now = Math.floor(challenge.expiresAt.getTime() / 1000) + 2;
  const result = verifyChallenge({
    secret: SECRET,
    token: challenge.token,
    answer: 'MN45OP',
    now,
  });

  assert.deepEqual(result, { ok: false, reason: 'expired' });
});

test('verifyChallenge fails with invalid-signature for tampered payload', () => {
  const challenge = createChallenge({
    secret: SECRET,
    text: 'HG67JK',
    length: 6,
  });

  const [payloadSegment, signatureSegment] = challenge.token.split('.');
  const payload = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8')) as {
    exp: number;
  };
  payload.exp += 1000;
  const tamperedPayloadSegment = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const tamperedToken = `${tamperedPayloadSegment}.${signatureSegment}`;

  const result = verifyChallenge({
    secret: SECRET,
    token: tamperedToken,
    answer: 'HG67JK',
  });

  assert.deepEqual(result, { ok: false, reason: 'invalid-signature' });
});

test('verifyChallenge fails with invalid-signature for tampered signature', () => {
  const challenge = createChallenge({
    secret: SECRET,
    text: 'YU54NM',
    length: 6,
  });

  const [payloadSegment, signatureSegment] = challenge.token.split('.');
  const replacement = signatureSegment.endsWith('A') ? 'B' : 'A';
  const tamperedToken = `${payloadSegment}.${signatureSegment.slice(0, -1)}${replacement}`;

  const result = verifyChallenge({
    secret: SECRET,
    token: tamperedToken,
    answer: 'YU54NM',
  });

  assert.deepEqual(result, { ok: false, reason: 'invalid-signature' });
});

test('verifyChallenge fails with invalid-signature for short signature', () => {
  const challenge = createChallenge({
    secret: SECRET,
    text: 'YU54NM',
    length: 6,
  });

  const [payloadSegment] = challenge.token.split('.');
  const tamperedToken = `${payloadSegment}.x`;

  const result = verifyChallenge({
    secret: SECRET,
    token: tamperedToken,
    answer: 'YU54NM',
  });

  assert.deepEqual(result, { ok: false, reason: 'invalid-signature' });
});

test('verifyChallenge fails with malformed token', () => {
  const result = verifyChallenge({
    secret: SECRET,
    token: 'bad-token',
    answer: 'ANY123',
  });

  assert.deepEqual(result, { ok: false, reason: 'malformed-token' });
});

test('verifyChallenge supports replay hook for application-level replay checks', () => {
  const challenge = createChallenge({
    secret: SECRET,
    text: 'PL67MN',
    length: 6,
  });

  const replayed = verifyChallenge({
    secret: SECRET,
    token: challenge.token,
    answer: 'PL67MN',
    isReplay: () => true,
  });

  assert.deepEqual(replayed, { ok: false, reason: 'mismatch' });
});

test('generated challenges are unique and verifiable with their own answers', () => {
  const count = 25;
  const tokens = new Set<string>();

  for (let i = 0; i < count; i += 1) {
    const answer = `A${i.toString().padStart(5, '0')}`;
    const challenge = createChallenge({
      secret: SECRET,
      text: answer,
      length: 6,
    });

    tokens.add(challenge.token);

    const result = verifyChallenge({
      secret: SECRET,
      token: challenge.token,
      answer,
    });

    assert.deepEqual(result, { ok: true });
  }

  assert.equal(tokens.size, count);
});

test('createChallenge can read secret from NCAPTCHA_SECRET and generate random text', () => {
  const previous = process.env.NCAPTCHA_SECRET;
  process.env.NCAPTCHA_SECRET = SECRET;

  try {
    const challenge = createChallenge({
      length: 6,
      distortion: 'high',
      noise: 2,
      fonts: ['Arial'],
      charset: 'ABCD1234',
      excludeChars: 'D4',
    });
    assert.equal(challenge.mimeType, 'image/png');
    assert.ok(challenge.token.includes('.'));
  } finally {
    process.env.NCAPTCHA_SECRET = previous;
  }
});

test('createChallenge validates option ranges and provided text length', () => {
  assert.throws(() => createChallenge({ secret: SECRET, length: 3 }), /length must be an integer between 4 and 10/);
  assert.throws(() => createChallenge({ secret: SECRET, width: 199 }), /width must be an integer between 200 and 1000/);
  assert.throws(() => createChallenge({ secret: SECRET, height: 70 }), /height must be an integer between 80 and 400/);
  assert.throws(() => createChallenge({ secret: SECRET, ttlSeconds: 20 }), /ttlSeconds must be an integer between 30 and 3600/);
  assert.throws(() => createChallenge({ secret: SECRET, length: 6, text: 'AB12' }), /Provided text must match the configured length/);
});

test('createChallenge validates secret and charset exclusions', () => {
  assert.throws(() => createChallenge({ secret: 'short', text: 'AB12CD', length: 6 }), /at least 16 characters/);
  assert.throws(
    () => createChallenge({ secret: SECRET, charset: 'AB', excludeChars: 'AB', text: 'AAAA', length: 4 }),
    /must contain at least 2 allowed characters/,
  );
});

test('verifyChallenge detects malformed payload and accepts Date now input', () => {
  const challenge = createChallenge({
    secret: SECRET,
    text: 'RT56YU',
    length: 6,
    ttlSeconds: 60,
  });

  const [payloadSegment, signatureSegment] = challenge.token.split('.');
  const payload = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8')) as {
    v: number;
  };
  payload.v = 999;
  const malformedShapeToken = `${Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')}.${signatureSegment}`;
  const malformedShapeResult = verifyChallenge({
    secret: SECRET,
    token: malformedShapeToken,
    answer: 'RT56YU',
  });
  assert.deepEqual(malformedShapeResult, { ok: false, reason: 'malformed-token' });

  const invalidJsonToken = `${Buffer.from('{"v":', 'utf8').toString('base64url')}.${signatureSegment}`;
  const invalidJsonResult = verifyChallenge({
    secret: SECRET,
    token: invalidJsonToken,
    answer: 'RT56YU',
  });
  assert.deepEqual(invalidJsonResult, { ok: false, reason: 'malformed-token' });

  const successWithDateNow = verifyChallenge({
    secret: SECRET,
    token: challenge.token,
    answer: 'RT56YU',
    now: new Date(),
  });
  assert.deepEqual(successWithDateNow, { ok: true });
});
