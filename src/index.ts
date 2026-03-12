import { createCanvas } from 'canvas';
import {
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  timingSafeEqual,
} from 'node:crypto';

export type DistortionLevel = 'low' | 'medium' | 'high';

export interface CaptchaOptions {
  secret?: string;
  text?: string;
  length?: number;
  width?: number;
  height?: number;
  ttlSeconds?: number;
  charset?: string;
  excludeChars?: string;
  distortion?: DistortionLevel;
  noise?: number;
  backgroundColor?: string;
  textColor?: string;
  lineColor?: string;
  speckleColor?: string;
  fonts?: string[];
}

export interface Challenge {
  token: string;
  imageBuffer: Buffer;
  mimeType: 'image/png';
  expiresAt: Date;
}

export interface VerifyInput {
  token: string;
  answer: string;
  secret?: string;
  now?: number | Date;
  isReplay?: (tokenId: string, payload: TokenPayload) => boolean;
}

export interface VerifyResult {
  ok: boolean;
  reason?: 'expired' | 'invalid-signature' | 'mismatch' | 'malformed-token' | 'replayed';
}

interface DistortionConfig {
  rotateMaxRad: number;
  skewMax: number;
  xJitter: number;
  yJitter: number;
  curveLines: number;
  waves: number;
  speckleDensity: number;
}

export interface TokenPayload {
  v: 2;
  iat: number;
  exp: number;
  id: string;
  salt: string;
  ads: string;
  ah: string;
}

const DEFAULT_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const DEFAULT_EXCLUDE = '01ILO';

const DISTORTION_PRESETS: Record<DistortionLevel, DistortionConfig> = {
  low: {
    rotateMaxRad: 0.12,
    skewMax: 0.08,
    xJitter: 4,
    yJitter: 8,
    curveLines: 2,
    waves: 1,
    speckleDensity: 0.008,
  },
  medium: {
    rotateMaxRad: 0.2,
    skewMax: 0.13,
    xJitter: 7,
    yJitter: 12,
    curveLines: 3,
    waves: 2,
    speckleDensity: 0.014,
  },
  high: {
    rotateMaxRad: 0.28,
    skewMax: 0.18,
    xJitter: 10,
    yJitter: 16,
    curveLines: 4,
    waves: 3,
    speckleDensity: 0.02,
  },
};

const DEFAULT_FONTS = ['Arial', 'Helvetica', 'Verdana', 'Trebuchet MS', 'Tahoma'];

function resolveSecret(secret?: string): string {
  const resolvedSecret = secret ?? process.env.NCAPTCHA_SECRET;
  if (!resolvedSecret || resolvedSecret.trim().length < 16) {
    throw new Error('A secret of at least 16 characters is required (pass secret option or set NCAPTCHA_SECRET).');
  }
  return resolvedSecret;
}

function base64UrlEncode(input: Buffer | string): string {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(input: string): Buffer {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

function hmacSha256(input: string, secret: string): Buffer {
  return createHmac('sha256', secret).update(input).digest();
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

function safeEqualUtf8(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a, 'utf8');
  const bBuffer = Buffer.from(b, 'utf8');
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }
  return timingSafeEqual(aBuffer, bBuffer);
}

function randomFraction(): number {
  return randomInt(0, 1_000_000) / 1_000_000;
}

function randomBetween(min: number, max: number): number {
  return min + randomFraction() * (max - min);
}

function randomTokenSegment(size = 12): string {
  return base64UrlEncode(randomBytes(size));
}

function normalizeAnswer(answer: string): string {
  return answer.trim().toUpperCase();
}

function buildAllowedCharset(charset: string, excludeChars: string): string {
  const excluded = new Set(excludeChars.toUpperCase());
  const allowed = [...new Set(charset.toUpperCase().split('').filter((char) => !excluded.has(char)))];

  if (allowed.length < 2) {
    throw new Error('Captcha charset must contain at least 2 allowed characters after exclusions.');
  }

  return allowed.join('');
}

function generateText(length: number, charset: string): string {
  let output = '';
  for (let i = 0; i < length; i += 1) {
    output += charset[randomInt(0, charset.length)];
  }
  return output;
}

function computeAnswerHash(answer: string, secret: string, salt: string, seed: string): string {
  return sha256Hex(`${secret}:${normalizeAnswer(answer)}:${salt}:${seed}`);
}

function currentUnixSeconds(now?: number | Date): number {
  if (typeof now === 'number') {
    return Math.floor(now);
  }
  if (now instanceof Date) {
    return Math.floor(now.getTime() / 1000);
  }
  return Math.floor(Date.now() / 1000);
}

function signPayload(payloadSegment: string, secret: string): string {
  return base64UrlEncode(hmacSha256(payloadSegment, secret));
}

function createToken(payload: TokenPayload, secret: string): string {
  const payloadJson = JSON.stringify(payload);
  const payloadSegment = base64UrlEncode(payloadJson);
  const signatureSegment = signPayload(payloadSegment, secret);
  return `${payloadSegment}.${signatureSegment}`;
}

function parseToken(token: string): { payload: TokenPayload; payloadSegment: string; signatureSegment: string } | null {
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return null;
  }

  try {
    const payloadBuffer = base64UrlDecode(parts[0]);
    const parsed = JSON.parse(payloadBuffer.toString('utf8')) as TokenPayload;
    if (
      parsed.v !== 2 ||
      typeof parsed.iat !== 'number' ||
      typeof parsed.exp !== 'number' ||
      typeof parsed.id !== 'string' ||
      typeof parsed.salt !== 'string' ||
      typeof parsed.ads !== 'string' ||
      typeof parsed.ah !== 'string'
    ) {
      return null;
    }

    return { payload: parsed, payloadSegment: parts[0], signatureSegment: parts[1] };
  } catch {
    return null;
  }
}

function renderCaptchaImage(text: string, options: Required<Pick<CaptchaOptions, 'width' | 'height' | 'distortion' | 'noise' | 'backgroundColor' | 'textColor' | 'lineColor' | 'speckleColor' | 'fonts'>>): Buffer {
  const canvas = createCanvas(options.width, options.height);
  const ctx = canvas.getContext('2d');
  const distortion = DISTORTION_PRESETS[options.distortion];

  const gradient = ctx.createLinearGradient(0, 0, options.width, options.height);
  gradient.addColorStop(0, options.backgroundColor);
  gradient.addColorStop(1, '#f1f6ff');
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, options.width, options.height);

  ctx.save();
  ctx.globalAlpha = 0.1;
  for (let i = 0; i < 90; i += 1) {
    const x = randomBetween(0, options.width);
    const y = randomBetween(0, options.height);
    const radius = randomBetween(6, 24);
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fillStyle = i % 2 === 0 ? '#ffffff' : '#d7e4ff';
    ctx.fill();
  }
  ctx.restore();

  ctx.strokeStyle = options.lineColor;
  ctx.lineWidth = 1.5 + options.noise * 1.2;
  for (let i = 0; i < distortion.curveLines + Math.floor(options.noise); i += 1) {
    ctx.beginPath();
    ctx.moveTo(0, randomBetween(0, options.height));
    ctx.bezierCurveTo(
      randomBetween(0, options.width * 0.3),
      randomBetween(0, options.height),
      randomBetween(options.width * 0.3, options.width),
      randomBetween(0, options.height),
      options.width,
      randomBetween(0, options.height),
    );
    ctx.stroke();
  }

  for (let wave = 0; wave < distortion.waves; wave += 1) {
    ctx.beginPath();
    const amplitude = randomBetween(4, 12 + options.noise * 2);
    const frequency = randomBetween(0.015, 0.05);
    const phase = randomBetween(0, Math.PI * 2);

    for (let x = 0; x <= options.width; x += 4) {
      const y = options.height / 2 + Math.sin(x * frequency + phase) * amplitude + randomBetween(-2, 2);
      if (x === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    }
    ctx.stroke();
  }

  const charSlot = options.width / (text.length + 1);
  const baseFontSize = Math.floor(options.height * 0.56);

  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    const fontName = options.fonts[randomInt(0, options.fonts.length)];
    const fontSize = Math.floor(baseFontSize + randomBetween(-8, 8));
    const x = Math.floor(charSlot * (i + 1) + randomBetween(-distortion.xJitter, distortion.xJitter));
    const y = Math.floor(options.height * 0.64 + randomBetween(-distortion.yJitter, distortion.yJitter));

    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(randomBetween(-distortion.rotateMaxRad, distortion.rotateMaxRad));
    ctx.transform(
      1,
      randomBetween(-distortion.skewMax, distortion.skewMax),
      randomBetween(-distortion.skewMax, distortion.skewMax),
      1,
      0,
      0,
    );
    ctx.font = `700 ${fontSize}px "${fontName}", sans-serif`;
    ctx.fillStyle = options.textColor;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(char, 0, 0);
    ctx.restore();
  }

  const speckleCount = Math.floor(options.width * options.height * distortion.speckleDensity * Math.max(0.5, options.noise));
  ctx.fillStyle = options.speckleColor;
  for (let i = 0; i < speckleCount; i += 1) {
    const x = randomBetween(0, options.width);
    const y = randomBetween(0, options.height);
    const size = randomBetween(0.8, 2.1);
    ctx.fillRect(x, y, size, size);
  }

  return canvas.toBuffer('image/png');
}

export function createChallenge(options: CaptchaOptions = {}): Challenge {
  const secret = resolveSecret(options.secret);
  const length = options.length ?? 6;
  const width = options.width ?? 320;
  const height = options.height ?? 120;
  const ttlSeconds = options.ttlSeconds ?? 600;
  const distortion = options.distortion ?? 'medium';
  const noise = options.noise ?? 1;

  if (!Number.isInteger(length) || length < 4 || length > 10) {
    throw new Error('length must be an integer between 4 and 10.');
  }

  if (!Number.isInteger(width) || width < 200 || width > 1000) {
    throw new Error('width must be an integer between 200 and 1000.');
  }

  if (!Number.isInteger(height) || height < 80 || height > 400) {
    throw new Error('height must be an integer between 80 and 400.');
  }

  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 3600) {
    throw new Error('ttlSeconds must be an integer between 30 and 3600.');
  }

  if (!(distortion in DISTORTION_PRESETS)) {
    throw new Error("distortion must be one of: 'low', 'medium', 'high'.");
  }

  if (!Number.isInteger(noise) || noise < 0 || noise > 5) {
    throw new Error('noise must be an integer between 0 and 5.');
  }

  const charset = buildAllowedCharset(options.charset ?? DEFAULT_CHARSET, options.excludeChars ?? DEFAULT_EXCLUDE);
  const answer = options.text ? normalizeAnswer(options.text) : generateText(length, charset);

  if (answer.length !== length) {
    throw new Error('Provided text must match the configured length.');
  }

  const iat = currentUnixSeconds();
  const exp = iat + ttlSeconds;
  const salt = randomTokenSegment(9);
  const digestSeed = randomTokenSegment(9);
  const answerHash = computeAnswerHash(answer, secret, salt, digestSeed);

  const payload: TokenPayload = {
    v: 2,
    iat,
    exp,
    id: randomTokenSegment(10),
    salt,
    ads: digestSeed,
    ah: answerHash,
  };

  const token = createToken(payload, secret);
  const imageBuffer = renderCaptchaImage(answer, {
    width,
    height,
    distortion,
    noise,
    backgroundColor: options.backgroundColor ?? '#ecf4ff',
    textColor: options.textColor ?? '#10233d',
    lineColor: options.lineColor ?? '#2f4f75',
    speckleColor: options.speckleColor ?? '#32516f',
    fonts: options.fonts?.length ? options.fonts : DEFAULT_FONTS,
  });

  return {
    token,
    imageBuffer,
    mimeType: 'image/png',
    expiresAt: new Date(exp * 1000),
  };
}

export function verifyChallenge(input: VerifyInput): VerifyResult {
  const parsedToken = parseToken(input.token);

  if (!parsedToken) {
    return { ok: false, reason: 'malformed-token' };
  }

  const secret = resolveSecret(input.secret);
  const expectedSignature = signPayload(parsedToken.payloadSegment, secret);

  if (!safeEqualUtf8(expectedSignature, parsedToken.signatureSegment)) {
    return { ok: false, reason: 'invalid-signature' };
  }

  const now = currentUnixSeconds(input.now);
  if (now > parsedToken.payload.exp) {
    return { ok: false, reason: 'expired' };
  }

  if (input.isReplay?.(parsedToken.payload.id, parsedToken.payload)) {
    return { ok: false, reason: 'replayed' };
  }

  const actualAnswerHash = computeAnswerHash(
    input.answer,
    secret,
    parsedToken.payload.salt,
    parsedToken.payload.ads,
  );

  if (!safeEqualUtf8(actualAnswerHash, parsedToken.payload.ah)) {
    return { ok: false, reason: 'mismatch' };
  }

  return { ok: true };
}
