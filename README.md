# ncaptcha-api v2

Modern captcha generation for Node.js APIs with stateless signed verification.

## Highlights

- TypeScript + ESM package targeting Node 20+
- Harder-to-scan PNG captcha rendering with layered distortion/noise
- Stateless HMAC-signed token verification (no DB/session required)
- Node-native test runner (`node:test`) with coverage thresholds

## Install

```bash
yarn add ncaptcha-api
```

## Required Secret

A signing secret is required and must be at least 16 characters.

```bash
export NCAPTCHA_SECRET="replace-with-a-strong-secret"
```

You can also pass `secret` directly in API calls.

## API

```ts
import { createChallenge, verifyChallenge } from 'ncaptcha-api';

const challenge = createChallenge({
  length: 6,
  distortion: 'medium',
  ttlSeconds: 600,
});

// send token + imageBuffer to your client
const result = verifyChallenge({
  token: challenge.token,
  answer: 'USER_INPUT',
});
```
### `createChallenge(options?)`

Returns:

- `token: string`
- `imageBuffer: Buffer`
- `mimeType: "image/png"`
- `expiresAt: Date`

Selected options:

- `secret?: string`
- `text?: string` (mostly for testing)
- `length?: number` (default `6`)
- `width?: number` (default `320`)
- `height?: number` (default `120`)
- `ttlSeconds?: number` (default `600`)
- `charset?: string`
- `excludeChars?: string` (default excludes ambiguous characters)
- `distortion?: 'low' | 'medium' | 'high'` (default `medium`)
- `noise?: number` (integer `0` to `5`, default `1`)

### `verifyChallenge(input)`

Returns:

- `{ ok: true }`
- `{ ok: false, reason: 'expired' | 'invalid-signature' | 'mismatch' | 'malformed-token' | 'replayed' }`

Input fields:

- `token: string`
- `answer: string`
- `secret?: string`
- `now?: number | Date` (for deterministic tests)
- `isReplay?: (tokenId, payload) => boolean` (optional app-level replay hook, returns `replayed` when true)

## Security Notes

- Verification is stateless and signed; token tampering is detected.
- Replay prevention beyond token expiry is application-specific. Use `isReplay` with your own store/cache if needed.
- Use HTTPS and strong secrets in production.

## Real-world Example (Express)

```ts
import express from 'express';
import { createChallenge, verifyChallenge } from 'ncaptcha-api';

const app = express();
app.use(express.json());

app.get('/captcha', (_req, res) => {
  const challenge = createChallenge({
    ttlSeconds: 300,
    distortion: 'medium',
  });

  res.json({
    token: challenge.token,
    expiresAt: challenge.expiresAt.toISOString(),
    image: `data:${challenge.mimeType};base64,${challenge.imageBuffer.toString('base64')}`,
  });
});

app.post('/captcha/verify', (req, res) => {
  const { token, answer } = req.body ?? {};
  const result = verifyChallenge({ token, answer });

  if (!result.ok) {
    return res.status(400).json(result);
  }

  return res.status(200).json({ ok: true });
});

app.listen(3000);
```


## Migration from v1

v2 is a breaking release:

- Removed class API (`new NCaptcha().generate()/check()`)
- New function API: `createChallenge()` and `verifyChallenge()`
- Output changed from base64 data URL to `Buffer` + `mimeType`
- Token format upgraded to signed stateless payloads

## Development

```bash
corepack enable
yarn install --immutable
yarn test
yarn coverage
```
