import { createServer } from 'node:http';
import { URLSearchParams } from 'node:url';
import { createChallenge, verifyChallenge } from 'ncaptcha-api';

const secret = 'example-secret-1234567890';
const port = Number(process.env.PORT ?? 3000);
const demoText = process.env.CAPTCHA_TEXT;

function renderPage({ token = '', image = '', expiresAt = '', answer = '', result = null } = {}) {
  const statusMarkup = result
    ? `<p class="status ${result.ok ? 'ok' : 'error'}">${result.ok ? 'Captcha verified.' : `Verification failed: ${result.reason}.`
    }</p>`
    : '';

  const challengeMarkup = token
    ? `
      <p class="meta">Expires at ${expiresAt}</p>
      <img src="${image}" alt="Captcha challenge" width="320" height="120" />
      <form method="post" action="/verify">
        <input type="hidden" name="token" value="${token}" />
        <label for="answer">Enter the text from the image</label>
        <input id="answer" name="answer" value="${answer}" autocomplete="off" required />
        <button type="submit">Verify</button>
      </form>
    `
    : '<p>Unable to create captcha challenge.</p>';

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ncaptcha example</title>
    <style>
      :root {
        color-scheme: light;
        font-family: Georgia, "Times New Roman", serif;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background: linear-gradient(160deg, #f8f1e7 0%, #efe5d0 100%);
        color: #24170d;
      }
      main {
        width: min(92vw, 38rem);
        padding: 2rem;
        border: 1px solid #c7b79d;
        background: rgba(255, 251, 245, 0.94);
        box-shadow: 0 1.25rem 3rem rgba(71, 49, 24, 0.12);
      }
      h1 {
        margin-top: 0;
        font-size: 2rem;
      }
      p {
        line-height: 1.5;
      }
      .meta {
        font-size: 0.95rem;
        color: #5d4832;
      }
      img {
        display: block;
        width: 100%;
        max-width: 320px;
        margin: 1rem 0;
        border: 1px solid #c7b79d;
        background: #fff;
      }
      form {
        display: grid;
        gap: 0.75rem;
      }
      input,
      button {
        font: inherit;
        padding: 0.8rem 0.9rem;
      }
      button {
        width: fit-content;
        border: 0;
        background: #7d4e24;
        color: #fffaf3;
        cursor: pointer;
      }
      .status {
        padding: 0.85rem 1rem;
        margin-bottom: 1rem;
      }
      .ok {
        background: #d9f1df;
      }
      .error {
        background: #f7d7d7;
      }
      a {
        color: #7d4e24;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>ncaptcha example</h1>
      <p>This page runs the full generate and verify cycle against the local package.</p>
      ${statusMarkup}
      ${challengeMarkup}
      <p><a href="/">Load a fresh captcha</a></p>
    </main>
  </body>
</html>`;
}

function sendHtml(response, html, statusCode = 200) {
  response.writeHead(statusCode, { 'content-type': 'text/html; charset=utf-8' });
  response.end(html);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';

    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error('Request body too large.'));
        request.destroy();
      }
    });
    request.on('end', () => resolve(body));
    request.on('error', reject);
  });
}

function buildChallengePage(result = null, answer = '') {
  const challenge = createChallenge({
    secret,
    text: demoText,
    ttlSeconds: 300,
    distortion: 'high', // low, medium, high
    noise: 5, // 0-5,  0 is the least noisy, 5 is the most noisy
  });

  return renderPage({
    token: challenge.token,
    image: `data:${challenge.mimeType};base64,${challenge.imageBuffer.toString('base64')}`,
    expiresAt: challenge.expiresAt.toISOString(),
    answer,
    result,
  });
}

const server = createServer(async (request, response) => {
  try {
    if (request.method === 'GET' && request.url === '/') {
      sendHtml(response, buildChallengePage());
      return;
    }

    if (request.method === 'POST' && request.url === '/verify') {
      const rawBody = await readBody(request);
      const params = new URLSearchParams(rawBody);
      const token = params.get('token') ?? '';
      const answer = params.get('answer') ?? '';
      const result = verifyChallenge({
        secret,
        token,
        answer,
      });

      sendHtml(response, buildChallengePage(result, answer), result.ok ? 200 : 400);
      return;
    }

    response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    response.end('Not found');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unexpected error';
    sendHtml(response, `<p>${message}</p><p><a href="/">Back</a></p>`, 500);
  }
});

server.listen(port, () => {
  console.log(`Example app running at http://localhost:${port}`);
});
