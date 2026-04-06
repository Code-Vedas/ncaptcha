# Example

Minimal Node.js app using the local `ncaptcha-api` package for the full captcha cycle.

## Run

From the repository root:

```bash
yarn build
cd example
yarn install
yarn start
```

Open `http://localhost:3000`.

The app:

- Generates a captcha challenge with the local library
- Renders the PNG inline in a simple HTML form
- Posts the token and typed answer back to the server
- Verifies the answer with the same local library

Set `PORT` if you want a port other than `3000`.

Set `CAPTCHA_TEXT` if you want a fixed captcha value for demos or automated testing, for example:

```bash
CAPTCHA_TEXT=DEMO42 yarn start
```
