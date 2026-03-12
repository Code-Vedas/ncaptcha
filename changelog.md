# Changelog

All notable changes to `ncaptcha-api` are documented in this file.

## [2.0.0](https://github.com/Code-Vedas/ncaptcha/tree/v2.0.0) (2026-03-11)

[Full Changelog](https://github.com/Code-Vedas/ncaptcha/compare/07488ec675e711578218b080504dcac5580ddb8f...v2.0.0)

### Added
- Modern TypeScript + ESM package structure targeting Node.js 20+.
- New functional API: `createChallenge(options?)` and `verifyChallenge(input)`.
- Stateless signed captcha verification with HMAC-SHA256.
- Replay hook support in verification and explicit `replayed` reason.
- Stronger captcha rendering with layered distortion/noise controls.
- Runtime input validation for distortion/noise and secure token parsing.
- Native `node:test` test suite with strict coverage thresholds.
- ESLint setup with strict lint gate in CI.
- GitHub workflows for CI, Release Drafter, and Trusted Publishing release flow.

### Changed
- Breaking API migration from legacy class API (`generate/check`) to function-based API.
- Captcha output now returns PNG `Buffer` + mime type instead of only data URL flow.
- Project tooling moved from legacy Mocha/nyc/Travis stack to modern TypeScript + GitHub Actions.

### Security
- Constant-time signature/hash comparisons for verification checks.
- Base64url encoding/decoding path hardened to avoid regex-based ReDoS findings.

### Removed
- Legacy v1 implementation and test stack.
- Legacy CI (`.travis.yml`) and yarn lockfile.

## 1.1.2 (Legacy v1 line summary)

Published versions in the v1 line:
`1.0.0`, `1.0.1`, `1.0.2`, `1.0.3`, `1.0.4`, `1.0.5`, `1.0.6`, `1.0.7`, `1.0.8`, `1.0.9`, `1.0.10`, `1.0.11`, `1.1.0`, `1.1.1`, `1.1.2`

Summary of the v1 line:
- JavaScript/CommonJS class-based captcha module for API-only apps.
- Legacy `generate()` and `check()` behavior.
- Older dependency/test/tooling stack and CI setup.

Planned deprecation/removal notice:
- Versions `1.1.2` and below are considered legacy and will be removed from active support/release maintenance going forward.
