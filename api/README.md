# ozone-analyse

The backend for OZONE Shield. It receives a message from the website, checks it, sends it to Claude through Cloudflare AI Gateway, and returns a verdict as JSON.

## How a request is handled

1. CORS preflight and an allow-list of origins
2. Method, content type and request size checks (16 KB maximum)
3. Rate limiting: 10 requests per minute per client (IPv4 address or IPv6 /64), using the Workers Rate Limiting binding (`RATE_LIMITER`). If the limiter fails, requests are refused with 503 rather than let through.
4. Input clean-up and length checks (10 to 4,000 characters)
5. Cloudflare Turnstile check: the token from the website is verified with Siteverify and must come from `ozone-shield.bbaranda055.workers.dev`. Failures are logged with Cloudflare's error codes only, never the token or message.
6. Call to the Claude API through AI Gateway, with a 25-second timeout
7. JSON verdict returned to the website

## Configuration

- `wrangler.jsonc`: Worker name, entry point and the rate-limit binding
- Secrets, set in Cloudflare and never committed:
  - `ANTHROPIC_API_KEY`
  - `AI_GATEWAY_TOKEN`
  - `TURNSTILE_SECRET_KEY`

For local development, put test values in `api/.dev.vars`. It's listed in `.gitignore`, so it can't be committed.

## Status

This is the code as it runs today, added to the repository as a baseline. Known issues are being fixed one pull request at a time, so each change can be reviewed on its own.

## Tests

```bash
node --test api/test/*.test.mjs
```

## Deployment

Cloudflare Workers Builds deploys this Worker from the `main` branch:

- Root directory: `/api`
- Deploy command: `npx wrangler deploy`
- Settings come from `wrangler.jsonc`, which matches the dashboard

Pull requests don't create backend previews: `preview_urls` is `false` and preview builds are switched off, so no extra public copy of the API runs with the real secrets. To undo a bad deploy, roll back in Cloudflare under ozone-analyse → Deployments.
