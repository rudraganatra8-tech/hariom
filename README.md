# Hari Om: your private ledger, income and expense tracker

White and black app for your phone. Runs on your own Cloudflare account (free plan is enough). Your data is encrypted, the app locks itself, and it can notify you and send WhatsApp reminders.

## Put it online (GitHub + Cloudflare, nothing to type)

1. Keep this repository on GitHub with the folders `public`, `src` and `scripts` exactly as they are.
2. Cloudflare dashboard > Workers & Pages > Create > Import a repository > pick this one. Deploy command `npx wrangler deploy`, no build command.
3. In `wrangler.toml` the worker `name` must match the name of your Cloudflare worker, and `database_id` must be your D1 database id.
4. Open your `workers.dev` link on the phone, choose **Create account** (username + password, at least 8 characters). The first account becomes the owner and nobody else can ever create one.
5. Save the recovery key shown after creating the account. Then install the app (Chrome menu > Install app, or Safari Share > Add to Home Screen).

Tables and encryption keys are created automatically the first time the app runs. For the strongest setup you can also store `DATA_KEY` and `VAPID_JWK` as Cloudflare secrets (`node scripts/setup-secrets.mjs`), they are used when present.

## Using it

* **+ button** opens a menu: *You Gave*, *You Took* (money between people) and *Income*, *Expense* (your own money).
* **Income / Expense** slip: amount, category (defaults plus your own, each category gets its own section), date and time, then **Save** or **Next** for a description. No notifications for these.
* **Home** shows a live bar graph: income, expenses, and what is left.
* **More** tab: Monthly, Yearly or Lifetime view, an optional budget for each, and every category as its own section with its entries.
* **Quick unlock** (You tab): fingerprint, Face ID or the phone's own screen lock. The app password always works too.
* **Shortcuts**: long-press the installed app icon for Add expense, Add income, You Gave, You Took.
* Reminders and WhatsApp work as before (Remind tab).

## Security

| Risk | What stops it |
|---|---|
| Stolen database | Everything personal is AES-256-GCM encrypted. The username is stored only as a keyed hash. |
| Password guessing | 5 wrong passwords lock login 15 min, then 1 h, 6 h, 24 h. Rate limit per internet address. |
| Another site acting as you | HttpOnly, Secure, SameSite=Strict cookie, plus custom header and origin checks on every request. |
| Injected scripts | Strict Content-Security-Policy, all text escaped. |
| Someone holding your unlocked phone | Auto-lock, encrypted local copy, 5 wrong tries erase it from the phone. |
| Stranger creating an account on your link | Only one account can ever exist. Create yours right after deploying. |

Limits to know: with no Cloudflare secrets set, the encryption key lives in the same database (protects against leaked exports, not against someone with full access to your Cloudflare account). Use a strong password and turn on two-factor login for Cloudflare and GitHub. "Download backup" is not encrypted. Phone home-screen widgets are not possible for a web app, see Shortcuts above.

## WhatsApp automatic sending (optional)

Create a Meta developer account and Business app with the WhatsApp product, an approved Utility template with two variables (`Hello {{1}}, this is a reminder: {{2}} Thank you.`), then add `WA_TOKEN`, `WA_PHONE_ID`, `WA_TEMPLATE` (and `WA_LANG` if not English) under the worker's Settings > Variables and Secrets.

## Files

`public/` the app, `src/worker.js` backend, `src/schema.js` and `schema.sql` tables, `scripts/setup-secrets.mjs` optional keys, `wrangler.toml` Cloudflare settings.
