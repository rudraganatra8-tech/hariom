# Hari Om: your private ledger, income and expense tracker

White and black app for your phone. Runs on your own Cloudflare account (free plan is enough). Your data is encrypted, the app locks itself, and it can notify you and send WhatsApp reminders.

## Put it online (GitHub + Cloudflare, nothing to type)

1. Keep this repository on GitHub with the folders `public`, `src` and `scripts` exactly as they are.
2. Cloudflare dashboard > Workers & Pages > Create > Import a repository > pick this one. Deploy command `npx wrangler deploy`, no build command.
3. In `wrangler.toml` the worker `name` must match the name of your Cloudflare worker, and `database_id` must be your D1 database id.
4. Open your `workers.dev` link on the phone, choose **Create account** (username + password, at least 8 characters). Anyone with your link can create their own separate account (up to 100 people, change it with a `MAX_USERS` variable). The first account is the admin.
5. Save the recovery key shown after creating the account. Then install the app (Chrome menu > Install app, or Safari Share > Add to Home Screen).

Tables and encryption keys are created automatically the first time the app runs. For the strongest setup you can also store `DATA_KEY` and `VAPID_JWK` as Cloudflare secrets (`node scripts/setup-secrets.mjs`), they are used when present.

## iPhone and Android

* **Android (Chrome):** menu > Install app. Fingerprint, face or screen lock unlock, notifications, and long-press shortcuts all work.
* **iPhone (Safari):** tap Share > **Add to Home Screen**, then always open Hari Om from that icon. Face ID / Touch ID unlock and notifications work only from the installed icon (iOS 16.4 or newer). The first time you tap Face ID, iOS may show a "save passkey" style prompt, that is normal. Icon shortcuts and vibration are not available on iPhone.
* The app offers to turn on quick unlock right after you create or log in to an account, and you can switch it any time in the You tab.

## Using it

* **+ button** opens a menu: *You Gave*, *You Took* (money between people) and *Income*, *Expense* (your own money).
* **Income / Expense** slip: amount, category (defaults plus your own, each category gets its own section), date and time, then **Save** or **Next** for a description. No notifications for these.
* **Home** shows a live bar graph: income, expenses, and what is left.
* **More** tab: Monthly, Yearly or Lifetime view, an optional budget for each, and every category as its own section with its entries.
* **Quick unlock** (You tab): fingerprint, Face ID or the phone's own screen lock. The app password always works too.
* **Shortcuts**: long-press the installed app icon for Add expense, Add income, You Gave, You Took.
* **Free WhatsApp reminders (no Meta account needed):** when a message is due, a notification says "Send this to Ramesh?". Tap it, unlock (Face ID / fingerprint), check the message, press **Send**. WhatsApp opens with the chat and text ready and you press its send button. If you ignore it, you are nudged again every hour (3 times). Works with normal WhatsApp or WhatsApp Business.
* Automatic sending without any tap is optional and paid by Meta (about 15 paise per message), see the last section.

## Security

| Risk | What stops it |
|---|---|
| Stolen database | Everything personal is AES-256-GCM encrypted. The username is stored only as a keyed hash. |
| Password guessing | 5 wrong passwords lock login 15 min, then 1 h, 6 h, 24 h. Rate limit per internet address. |
| Another site acting as you | HttpOnly, Secure, SameSite=Strict cookie, plus custom header and origin checks on every request. |
| Injected scripts | Strict Content-Security-Policy, all text escaped. |
| Someone holding your unlocked phone | Auto-lock, encrypted local copy, 5 wrong tries erase it from the phone. |
| One person reading another's data | Every row is tied to its owner and checked on every request. Each person's data is encrypted with row-bound keys. |
| Mass sign-ups | 5 new accounts per internet address per hour and a total user limit. |

Several people can use one server. WhatsApp automatic sending works only for the admin's account (it uses your WhatsApp number); everyone else gets a notification and sends with one tap. As the Cloudflare owner you can technically read everyone's data because the server holds the key, so only host people who trust you.

Several people can use one server. WhatsApp automatic sending works only for the admin's account (it uses your WhatsApp number); everyone else gets a notification and sends with one tap. As the Cloudflare owner you can technically read everyone's data because the server holds the key, so only host people who trust you.

Limits to know: with no Cloudflare secrets set, the encryption key lives in the same database (protects against leaked exports, not against someone with full access to your Cloudflare account). Use a strong password and turn on two-factor login for Cloudflare and GitHub. "Download backup" is not encrypted. Phone home-screen widgets are not possible for a web app, see Shortcuts above.

## WhatsApp automatic sending (optional)

Create a Meta developer account and Business app with the WhatsApp product, an approved Utility template with two variables (`Hello {{1}}, this is a reminder: {{2}} Thank you.`), then add `WA_TOKEN`, `WA_PHONE_ID`, `WA_TEMPLATE` (and `WA_LANG` if not English) under the worker's Settings > Variables and Secrets.

## Files

`public/` the app, `src/worker.js` backend, `src/schema.js` and `schema.sql` tables, `scripts/setup-secrets.mjs` optional keys, `wrangler.toml` Cloudflare settings.
