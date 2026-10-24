# Hari Om: your private ledger with reminders

White and black app for Android. Runs on your own Cloudflare account (free plan is enough).
Your data is encrypted, the app asks for your PIN every time it opens, and it can notify you and send WhatsApp reminders.

## Step 1. Put the app online (one time, about 15 minutes, needs a computer)

1. Install Node.js (the LTS version) from https://nodejs.org
2. Unzip this folder, open a terminal or command prompt inside it and run these one by one:

```
npx wrangler login
npx wrangler d1 create hariom-db
```

3. The second command prints a `database_id`. Open `wrangler.toml`, replace `PASTE_YOUR_DATABASE_ID_HERE` with it and save.

```
npx wrangler d1 execute hariom-db --remote --file=schema.sql
npx wrangler deploy
```

4. The last command prints your link, like `https://hariom.your-name.workers.dev`. Do not open it yet.

## Step 2. Create your secret keys (do this before using the app)

These keys are what keep your data private. They are made on your computer and sent straight to Cloudflare.

```
node scripts/setup-secrets.mjs
npx wrangler secret bulk secrets.json
```

* The first command prints your **setup code**. Write it down, you need it once when creating your account.
* **Keep a copy of `secrets.json` in a password manager or a private note.** It holds the key that unlocks your data. If it is lost, the saved data cannot be read, even by you. Then delete the file from this folder (never put it in a zip, email or chat).
* Without these keys the app refuses to work. That is on purpose.

## Step 3. Install on your phone

1. Open your link in Chrome on the phone.
2. Create your account: mobile number, 4 digit PIN and the setup code. Only one account can ever be created, and only with the setup code, so nobody else can take over your app.
3. Save the recovery key shown on the screen (take a screenshot). It is the only way to reset a forgotten PIN.
4. Chrome menu (three dots) > **Install app** (or **Add to Home screen**).

## Step 4. Turn on notifications

Open the app > **You** tab > **Turn on notifications**. Use **Send a test** to check. Chrome will ask for permission once. It also asks the first time you set a reminder for yourself.

## Using it

* **+ button**: the Transaction Slip. Slide between *You Gave* (green, you will receive) and *You Took* (red, you will pay).
* After **You Gave**, you write a WhatsApp message for that person and choose when it goes. After **You Took**, it opens **Remind me**: write what the notification should say to you and pick the date and time. A switch lets you change the target either way.
* Repeats: once, every 15 days, every 30 days, every month, last day of month, or custom days.
* **Receive** and **Pay** tabs show totals and parties. Tap a party for its history by month, tap a transaction for all details, edit or delete.
* **Remind** tab: upcoming and sent. If WhatsApp is not connected yet, you get a notification when a message is due and **Send now** opens WhatsApp with the message ready.
* The app locks when you leave it (1, 5 or 15 minutes, your choice) and asks for the PIN on every fresh launch. It works offline and uploads your changes when the internet returns.

## How your data is protected

| Risk | What stops it |
|---|---|
| Someone steals the database | Names, phone numbers, amounts, notes and messages are stored as AES-256-GCM ciphertext. The key is a Cloudflare secret that is not in the database. Your mobile number is stored only as a keyed hash. |
| Guessing your PIN | 5 wrong PINs lock login for 15 minutes, then 1 hour, 6 hours, 24 hours. The PIN is hashed together with a server secret, so a stolen database cannot be brute forced. A rate limit also applies per internet address. |
| Someone else creating an account on your link | Account creation needs your setup code and works only once. |
| Another website acting as you | The login cookie is HttpOnly, Secure and SameSite=Strict, so page scripts and other sites cannot use it. Every request must also come from your own site. |
| Malicious text injected into the app | Strict Content-Security-Policy (only your own scripts run, no framing), and all text is escaped before display. |
| Someone picks up your unlocked phone later | The app locks itself after the time you choose. The copy of your data on the phone is encrypted with your PIN. Five wrong PINs on the lock screen erase it from the phone (it stays on the server). |
| Lost phone | Log in from another phone, change your PIN. Changing the PIN signs out every other device. |

Be aware of the limits:
* A 4 digit PIN is weak against someone who has your phone **and** your encrypted local copy. The lockout protects the server, not a stolen file. A phone screen lock is your first line of defence.
* You (as the Cloudflare account owner) can technically read the data, because the server must be able to send reminders. Protect your Cloudflare login with two-factor authentication.
* WhatsApp messages travel through Meta's WhatsApp servers like any WhatsApp message. Push notifications go through Google's push service, but it only receives an empty wake-up signal. The text is fetched from your own server.
* The "Download backup" file is not encrypted. Keep it private.

## Step 5. Automatic WhatsApp sending (optional, do it after the app works)

1. Go to https://developers.facebook.com, create a Meta developer account and a **Business** app, add the **WhatsApp** product and add your business number.
2. Create a message template (category Utility) with exactly two variables, for example:
   `Hello {{1}}, this is a reminder: {{2}} Thank you.`
   Wait for Meta to approve it.
3. From the WhatsApp > API Setup page note the **Phone number ID** and create a **permanent access token** (System User token) with the `whatsapp_business_messaging` permission.
4. Run these, pasting each value when asked:

```
npx wrangler secret put WA_TOKEN
npx wrangler secret put WA_PHONE_ID
npx wrangler secret put WA_TEMPLATE
```

(`WA_TEMPLATE` is the template name. If it is not English, also run `npx wrangler secret put WA_LANG` with its code, for example `en_US` or `hi`.)

The server checks every minute and sends due messages. Meta's rules about using one number in both the WhatsApp Business app and the API change from time to time, so check their current onboarding page.

## If something goes wrong

* **"Server is not set up yet"**: do step 2.
* **Cloudflare shows "CPU time limit exceeded" on login**: the free plan allows very little processing per request. Cloudflare's paid Workers plan (about 5 US dollars a month) removes the limit. Nothing else changes.
* **Forgot your PIN**: login screen > Forgot PIN > recovery key.
* **Lost both the PIN and the recovery key**: the data cannot be opened any more. To start fresh, open the D1 database `hariom-db` in the Cloudflare dashboard and run `delete from users; delete from sessions;`, then create the account again with your setup code. Old entries stay in the database but are not visible to the new account.

## Updating later

Change files in `public/` or `src/`, then run `npx wrangler deploy`. Your data is not touched.

## Files

* `public/` the app (index.html, app.js, styles.css, theme.js, manifest, service worker, icons)
* `src/worker.js` login, encrypted storage, sync, reminders, push and WhatsApp
* `schema.sql` database tables
* `scripts/setup-secrets.mjs` creates your secret keys
* `wrangler.toml` Cloudflare settings
