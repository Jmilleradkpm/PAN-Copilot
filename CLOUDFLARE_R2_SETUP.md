# Cloudflare R2 — Setup Guide for PAN Copilot Distribution

One-time setup (~20 minutes). After this, every tagged release automatically
builds and uploads the `.exe` — you never touch the file hosting again.

---

## Step 1 — Create the R2 Bucket

1. Log in to [dash.cloudflare.com](https://dash.cloudflare.com)
2. Click **R2** in the left sidebar
3. Click **Create bucket**
4. Name it: `pan-copilot-downloads`
5. Leave location as **Automatic**
6. Click **Create bucket**

---

## Step 2 — Connect a Custom Domain

This gives you `https://downloads.adkcyber.com/...` instead of the ugly R2 URL.

1. In your new bucket, go to **Settings → Custom Domains**
2. Click **Connect Domain**
3. Enter: `downloads.adkcyber.com`
4. Cloudflare will automatically add the DNS record (since adkcyber.com is on Cloudflare)
5. Status changes to **Active** within ~1 minute

---

## Step 3 — Create an R2 API Token

1. Go to **R2 → Manage R2 API Tokens** (top-right of the R2 page)
2. Click **Create API Token**
3. Settings:
   - **Token name:** `github-actions-pan-copilot`
   - **Permissions:** `Object Read & Write`
   - **Bucket scope:** `pan-copilot-downloads` (specific bucket, not all)
4. Click **Create API Token**
5. **Copy both values — they're shown only once:**
   - Access Key ID
   - Secret Access Key

---

## Step 4 — Get Your Cloudflare Account ID

1. Go to any domain in your Cloudflare dashboard
2. Scroll down on the right sidebar — you'll see **Account ID**
3. Copy the 32-character hex string

---

## Step 5 — Create a GitHub Repository

1. Push the `PAN Copilot` project folder to a new GitHub repo
   ```bash
   cd "C:\Users\jmill\OneDrive\Documents\Claude\Projects\PAN Copilot"
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/pan-copilot.git
   git push -u origin main
   ```

2. Go to the repo on GitHub → **Settings → Secrets and variables → Actions**
3. Click **New repository secret** for each of the following:

| Secret Name | Value |
|---|---|
| `CF_R2_ACCESS_KEY_ID` | Access Key ID from Step 3 |
| `CF_R2_SECRET_ACCESS_KEY` | Secret from Step 3 |
| `CF_R2_ACCOUNT_ID` | Account ID from Step 4 |
| `CF_R2_BUCKET` | `pan-copilot-downloads` |
| `PAN_COPILOT_SYSTEM_PROMPT` | Full text of your `PAN_Copilot_Master_System_Prompt.md` |

> **Note on `PAN_COPILOT_SYSTEM_PROMPT`:** Your system prompt is your core IP.
> It is NOT committed to the repo — it's stored as an encrypted GitHub secret
> and injected at build time. Open your `.md` file, select all, copy, paste as
> the secret value.

---

## Step 6 — Ship Your First Release

```bash
cd "C:\Users\jmill\OneDrive\Documents\Claude\Projects\PAN Copilot"

# Tag the release
git tag v1.0.0
git push origin v1.0.0
```

That's it. GitHub Actions will:
1. Spin up a Windows runner
2. Install Python + dependencies
3. Build the `.exe` with PyInstaller
4. Zip the distribution folder
5. Upload to R2 as both `/releases/v1.0.0/PAN_Copilot_v1.0.0.zip` and `/latest/PAN_Copilot.zip`
6. Upload `/version.json` for future auto-update support

Watch the build at: `github.com/YOUR_USERNAME/pan-copilot/actions`

Build time: ~5–8 minutes on the Windows runner.

---

## Step 7 — Verify

Once the action completes, test the download URL:
```
https://downloads.adkcyber.com/latest/PAN_Copilot.zip
https://downloads.adkcyber.com/version.json
```

Both should return immediately from Cloudflare's edge.

---

## Releasing Future Versions

```bash
# Make your changes, commit them, then:
git tag v1.1.0
git push origin v1.1.0
```

The `/latest/PAN_Copilot.zip` URL automatically updates. Users who re-download
always get the newest version. The old versioned zip at `/releases/v1.0.0/...`
stays forever so you have rollback history.

---

## What Users Download

Users get a `.zip` file containing the `PAN Copilot` folder:
```
PAN Copilot/
├── PAN Copilot.exe   ← double-click to launch
├── _internal/        ← Python runtime + dependencies
└── ...
```

**Instructions for users:**
1. Download and unzip `PAN_Copilot.zip`
2. Open the `PAN Copilot` folder
3. Double-click `PAN Copilot.exe`
4. Windows may show a SmartScreen warning — click "More info" → "Run anyway"
   (this disappears after you get a code-signing certificate)

---

## Optional: Code Signing (~$200/yr, removes SmartScreen warning)

Once you have paying users, get an EV (Extended Validation) code-signing cert from:
- **DigiCert** or **Sectigo** — ~$200–400/yr
- Add the cert to GitHub Secrets and add a `signtool` step to the workflow

For the beta/launch phase, SmartScreen is a minor UX speed bump, not a blocker.
