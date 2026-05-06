# Deploying PAN Copilot to Railway

## Prerequisites
- Railway account at railway.app (free tier works to start)
- Git repo (GitHub, GitLab, or Bitbucket) containing this project folder
- Anthropic API key with billing credit loaded

---

## Steps

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Initial PAN Copilot"
git remote add origin https://github.com/YOUR_USERNAME/pan-copilot.git
git push -u origin main
```

### 2. Create Railway project
1. Go to railway.app → New Project → Deploy from GitHub repo
2. Select your `pan-copilot` repo
3. Railway will auto-detect Python and run `pip install -r backend/requirements.txt`

### 3. Set environment variables in Railway dashboard
| Variable | Value |
|---|---|
| `ANTHROPIC_API_KEY` | `sk-ant-api03-...` |
| `JWT_SECRET` | Any long random string (min 32 chars) |
| `PORT` | Railway sets this automatically |

### 4. Set the start command
In Railway → Settings → Deploy:
```
uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

### 5. Deploy
Railway builds and deploys automatically on every push to `main`.

Your app will be live at: `https://pan-copilot-production.up.railway.app`

The frontend is served at `/` — same domain as the API, so no CORS issues.

---

## Local development (unchanged)
```bash
cd backend
pip install -r requirements.txt
# Create backend/.env with: ANTHROPIC_API_KEY=sk-ant-...
python main.py
# Open pan_copilot.html directly in browser
```

---

## Scaling up
- Railway free tier: 500 hrs/month compute, sleeps after inactivity
- Railway Hobby ($5/mo): always-on, custom domain
- Add a custom domain in Railway → Settings → Domains
