# SentinelAI

Real time phishing URL analysis dashboard built with React, Express, MongoDB and a Python scikit-learn service.

## Requirements
- Node.js 20+
- Python 3.10+
- MongoDB (optional; analysis works without it)

## Run locally
1. Copy `.env.example` to `server/.env` and adjust `MONGODB_URI` if needed.
2. Install JavaScript dependencies: `npm install`
3. Start the API and frontend: `npm run dev`
4. Optional ML service: `cd ml-service`, create a virtual environment, `pip install -r requirements.txt`, then `uvicorn app:app --reload --port 8000`.
5. Open http://localhost:5173.

The API gracefully falls back to its transparent heuristic scorer when the ML service or MongoDB is unavailable. The UI clearly marks the model source. This prototype is a triage aid, not a guarantee that a site is safe.

## Deploy from GitHub (Render)
This repository includes `render.yaml` for a single-service deployment. Render builds the React app and serves it from the Express API, so the frontend and API share one public URL.

1. Push this repository to GitHub.
2. Sign in to [Render](https://render.com), choose **New** → **Blueprint**, and connect this GitHub repository.
3. Render reads `render.yaml`. Choose **Apply** to create the `sentinelai` web service.
4. Wait for the build to finish, then open the `onrender.com` URL shown on the service page.

The service runs without MongoDB or the Python ML service by using the API's in-memory history and heuristic URL scorer. Scan history is lost when the service restarts. For persistent history, create a MongoDB Atlas database and add `MONGODB_URI` in the Render service's **Environment** settings, then redeploy. To use the Python model, deploy `ml-service` separately and set `ML_SERVICE_URL` to its internal URL in Render. The included model is a synthetic-data baseline and should not be relied on for real-world security decisions.

Render's free services may sleep when idle and take a short time to wake on the next visit. Hosting plans and availability can change; check Render's current plan details before deploying.

## API
- `GET /api/health` service status
- `GET /api/analyses?limit=20` recent scan history
- `POST /api/analyses` body `{ "url": "https://example.com" }`
- `GET /api/stats` overview counts

## Structure
`client/` React dashboard · `server/` Express API and persistence · `ml-service/` FastAPI + scikit-learn feature model.
