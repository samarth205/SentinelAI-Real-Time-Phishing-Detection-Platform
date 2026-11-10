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

## API
- `GET /api/health` service status
- `GET /api/analyses?limit=20` recent scan history
- `POST /api/analyses` body `{ "url": "https://example.com" }`
- `GET /api/stats` overview counts

## Structure
`client/` React dashboard · `server/` Express API and persistence · `ml-service/` FastAPI + scikit-learn feature model.
