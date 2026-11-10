import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import mongoose from 'mongoose';
import { z } from 'zod';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || 'http://localhost:5173' }));
app.use(express.json({ limit: '20kb' }));
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const analysisSchema = new mongoose.Schema({
  url: { type: String, required: true, index: true }, domain: { type: String, required: true },
  risk: { type: String, enum: ['Safe', 'High', 'Critical'], required: true }, score: { type: Number, min: 0, max: 100, required: true },
  flags: [String], source: String, durationMs: Number, scannedAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });
const Analysis = mongoose.model('Analysis', analysisSchema);
let dbReady = false;
if (process.env.MONGODB_URI) mongoose.connect(process.env.MONGODB_URI).then(() => { dbReady = true; console.log('MongoDB connected'); }).catch(err => console.warn('MongoDB unavailable; using in-memory fallback:', err.message));
const memory = [];

function heuristic(url) {
  const parsed = new URL(url); const host = parsed.hostname.toLowerCase(); const full = url.toLowerCase();
  const flags = []; let score = 4;
  if (parsed.protocol !== 'https:') { score += 18; flags.push('No HTTPS encryption'); }
  if (/\d{1,3}(?:\.\d{1,3}){3}/.test(host)) { score += 35; flags.push('IP address used as domain'); }
  if (host.split('.').length > 4) { score += 15; flags.push('Unusually deep subdomain'); }
  if (host.length > 28) { score += 12; flags.push('Unusually long domain'); }
  if (/(login|verify|secure|account|update|wallet|signin|password)/.test(full)) { score += 15; flags.push('Credential or account keywords'); }
  if (/(%[0-9a-f]{2}){4,}|@|xn--/.test(full)) { score += 25; flags.push('Obfuscated URL pattern'); }
  if ((host.match(/-/g) || []).length >= 2) { score += 18; flags.push('Multiple hyphens in domain'); }
  const known = ['google.com','microsoft.com','apple.com','amazon.com','paypal.com','github.com','notion.so'];
  if (known.some(d => host === d || host.endsWith(`.${d}`))) { score = Math.min(score, 5); flags.length = 0; flags.push('Known established domain'); }
  score = Math.min(score, 99); if (!flags.length) flags.push('No obvious risk signals');
  return { score, risk: score >= 75 ? 'Critical' : score >= 40 ? 'High' : 'Safe', flags, source: 'heuristic' };
}
const bodySchema = z.object({ url: z.string().trim().min(4).max(2048) });
app.get('/api/health', (_req, res) => res.json({ status: 'ok', database: dbReady ? 'connected' : 'offline', model: process.env.ML_SERVICE_URL || 'heuristic fallback' }));
app.post('/api/analyses', async (req, res) => {
  const parsedBody = bodySchema.safeParse(req.body);
  if (!parsedBody.success) return res.status(400).json({ error: 'Provide a valid URL (maximum 2,048 characters).' });
  let normalized; try { normalized = new URL(/^https?:\/\//i.test(parsedBody.data.url) ? parsedBody.data.url : `https://${parsedBody.data.url}`); if (!['http:','https:'].includes(normalized.protocol)) throw new Error(); } catch { return res.status(400).json({ error: 'That URL is not valid. Check the address and try again.' }); }
  const scanStartedAt = Date.now();
  let result;
  try { const response = await fetch(`${process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000'}/predict`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: normalized.href }), signal: AbortSignal.timeout(2500) }); if (!response.ok) throw new Error('ML service response error'); result = { ...await response.json(), source: 'scikit-learn' }; } catch { result = heuristic(normalized.href); }
  const record = { url: normalized.href, domain: normalized.hostname, ...result, durationMs: Date.now() - scanStartedAt, scannedAt: new Date() };
  try { if (dbReady) await Analysis.create(record); else memory.unshift(record); } catch (err) { console.error('Could not save scan:', err.message); memory.unshift(record); }
  res.status(201).json(record);
});
app.get('/api/analyses', async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
  try { const items = dbReady ? await Analysis.find().sort({ scannedAt: -1 }).limit(limit).lean() : memory.slice(0, limit); res.json({ items }); } catch { res.json({ items: memory.slice(0, limit) }); }
});
app.get('/api/stats', async (_req, res) => {
  try {
    const rows = dbReady ? await Analysis.find().lean() : memory;
    const now = new Date(); const firstHour = new Date(now); firstHour.setMinutes(0, 0, 0); firstHour.setHours(firstHour.getHours() - 11);
    const activity = Array.from({ length: 12 }, (_, index) => {
      const hour = new Date(firstHour); hour.setHours(firstHour.getHours() + index);
      return { t: hour.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }), scans: 0, threats: 0 };
    });
    const distribution = { critical: 0, high: 0, safe: 0 };
    for (const row of rows) {
      if (row.risk === 'Critical') distribution.critical++;
      else if (row.risk === 'High') distribution.high++;
      else distribution.safe++;
      const scannedAt = new Date(row.scannedAt || 0);
      const index = Math.floor((scannedAt - firstHour) / 3600000);
      if (index >= 0 && index < activity.length) {
        activity[index].scans++;
        if (row.risk !== 'Safe') activity[index].threats++;
      }
    }
    const durations = rows.map(x => Number(x.durationMs)).filter(Number.isFinite).filter(x => x > 0);
    res.json({ total: rows.length, threats: rows.filter(x => x.risk !== 'Safe').length, safe: distribution.safe, avgMs: durations.length ? Math.round(durations.reduce((a, x) => a + x, 0) / durations.length) : null, distribution, activity });
  } catch {
    res.json({ total: memory.length, threats: memory.filter(x => x.risk !== 'Safe').length, safe: memory.filter(x => x.risk === 'Safe').length, avgMs: null, distribution: { critical: 0, high: 0, safe: 0 }, activity: [] });
  }
});
const clientDist = path.resolve(__dirname, '../../client/dist');
app.use(express.static(clientDist));
app.get('*', (req, res, next) => req.path.startsWith('/api/') ? next() : res.sendFile(path.join(clientDist, 'index.html'), err => err && next()));
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'Unexpected server error.' }); });
const port = Number(process.env.PORT) || 4000;
app.listen(port, () => console.log(`SentinelAI API listening on :${port}`));
