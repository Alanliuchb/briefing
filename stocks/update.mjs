// stocks/update.mjs
// 由 GitHub Actions 執行:抓取 Yahoo 報價 → 計算台幣總資產 → 加密寫入 data.enc
// 需要兩個環境變數(GitHub Secrets):
//   VIEW_PASSWORD        看板開啟密碼
//   PORTFOLIO_HOLDINGS   持股清單 JSON(陣列)
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const PASSWORD = process.env.VIEW_PASSWORD;
const HOLDINGS_JSON = process.env.PORTFOLIO_HOLDINGS;
if (!PASSWORD) { console.error('缺少 VIEW_PASSWORD'); process.exit(1); }
if (!HOLDINGS_JSON) { console.error('缺少 PORTFOLIO_HOLDINGS'); process.exit(1); }

const HOLDINGS = JSON.parse(HOLDINGS_JSON);
const DATA_PATH = path.join('stocks', 'data.enc');
const PBKDF2_ITERS = 200000;

// ---- 加解密(與瀏覽器 WebCrypto 相容)----
function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERS, 32, 'sha256');
}
function encrypt(obj, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(password, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const pt = Buffer.from(JSON.stringify(obj), 'utf8');
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  // WebCrypto 期望 ciphertext 後面接 authTag
  const data = Buffer.concat([ct, tag]);
  return { v: 1, iters: PBKDF2_ITERS, salt: salt.toString('base64'), iv: iv.toString('base64'), data: data.toString('base64') };
}
function decrypt(env, password) {
  const salt = Buffer.from(env.salt, 'base64');
  const iv = Buffer.from(env.iv, 'base64');
  const raw = Buffer.from(env.data, 'base64');
  const tag = raw.subarray(raw.length - 16);
  const ct = raw.subarray(0, raw.length - 16);
  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString('utf8'));
}

// ---- 抓取 Yahoo 報價 ----
async function fetchQuote(symbol) {
  const hosts = ['query1.finance.yahoo.com', 'query2.finance.yahoo.com'];
  let lastErr;
  for (const host of hosts) {
    try {
      const url = `https://${host}/v8/finance/chart/${encodeURIComponent(symbol)}?interval=1d&range=5d`;
      const res = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
          'Accept': 'application/json'
        }
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const j = await res.json();
      const meta = j?.chart?.result?.[0]?.meta;
      if (!meta || meta.regularMarketPrice == null) throw new Error('無價格');
      return { price: meta.regularMarketPrice, prev: meta.chartPreviousClose ?? meta.previousClose ?? meta.regularMarketPrice };
    } catch (e) { lastErr = e; }
  }
  throw new Error(`${symbol}: ${lastErr?.message || '抓取失敗'}`);
}

async function main() {
  // 匯率 USD→TWD
  const fxQ = await fetchQuote('TWD=X');
  const fx = fxQ.price;

  const rows = [];
  let totalVal = 0, totalCost = 0, totalValPrev = 0;
  for (const h of HOLDINGS) {
    const q = await fetchQuote(h.sym);
    const rate = h.ccy === 'USD' ? fx : 1;
    const valNative = q.price * h.shares;
    const prevNative = q.prev * h.shares;
    const costNative = h.cost * h.shares;
    const valTwd = valNative * rate;
    const prevTwd = prevNative * rate;
    const costTwd = costNative * rate;
    const pl = valNative - costNative;
    const plPct = costNative ? (pl / costNative) * 100 : 0;
    const dayPct = q.prev ? ((q.price - q.prev) / q.prev) * 100 : 0;
    rows.push({
      sym: h.sym, name: h.name, ccy: h.ccy, shares: h.shares, cost: h.cost,
      price: q.price, prev: q.prev,
      valTwd, costTwd, plTwd: valTwd - costTwd, plPct, dayPct
    });
    totalVal += valTwd; totalCost += costTwd; totalValPrev += prevTwd;
  }
  const totals = {
    val: totalVal, cost: totalCost, pl: totalVal - totalCost,
    plPct: totalCost ? ((totalVal - totalCost) / totalCost) * 100 : 0,
    dayPct: totalValPrev ? ((totalVal - totalValPrev) / totalValPrev) * 100 : 0
  };

  const now = new Date();
  const tw = new Date(now.getTime() + 8 * 3600 * 1000);
  const stamp = tw.toISOString().slice(0, 16).replace('T', ' ');

  // 讀取既有歷史(解密),附加一筆
  let history = [];
  if (fs.existsSync(DATA_PATH)) {
    try {
      const prev = decrypt(JSON.parse(fs.readFileSync(DATA_PATH, 'utf8')), PASSWORD);
      if (Array.isArray(prev.history)) history = prev.history;
    } catch (e) { console.warn('讀取舊資料失敗(可能密碼換過),重新開始歷史:', e.message); }
  }
  history.push({ t: stamp, V: Math.round(totalVal), C: Math.round(totalCost), P: Math.round(totals.pl), PP: +totals.plPct.toFixed(2), fx: +fx.toFixed(3) });

  const payload = { updated: stamp, fx, totals, rows, history };
  const enc = encrypt(payload, PASSWORD);
  fs.mkdirSync('stocks', { recursive: true });
  fs.writeFileSync(DATA_PATH, JSON.stringify(enc));
  console.log(`已更新 ${DATA_PATH} — 總資產 NT$${Math.round(totalVal).toLocaleString()},歷史 ${history.length} 筆`);
}

main().catch(e => { console.error(e); process.exit(1); });
