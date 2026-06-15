// stocks/update.mjs
// 由 GitHub Actions 執行:抓取報價 → 計算台幣總資產 → 加密寫入 data.enc
// 資料來源(皆免金鑰、可從雲端伺服器存取，避開 Yahoo 對 GitHub IP 的封鎖):
//   美股 / ETF        CNBC quote 服務(單次批次查詢)
//   匯率 USD→TWD      open.er-api.com
//   台股 ETF          台灣證交所 TWSE 官方 API
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

// ---- 共用工具 ----
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const num = v => parseFloat(String(v).replace(/[,%\s]/g, ''));

async function withRetry(fn, label, tries = 4) {
  let last;
  for (let i = 0; i < tries; i++) {
    try { return await fn(); }
    catch (e) { last = e; if (i < tries - 1) await sleep(1500 * (i + 1)); }
  }
  throw new Error(`${label}: ${last?.message || '失敗'}`);
}

// ---- 匯率 USD→TWD(open.er-api.com,免金鑰)----
async function fetchFx() {
  const res = await fetch('https://open.er-api.com/v6/latest/USD', { headers: { 'User-Agent': UA, 'Accept': 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const j = await res.json();
  const twd = j?.rates?.TWD;
  if (!twd) throw new Error('回應無 TWD 匯率');
  return twd;
}

// ---- 美股 / ETF(CNBC,一次批次查詢多檔)----
async function fetchUsQuotes(symbols) {
  if (!symbols.length) return {};
  const url = 'https://quote.cnbc.com/quote-html-webservice/restQuote/symbolType/symbol?symbols='
    + symbols.map(encodeURIComponent).join('|')
    + '&requestMethod=itv&noform=1&fund=1&exthrs=1&output=json';
  const res = await fetch(url, { headers: { 'User-Agent': UA, 'Accept': 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const j = await res.json();
  let arr = j?.FormattedQuoteResult?.FormattedQuote || [];
  if (!Array.isArray(arr)) arr = [arr];
  const map = {};
  for (const q of arr) {
    const price = num(q.last);
    const pct = num(q.change_pct);
    if (!isFinite(price)) continue;
    // 由當日漲跌幅回推昨收,計算組合層級的今日變動
    const prev = (isFinite(pct) && (1 + pct / 100) !== 0) ? price / (1 + pct / 100) : price;
    map[q.symbol] = { price, prev };
  }
  return map;
}

// ---- 台股 ETF(TWSE 官方 API,當月每日成交資訊)----
async function fetchTwQuote(stockNo) {
  const now = new Date();
  const tw = new Date(now.getTime() + 8 * 3600 * 1000);
  const ymd = tw.toISOString().slice(0, 10).replace(/-/g, '');
  const url = `https://www.twse.com.tw/rwd/zh/afterTrading/STOCK_DAY?date=${ymd}&stockNo=${stockNo}&response=json`;
  const res = await fetch(url, { headers: { 'User-Agent': UA, 'Accept': 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const j = await res.json();
  let data = j?.data;
  // 月初資料不足兩筆時,補抓上個月
  if (!data || data.length < 2) {
    const pm = new Date(tw.getTime()); pm.setUTCDate(0); // 上個月最後一天
    const ymd2 = pm.toISOString().slice(0, 10).replace(/-/g, '');
    try {
      const r2 = await fetch(`https://www.twse.com.tw/rwd/zh/afterTrading/STOCK_DAY?date=${ymd2}&stockNo=${stockNo}&response=json`, { headers: { 'User-Agent': UA, 'Accept': 'application/json' } });
      const j2 = await r2.json();
      const prevMonth = j2?.data || [];
      data = [...prevMonth, ...(data || [])];
    } catch (e) { /* 補抓失敗就用現有資料 */ }
  }
  if (!data || !data.length) throw new Error('TWSE 無資料');
  const closeAt = row => num(row[6]); // 收盤價在第 7 欄
  const last = data[data.length - 1];
  const prevRow = data.length >= 2 ? data[data.length - 2] : last;
  return { price: closeAt(last), prev: closeAt(prevRow) };
}

async function main() {
  const fx = await withRetry(fetchFx, '匯率');

  const usSyms = HOLDINGS.filter(h => h.ccy === 'USD').map(h => h.sym);
  const usMap = await withRetry(() => fetchUsQuotes(usSyms), '美股報價');

  const rows = [];
  let totalVal = 0, totalCost = 0, totalValPrev = 0;
  for (const h of HOLDINGS) {
    let q;
    if (h.ccy === 'USD') {
      q = usMap[h.sym];
      if (!q) throw new Error(`缺少報價:${h.sym}`);
    } else {
      const stockNo = h.sym.replace(/\.TW$/i, '');
      await sleep(500);
      q = await withRetry(() => fetchTwQuote(stockNo), `台股 ${h.sym}`);
    }
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
