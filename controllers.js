const { fetch } = require('undici');
const crypto = require('crypto');

// --------------------- Config (from env) ---------------------
const QRNG_ENABLED = String(process.env.QRNG_ENABLED || 'false') === 'true';
const QRNG_URL = process.env.QRNG_URL || 'https://api.qrng.outshift.com/api/v1/random_numbers';
const QRNG_API_KEY = process.env.QRNG_API_KEY || '';
const QRNG_BITS_PER_BLOCK = parseInt(process.env.QRNG_BITS_PER_BLOCK || '8', 10); // 8 bits = 1 byte, optimal for 32-byte seeds
const QRNG_RESEED_MS = parseInt(process.env.QRNG_RESEED_MS || '3600000', 10); // Default 1 hour

const MAX_LEN = 256;
const MAX_COUNT = 50;

const DEFAULT_SYMBOLS = '!@#$%^&*()-_=+[]{}:;<>,.?';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';

// --- Minimal HKDF (Node has hkdfSync in v19+, we'll stay portable) ---
function hkdfSha256(ikm, salt, info, length) {
  // HKDF-Extract
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  // HKDF-Expand
  const blocks = [];
  let prev = Buffer.alloc(0);
  let generated = 0;
  for (let i = 1; generated < length; i++) {
    const h = crypto.createHmac('sha256', prk);
    h.update(prev);
    h.update(info);
    h.update(Buffer.from([i]));
    const t = h.digest();
    blocks.push(t);
    generated += t.length;
    prev = t;
  }
  return Buffer.concat(blocks).subarray(0, length);
}

// --- AES-256-CTR CSPRNG (key/iv via HKDF from QRNG + OS entropy) ---
class CSPRNG {
  constructor() {
    this.key = null;          // 32 bytes
    this.ivBase = null;       // 16 bytes (CTR IV prefix)
    this.counter = 0n;        // 64-bit block counter
    this.pool = Buffer.alloc(0);
    this.lastReseed = 0;
  }

  async reseed(seedMaterial) {
    // Mix QRNG seed with OS entropy to protect against either source failing
    const osEntropy = crypto.randomBytes(32);
    const salt = crypto.createHash('sha256').update(osEntropy).digest();
    const info = Buffer.from('hamtech-password-csprng-seed');
    const okm = hkdfSha256(seedMaterial, salt, info, 48); // 32B key + 16B IV

    this.key = okm.subarray(0, 32);
    this.ivBase = okm.subarray(32, 48);
    this.counter = 0n;
    this.pool = Buffer.alloc(0);
    this.lastReseed = Date.now();
  }

  // Create a fresh IV by combining ivBase with a 64-bit counter
  _ivForCounter(cnt) {
    // ivBase: 16 bytes -> treat last 8 bytes as counter field
    const iv = Buffer.from(this.ivBase);
    const ctrBytes = Buffer.alloc(8);
    ctrBytes.writeBigUInt64BE(cnt);
    // put the counter in the tail of IV
    ctrBytes.copy(iv, 8);
    return iv;
  }

  _refill(minBytes = 4096) {
    if (!this.key || !this.ivBase) {
      // Fallback to OS RNG if not seeded yet
      this.pool = Buffer.concat([this.pool, crypto.randomBytes(minBytes)]);
      return;
    }
    const chunkSize = Math.max(4096, minBytes);
    // Generate in 16-byte blocks; each counter value produces a new keystream segment
    const blocks = Math.ceil(chunkSize / 16);
    const out = Buffer.alloc(blocks * 16);
    let offset = 0;

    for (let i = 0; i < blocks; i++) {
      const iv = this._ivForCounter(this.counter);
      this.counter += 1n;

      const cipher = crypto.createCipheriv('aes-256-ctr', this.key, iv);
      // Encrypt 16 zero bytes → 16 bytes of keystream
      const ks = Buffer.concat([cipher.update(Buffer.alloc(16)), cipher.final()]);
      ks.copy(out, offset);
      offset += 16;
    }
    this.pool = Buffer.concat([this.pool, out]);
  }

  async getBytes(n) {
    const now = Date.now();
    if (!this.key || !this.ivBase || (now - this.lastReseed) >= QRNG_RESEED_MS) {
      // Caller is responsible for providing fresh QRNG seed via reseed()
      // We don't auto-seed here to keep responsibilities clean
    }
    if (this.pool.length < n) this._refill(n - this.pool.length);
    const out = this.pool.subarray(0, n);
    this.pool = this.pool.subarray(n);
    return out;
  }
}

const csprng = new CSPRNG();
/** Map 32-bit words to indices with rejection sampling (no modulo bias). */
function indicesFromBytes(buf, base) {
    const out = [];
    const acceptMax = Math.floor(0x100000000 / base) * base;
    for (let i = 0; i + 4 <= buf.length; i += 4) {
        const n = buf.readUInt32BE(i);
        if (n < acceptMax) out.push(n % base);
    }
    return out;
}

// --------------- Charset & policies ---------------
function buildCharset(opts) {
    const {
        includeLower = true, includeUpper = true, includeDigits = true,
        includeSymbols = true, symbols = DEFAULT_SYMBOLS, excludeAmbiguous = true
    } = opts || {};

    let set = '';
    if (includeLower) set += LOWER;
    if (includeUpper) set += UPPER;
    if (includeDigits) set += DIGITS;
    if (includeSymbols) set += (symbols || DEFAULT_SYMBOLS);

    if (!set) throw new Error('Empty charset: select at least one class');

    if (excludeAmbiguous) {
        const amb = new Set(['O', '0', 'I', 'l', '1', 'S', '5', 'B', '8', 'Z', '2']);
        set = Array.from(set).filter(ch => !amb.has(ch)).join('');
    }
    // Dedup
    set = Array.from(new Set(set)).join('');
    if (set.length < 2) throw new Error('Charset too small after filters');

    return set;
}

// ----------------- QRNG seed helpers -----------------

function packBlocksToBytes(blocks, bitsPerBlock = QRNG_BITS_PER_BLOCK) {
    let bits = '';
    for (const item of blocks) {
        let b = (item && typeof item.binary === 'string') ? item.binary.trim() : null;
        if (!b || !/^[01]+$/.test(b)) {
            const d = Number(item?.decimal);
            if (!Number.isInteger(d) || d < 0) continue;
            b = d.toString(2);
        }
        // force fixed width to avoid bias
        b = b.padStart(bitsPerBlock, '0');
        bits += b;
    }
    const out = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        out.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return Buffer.from(out);
}

async function fetchOutshiftQrngBlocks(blockCount) {
    if (!QRNG_ENABLED || !QRNG_API_KEY) throw new Error('QRNG not configured');
    const body = { encoding: 'raw', format: 'all', bits_per_block: QRNG_BITS_PER_BLOCK, number_of_blocks: blockCount };
    const r = await fetch(QRNG_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-id-api-key': QRNG_API_KEY
        },
        body: JSON.stringify(body),
        cache: 'no-store'
    });
    if (!r.ok) throw new Error(`QRNG HTTP ${r.status}`);
    const json = await r.json();
    const arr = json?.random_numbers;
    if (!Array.isArray(arr) || arr.length === 0) throw new Error('QRNG returned no data');
    return packBlocksToBytes(arr, QRNG_BITS_PER_BLOCK);
}

// Pull a small QRNG seed (e.g., 64 bytes = 512 bits) for reseeding
async function getQrngSeedBytes(seedBytes = 64) {
  // We'll request enough blocks to cover seedBytes (8 bits per block = 1 byte per block)
  const bitsNeeded = seedBytes * 8;
  const blocks = Math.ceil(bitsNeeded / QRNG_BITS_PER_BLOCK);
  const buf = await fetchOutshiftQrngBlocks(blocks);
  // Truncate to exactly seedBytes
  return buf.subarray(0, seedBytes);
}

// Reseed scheduler (call at startup and on interval)
async function reseedFromQrng() {
  if (!QRNG_ENABLED || !QRNG_API_KEY) {
    // Fall back to OS entropy if QRNG is unavailable
    await csprng.reseed(crypto.randomBytes(64));
    return;
  }
  const seed = await getQrngSeedBytes(64);
  await csprng.reseed(seed);
  console.log(`[${new Date().toISOString()}] CSPRNG reseeded from QRNG (${seed.length} bytes)`);
}

// Kick off at boot and every QRNG_RESEED_MS
(async () => {
  try {
    await reseedFromQrng();
  } catch (e) {
    console.error('Initial reseed failed, using OS entropy fallback:', e);
    await csprng.reseed(crypto.randomBytes(64));
  }
  setInterval(() => {
    reseedFromQrng().catch(err => console.error('Periodic reseed failed:', err));
  }, QRNG_RESEED_MS);
})();

// --------------- Password derivation ---------------
async function derivePassword(length, charset, requireEachClass, opts) {
  if (length > MAX_LEN) throw new Error('length exceeds limit');

  // Pull a chunk from the CSPRNG, top up as needed
  let stream = await csprng.getBytes(Math.max(128, length * 4)); // 4B → 1 index; top-up below if needed

  const pullIdx = (base) => {
    let pool = [];
    return async (n = base) => {
      while (pool.length === 0) {
        pool = indicesFromBytes(stream, base);
        if (pool.length === 0) {
          // top-up the stream
          stream = Buffer.concat([stream, await csprng.getBytes(256)]);
        }
      }
      return pool.shift() % n;
    };
  };

  const pickChar = pullIdx(charset.length);
  const out = [];
  for (let i = 0; i < length; i++) out.push(charset[await pickChar()]);

  if (requireEachClass) {
    const pickPos = pullIdx(out.length);
    const pickFromSet = async (n) => (await pullIdx(n)());
    await enforceRequirementsAsync(out, opts, pickPos, pickFromSet);
  }

  return out.join('');
}

async function enforceRequirementsAsync(pwArray, opts, pickPos, pickFromSet) {
    const reqSets = [];
    if (opts.includeLower) reqSets.push(LOWER);
    if (opts.includeUpper) reqSets.push(UPPER);
    if (opts.includeDigits) reqSets.push(DIGITS);
    if (opts.includeSymbols) reqSets.push(opts.symbols || DEFAULT_SYMBOLS);

    for (const s of reqSets) {
        if (!s) continue;
        const ok = pwArray.some(c => s.includes(c));
        if (!ok) {
            const pos = await pickPos(pwArray.length);
            const ci = await pickFromSet(s.length);
            pwArray[pos] = s[ci];
        }
    }
    return pwArray;
}

// --------------------- Controllers ---------------------
const passwordController = {
    generatePasswords: async (req, res) => {
        if (!QRNG_ENABLED || !QRNG_API_KEY) {
            return res.status(400).json({
                error: 'QRNG not configured',
                requiredEnv: ['QRNG_ENABLED=true', 'QRNG_API_KEY=<your key>', 'QRNG_URL=<optional override>']
            });
        }
        const {
            length = 24, count = 1,
            includeLower = true, includeUpper = true, includeDigits = true,
            includeSymbols = true, symbols = DEFAULT_SYMBOLS,
            excludeAmbiguous = true, requireEachClass = true
        } = req.body || {};

        const n = Math.min(Math.max(parseInt(count, 10) || 1, 1), MAX_COUNT);
        const L = Math.min(Math.max(parseInt(length, 10) || 24, 4), MAX_LEN);

        const opts = {
            includeLower: !!includeLower,
            includeUpper: !!includeUpper,
            includeDigits: !!includeDigits,
            includeSymbols: !!includeSymbols,
            symbols: String(symbols || DEFAULT_SYMBOLS),
            excludeAmbiguous: !!excludeAmbiguous
        };

        const charset = buildCharset(opts);
        const out = [];
        for (let i = 0; i < n; i++) {
            // eslint-disable-next-line no-await-in-loop
            out.push(await derivePassword(L, charset, !!requireEachClass, opts));
        }

        res.status(200).json({
            passwords: out,
            meta: {
                mode: 'charset',
                length: L,
                classes: { lower: opts.includeLower, upper: opts.includeUpper, digits: opts.includeDigits, symbols: opts.includeSymbols },
                excludeAmbiguous: opts.excludeAmbiguous,
                requireEachClass: !!requireEachClass,
                charsetSize: charset.length,
                sources: { qrng: QRNG_ENABLED }
            }
        });
    }
};

const healthController = {
    healthz: (req, res) => {
        res.json({
            ok: true,
            qrngEnabled: QRNG_ENABLED
        });
    }
};

const adminController = {
    reseedNow: async (req, res) => {
        try {
            await reseedFromQrng();
            res.json({ ok: true, reseededAt: new Date().toISOString() });
        } catch (e) {
            res.status(500).json({ ok: false, error: String(e) });
        }
    }
};

module.exports = {
    passwordController,
    healthController,
    adminController,
};


