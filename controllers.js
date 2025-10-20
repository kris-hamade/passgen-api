const { fetch } = require('undici');

// --------------------- Config (from env) ---------------------
const QRNG_ENABLED = String(process.env.QRNG_ENABLED || 'false') === 'true';
const QRNG_URL = process.env.QRNG_URL || 'https://api.qrng.outshift.com/api/v1/random_numbers';
const QRNG_API_KEY = process.env.QRNG_API_KEY || '';
const QRNG_BITS_PER_BLOCK = parseInt(process.env.QRNG_BITS_PER_BLOCK || '10', 10);

const MAX_LEN = 256;
const MAX_COUNT = 50;

const DEFAULT_SYMBOLS = '!@#$%^&*()-_=+[]{}:;<>,.?';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
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

function enforceRequirements(pwArray, opts, pickPos, pickFromSet) {
    const reqSets = [];
    if (opts.includeLower) reqSets.push(LOWER);
    if (opts.includeUpper) reqSets.push(UPPER);
    if (opts.includeDigits) reqSets.push(DIGITS);
    if (opts.includeSymbols) reqSets.push(opts.symbols || DEFAULT_SYMBOLS);

    for (const s of reqSets) {
        if (!s) continue;
        const ok = pwArray.some(c => s.includes(c));
        if (!ok) {
            const pos = pickPos(pwArray.length);
            const ci = pickFromSet(s.length);
            pwArray[pos] = s[ci];
        }
    }
    return pwArray;
}

// ----------------- QRNG fetch helpers -----------------
function pack10BitBlocksToBytes(blocks, bitsPerBlock = QRNG_BITS_PER_BLOCK) {
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
    return pack10BitBlocksToBytes(arr, QRNG_BITS_PER_BLOCK);
}

async function getQrngBytes(minBytes) {
    // Calculate how many blocks are required to reach minBytes
    const bitsNeeded = minBytes * 8;
    const blocks = Math.ceil(bitsNeeded / QRNG_BITS_PER_BLOCK);
    return await fetchOutshiftQrngBlocks(blocks);
}

// --------------- Password derivation ---------------
async function derivePassword(length, charset, requireEachClass, opts) {
    if (length > MAX_LEN) throw new Error('length exceeds limit');
    // initial QRNG buffer
    let stream = await getQrngBytes(Math.max(128, length * 8));

    const pullIdx = (base) => {
        let pool = [];
        return async (n = base) => {
            while (pool.length === 0) {
                pool = indicesFromBytes(stream, base);
                if (pool.length === 0) stream = await getQrngBytes(128);
            }
            return pool.shift() % n;
        };
    };

    const pickChar = pullIdx(charset.length);
    const out = [];
    for (let i = 0; i < length; i++) out.push(charset[await pickChar()]);

    if (requireEachClass) {
        const pickPos = pullIdx(out.length);
        const pickFromSet = async (n) => (await pullIdx(n)())
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

module.exports = {
    passwordController,
    healthController,
};


