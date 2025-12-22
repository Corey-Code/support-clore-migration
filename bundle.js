(() => {
  // node_modules/@noble/secp256k1/index.js
  var secp256k1_CURVE = {
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
    h: 1n,
    a: 0n,
    b: 7n,
    Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
  };
  var { p: P, n: N, Gx, Gy, b: _b } = secp256k1_CURVE;
  var L = 32;
  var L2 = 64;
  var lengths = {
    publicKey: L + 1,
    publicKeyUncompressed: L2 + 1,
    signature: L2,
    seed: L + L / 2,
  };
  var captureTrace = (...args) => {
    if (
      'captureStackTrace' in Error &&
      typeof Error.captureStackTrace === 'function'
    ) {
      Error.captureStackTrace(...args);
    }
  };
  var err = (message = '') => {
    const e = new Error(message);
    captureTrace(e, err);
    throw e;
  };
  var isBig = (n) => typeof n === 'bigint';
  var isStr = (s) => typeof s === 'string';
  var isBytes = (a) =>
    a instanceof Uint8Array ||
    (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
  var abytes = (value, length, title = '') => {
    const bytes = isBytes(value);
    const len = value?.length;
    const needsLen = length !== void 0;
    if (!bytes || (needsLen && len !== length)) {
      const prefix = title && `"${title}" `;
      const ofLen = needsLen ? ` of length ${length}` : '';
      const got = bytes ? `length=${len}` : `type=${typeof value}`;
      err(prefix + 'expected Uint8Array' + ofLen + ', got ' + got);
    }
    return value;
  };
  var u8n = (len) => new Uint8Array(len);
  var padh = (n, pad) => n.toString(16).padStart(pad, '0');
  var bytesToHex = (b) =>
    Array.from(abytes(b))
      .map((e) => padh(e, 2))
      .join('');
  var C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
  var _ch = (ch) => {
    if (ch >= C._0 && ch <= C._9) return ch - C._0;
    if (ch >= C.A && ch <= C.F) return ch - (C.A - 10);
    if (ch >= C.a && ch <= C.f) return ch - (C.a - 10);
    return;
  };
  var hexToBytes = (hex) => {
    const e = 'hex invalid';
    if (!isStr(hex)) return err(e);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2) return err(e);
    const array = u8n(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
      const n1 = _ch(hex.charCodeAt(hi));
      const n2 = _ch(hex.charCodeAt(hi + 1));
      if (n1 === void 0 || n2 === void 0) return err(e);
      array[ai] = n1 * 16 + n2;
    }
    return array;
  };
  var cr = () => globalThis?.crypto;
  var subtle = () =>
    cr()?.subtle ?? err('crypto.subtle must be defined, consider polyfill');
  var concatBytes = (...arrs) => {
    const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0));
    let pad = 0;
    arrs.forEach((a) => {
      r.set(a, pad);
      pad += a.length;
    });
    return r;
  };
  var randomBytes = (len = L) => {
    const c = cr();
    return c.getRandomValues(u8n(len));
  };
  var big = BigInt;
  var arange = (n, min, max, msg = 'bad number: out of range') =>
    isBig(n) && min <= n && n < max ? n : err(msg);
  var M = (a, b = P) => {
    const r = a % b;
    return r >= 0n ? r : b + r;
  };
  var modN = (a) => M(a, N);
  var invert = (num, md) => {
    if (num === 0n || md <= 0n) err('no inverse n=' + num + ' mod=' + md);
    let a = M(num, md),
      b = md,
      x = 0n,
      y = 1n,
      u = 1n,
      v = 0n;
    while (a !== 0n) {
      const q = b / a,
        r = b % a;
      const m = x - u * q,
        n = y - v * q;
      (b = a), (a = r), (x = u), (y = v), (u = m), (v = n);
    }
    return b === 1n ? M(x, md) : err('no inverse');
  };
  var callHash = (name) => {
    const fn = hashes[name];
    if (typeof fn !== 'function') err('hashes.' + name + ' not set');
    return fn;
  };
  var apoint = (p) => (p instanceof Point ? p : err('Point expected'));
  var koblitz = (x) => M(M(x * x) * x + _b);
  var FpIsValid = (n) => arange(n, 0n, P);
  var FpIsValidNot0 = (n) => arange(n, 1n, P);
  var FnIsValidNot0 = (n) => arange(n, 1n, N);
  var isEven = (y) => (y & 1n) === 0n;
  var u8of = (n) => Uint8Array.of(n);
  var getPrefix = (y) => u8of(isEven(y) ? 2 : 3);
  var lift_x = (x) => {
    const c = koblitz(FpIsValidNot0(x));
    let r = 1n;
    for (let num = c, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
      if (e & 1n) r = (r * num) % P;
      num = (num * num) % P;
    }
    return M(r * r) === c ? r : err('sqrt invalid');
  };
  var Point = class _Point {
    static BASE;
    static ZERO;
    X;
    Y;
    Z;
    constructor(X, Y, Z) {
      this.X = FpIsValid(X);
      this.Y = FpIsValidNot0(Y);
      this.Z = FpIsValid(Z);
      Object.freeze(this);
    }
    static CURVE() {
      return secp256k1_CURVE;
    }
    /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
    static fromAffine(ap) {
      const { x, y } = ap;
      return x === 0n && y === 0n ? I : new _Point(x, y, 1n);
    }
    /** Convert Uint8Array or hex string to Point. */
    static fromBytes(bytes) {
      abytes(bytes);
      const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
      let p = void 0;
      const length = bytes.length;
      const head = bytes[0];
      const tail = bytes.subarray(1);
      const x = sliceBytesNumBE(tail, 0, L);
      if (length === comp && (head === 2 || head === 3)) {
        let y = lift_x(x);
        const evenY = isEven(y);
        const evenH = isEven(big(head));
        if (evenH !== evenY) y = M(-y);
        p = new _Point(x, y, 1n);
      }
      if (length === uncomp && head === 4)
        p = new _Point(x, sliceBytesNumBE(tail, L, L2), 1n);
      return p ? p.assertValidity() : err('bad point: not on curve');
    }
    static fromHex(hex) {
      return _Point.fromBytes(hexToBytes(hex));
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    /** Equality check: compare points P&Q. */
    equals(other) {
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
      const X1Z2 = M(X1 * Z2);
      const X2Z1 = M(X2 * Z1);
      const Y1Z2 = M(Y1 * Z2);
      const Y2Z1 = M(Y2 * Z1);
      return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    is0() {
      return this.equals(I);
    }
    /** Flip point over y coordinate. */
    negate() {
      return new _Point(this.X, M(-this.Y), this.Z);
    }
    /** Point doubling: P+P, complete formula. */
    double() {
      return this.add(this);
    }
    /**
     * Point addition: P+Q, complete, exception-free formula
     * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
     * Cost: `12M + 0S + 3*a + 3*b3 + 23add`.
     */
    // prettier-ignore
    add(other) {
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
      const a = 0n;
      const b = _b;
      let X3 = 0n, Y3 = 0n, Z3 = 0n;
      const b3 = M(b * 3n);
      let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1);
      let t4 = M(X2 + Y2);
      t3 = M(t3 * t4);
      t4 = M(t0 + t1);
      t3 = M(t3 - t4);
      t4 = M(X1 + Z1);
      let t5 = M(X2 + Z2);
      t4 = M(t4 * t5);
      t5 = M(t0 + t2);
      t4 = M(t4 - t5);
      t5 = M(Y1 + Z1);
      X3 = M(Y2 + Z2);
      t5 = M(t5 * X3);
      X3 = M(t1 + t2);
      t5 = M(t5 - X3);
      Z3 = M(a * t4);
      X3 = M(b3 * t2);
      Z3 = M(X3 + Z3);
      X3 = M(t1 - Z3);
      Z3 = M(t1 + Z3);
      Y3 = M(X3 * Z3);
      t1 = M(t0 + t0);
      t1 = M(t1 + t0);
      t2 = M(a * t2);
      t4 = M(b3 * t4);
      t1 = M(t1 + t2);
      t2 = M(t0 - t2);
      t2 = M(a * t2);
      t4 = M(t4 + t2);
      t0 = M(t1 * t4);
      Y3 = M(Y3 + t0);
      t0 = M(t5 * t4);
      X3 = M(t3 * X3);
      X3 = M(X3 - t0);
      t0 = M(t3 * t1);
      Z3 = M(t5 * Z3);
      Z3 = M(Z3 + t0);
      return new _Point(X3, Y3, Z3);
    }
    subtract(other) {
      return this.add(apoint(other).negate());
    }
    /**
     * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
     * Uses {@link wNAF} for base point.
     * Uses fake point to mitigate side-channel leakage.
     * @param n scalar by which point is multiplied
     * @param safe safe mode guards against timing attacks; unsafe mode is faster
     */
    multiply(n, safe = true) {
      if (!safe && n === 0n) return I;
      FnIsValidNot0(n);
      if (n === 1n) return this;
      if (this.equals(G)) return wNAF(n).p;
      let p = I;
      let f = G;
      for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
        if (n & 1n) p = p.add(d);
        else if (safe) f = f.add(d);
      }
      return p;
    }
    multiplyUnsafe(scalar) {
      return this.multiply(scalar, false);
    }
    /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
    toAffine() {
      const { X: x, Y: y, Z: z } = this;
      if (this.equals(I)) return { x: 0n, y: 0n };
      if (z === 1n) return { x, y };
      const iz = invert(z, P);
      if (M(z * iz) !== 1n) err('inverse invalid');
      return { x: M(x * iz), y: M(y * iz) };
    }
    /** Checks if the point is valid and on-curve. */
    assertValidity() {
      const { x, y } = this.toAffine();
      FpIsValidNot0(x);
      FpIsValidNot0(y);
      return M(y * y) === koblitz(x) ? this : err('bad point: not on curve');
    }
    /** Converts point to 33/65-byte Uint8Array. */
    toBytes(isCompressed = true) {
      const { x, y } = this.assertValidity().toAffine();
      const x32b = numTo32b(x);
      if (isCompressed) return concatBytes(getPrefix(y), x32b);
      return concatBytes(u8of(4), x32b, numTo32b(y));
    }
    toHex(isCompressed) {
      return bytesToHex(this.toBytes(isCompressed));
    }
  };
  var G = new Point(Gx, Gy, 1n);
  var I = new Point(0n, 1n, 0n);
  Point.BASE = G;
  Point.ZERO = I;
  var bytesToNumBE = (b) => big('0x' + (bytesToHex(b) || '0'));
  var sliceBytesNumBE = (b, from, to) => bytesToNumBE(b.subarray(from, to));
  var B256 = 2n ** 256n;
  var numTo32b = (num) => hexToBytes(padh(arange(num, 0n, B256), L2));
  var secretKeyToScalar = (secretKey) => {
    const num = bytesToNumBE(abytes(secretKey, L, 'secret key'));
    return arange(num, 1n, N, 'invalid secret key: outside of range');
  };
  var highS = (n) => n > N >> 1n;
  var getPublicKey = (privKey, isCompressed = true) => {
    return G.multiply(secretKeyToScalar(privKey)).toBytes(isCompressed);
  };
  var assertRecoveryBit = (recovery) => {
    if (![0, 1, 2, 3].includes(recovery))
      err('recovery id must be valid and present');
  };
  var assertSigFormat = (format) => {
    if (format != null && !ALL_SIG.includes(format))
      err(`Signature format must be one of: ${ALL_SIG.join(', ')}`);
    if (format === SIG_DER)
      err('Signature format "der" is not supported: switch to noble-curves');
  };
  var assertSigLength = (sig, format = SIG_COMPACT) => {
    assertSigFormat(format);
    const SL = lengths.signature;
    const RL = SL + 1;
    let msg = `Signature format "${format}" expects Uint8Array with length `;
    if (format === SIG_COMPACT && sig.length !== SL) err(msg + SL);
    if (format === SIG_RECOVERED && sig.length !== RL) err(msg + RL);
  };
  var Signature = class _Signature {
    r;
    s;
    recovery;
    constructor(r, s, recovery) {
      this.r = FnIsValidNot0(r);
      this.s = FnIsValidNot0(s);
      if (recovery != null) this.recovery = recovery;
      Object.freeze(this);
    }
    static fromBytes(b, format = SIG_COMPACT) {
      assertSigLength(b, format);
      let rec;
      if (format === SIG_RECOVERED) {
        rec = b[0];
        b = b.subarray(1);
      }
      const r = sliceBytesNumBE(b, 0, L);
      const s = sliceBytesNumBE(b, L, L2);
      return new _Signature(r, s, rec);
    }
    addRecoveryBit(bit) {
      return new _Signature(this.r, this.s, bit);
    }
    hasHighS() {
      return highS(this.s);
    }
    toBytes(format = SIG_COMPACT) {
      const { r, s, recovery } = this;
      const res = concatBytes(numTo32b(r), numTo32b(s));
      if (format === SIG_RECOVERED) {
        assertRecoveryBit(recovery);
        return concatBytes(Uint8Array.of(recovery), res);
      }
      return res;
    }
  };
  var bits2int = (bytes) => {
    const delta = bytes.length * 8 - 256;
    if (delta > 1024) err('msg invalid');
    const num = bytesToNumBE(bytes);
    return delta > 0 ? num >> big(delta) : num;
  };
  var bits2int_modN = (bytes) => modN(bits2int(abytes(bytes)));
  var SIG_COMPACT = 'compact';
  var SIG_RECOVERED = 'recovered';
  var SIG_DER = 'der';
  var ALL_SIG = [SIG_COMPACT, SIG_RECOVERED, SIG_DER];
  var defaultSignOpts = {
    lowS: true,
    prehash: true,
    format: SIG_COMPACT,
    extraEntropy: false,
  };
  var _sha = 'SHA-256';
  var hashes = {
    hmacSha256Async: async (key, message) => {
      const s = subtle();
      const name = 'HMAC';
      const k = await s.importKey(
        'raw',
        key,
        { name, hash: { name: _sha } },
        false,
        ['sign']
      );
      return u8n(await s.sign(name, k, message));
    },
    hmacSha256: void 0,
    sha256Async: async (msg) => u8n(await subtle().digest(_sha, msg)),
    sha256: void 0,
  };
  var prepMsg = (msg, opts, async_) => {
    abytes(msg, void 0, 'message');
    if (!opts.prehash) return msg;
    return async_ ? hashes.sha256Async(msg) : callHash('sha256')(msg);
  };
  var NULL = u8n(0);
  var byte0 = u8of(0);
  var byte1 = u8of(1);
  var _maxDrbgIters = 1e3;
  var _drbgErr = 'drbg: tried max amount of iterations';
  var hmacDrbg = (seed, pred) => {
    let v = u8n(L);
    let k = u8n(L);
    let i = 0;
    const reset = () => {
      v.fill(1);
      k.fill(0);
    };
    const h = (...b) => callHash('hmacSha256')(k, concatBytes(v, ...b));
    const reseed = (seed2 = NULL) => {
      k = h(byte0, seed2);
      v = h();
      if (seed2.length === 0) return;
      k = h(byte1, seed2);
      v = h();
    };
    const gen = () => {
      if (i++ >= _maxDrbgIters) err(_drbgErr);
      v = h();
      return v;
    };
    reset();
    reseed(seed);
    let res = void 0;
    while (!(res = pred(gen()))) reseed();
    reset();
    return res;
  };
  var _sign = (messageHash, secretKey, opts, hmacDrbg2) => {
    let { lowS, extraEntropy } = opts;
    const int2octets = numTo32b;
    const h1i = bits2int_modN(messageHash);
    const h1o = int2octets(h1i);
    const d = secretKeyToScalar(secretKey);
    const seedArgs = [int2octets(d), h1o];
    if (extraEntropy != null && extraEntropy !== false) {
      const e = extraEntropy === true ? randomBytes(L) : extraEntropy;
      seedArgs.push(abytes(e, void 0, 'extraEntropy'));
    }
    const seed = concatBytes(...seedArgs);
    const m = h1i;
    const k2sig = (kBytes) => {
      const k = bits2int(kBytes);
      if (!(1n <= k && k < N)) return;
      const ik = invert(k, N);
      const q = G.multiply(k).toAffine();
      const r = modN(q.x);
      if (r === 0n) return;
      const s = modN(ik * modN(m + r * d));
      if (s === 0n) return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & 1n);
      let normS = s;
      if (lowS && highS(s)) {
        normS = modN(-s);
        recovery ^= 1;
      }
      const sig = new Signature(r, normS, recovery);
      return sig.toBytes(opts.format);
    };
    return hmacDrbg2(seed, k2sig);
  };
  var setDefaults = (opts) => {
    const res = {};
    Object.keys(defaultSignOpts).forEach((k) => {
      res[k] = opts[k] ?? defaultSignOpts[k];
    });
    return res;
  };
  var sign = (message, secretKey, opts = {}) => {
    opts = setDefaults(opts);
    message = prepMsg(message, opts, false);
    return _sign(message, secretKey, opts, hmacDrbg);
  };
  var randomSecretKey = (seed = randomBytes(lengths.seed)) => {
    abytes(seed);
    if (seed.length < lengths.seed || seed.length > 1024)
      err('expected 40-1024b');
    const num = M(bytesToNumBE(seed), N - 1n);
    return numTo32b(num + 1n);
  };
  var createKeygen = (getPublicKey2) => (seed) => {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey2(secretKey) };
  };
  var keygen = createKeygen(getPublicKey);
  var extpubSchnorr = (priv) => {
    const d_ = secretKeyToScalar(priv);
    const p = G.multiply(d_);
    const { x, y } = p.assertValidity().toAffine();
    const d = isEven(y) ? d_ : modN(-d_);
    const px = numTo32b(x);
    return { d, px };
  };
  var pubSchnorr = (secretKey) => {
    return extpubSchnorr(secretKey).px;
  };
  var keygenSchnorr = createKeygen(pubSchnorr);
  var W = 8;
  var scalarBits = 256;
  var pwindows = Math.ceil(scalarBits / W) + 1;
  var pwindowSize = 2 ** (W - 1);
  var precompute = () => {
    const points = [];
    let p = G;
    let b = p;
    for (let w = 0; w < pwindows; w++) {
      b = p;
      points.push(b);
      for (let i = 1; i < pwindowSize; i++) {
        b = b.add(p);
        points.push(b);
      }
      p = b.double();
    }
    return points;
  };
  var Gpows = void 0;
  var ctneg = (cnd, p) => {
    const n = p.negate();
    return cnd ? n : p;
  };
  var wNAF = (n) => {
    const comp = Gpows || (Gpows = precompute());
    let p = I;
    let f = G;
    const pow_2_w = 2 ** W;
    const maxNum = pow_2_w;
    const mask = big(pow_2_w - 1);
    const shiftBy = big(W);
    for (let w = 0; w < pwindows; w++) {
      let wbits = Number(n & mask);
      n >>= shiftBy;
      if (wbits > pwindowSize) {
        wbits -= maxNum;
        n += 1n;
      }
      const off = w * pwindowSize;
      const offF = off;
      const offP = off + Math.abs(wbits) - 1;
      const isEven2 = w % 2 !== 0;
      const isNeg = wbits < 0;
      if (wbits === 0) {
        f = f.add(ctneg(isEven2, comp[offF]));
      } else {
        p = p.add(ctneg(isNeg, comp[offP]));
      }
    }
    if (n !== 0n) err('invalid wnaf');
    return { p, f };
  };

  // node_modules/bs58check/node_modules/@noble/hashes/esm/utils.js
  function isBytes2(a) {
    return (
      a instanceof Uint8Array ||
      (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array')
    );
  }
  function abytes2(b, ...lengths2) {
    if (!isBytes2(b)) throw new Error('Uint8Array expected');
    if (lengths2.length > 0 && !lengths2.includes(b.length))
      throw new Error(
        'Uint8Array expected of length ' + lengths2 + ', got length=' + b.length
      );
  }
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed) throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
      throw new Error('Hash#digest() has already been called');
  }
  function aoutput(out, instance) {
    abytes2(out);
    const min = instance.outputLen;
    if (out.length < min) {
      throw new Error(
        'digestInto() expects output buffer of length at least ' + min
      );
    }
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function rotr(word, shift) {
    return (word << (32 - shift)) | (word >>> shift);
  }
  function utf8ToBytes(str) {
    if (typeof str !== 'string') throw new Error('string expected');
    return new Uint8Array(new TextEncoder().encode(str));
  }
  function toBytes(data) {
    if (typeof data === 'string') data = utf8ToBytes(data);
    abytes2(data);
    return data;
  }
  var Hash = class {};
  function createHasher(hashCons) {
    const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashCons();
    return hashC;
  }

  // node_modules/bs58check/node_modules/@noble/hashes/esm/_md.js
  function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
      return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(4294967295);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
  }
  function Chi(a, b, c) {
    return (a & b) ^ (~a & c);
  }
  function Maj(a, b, c) {
    return (a & b) ^ (a & c) ^ (b & c);
  }
  var HashMD = class extends Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
      super();
      this.finished = false;
      this.length = 0;
      this.pos = 0;
      this.destroyed = false;
      this.blockLen = blockLen;
      this.outputLen = outputLen;
      this.padOffset = padOffset;
      this.isLE = isLE;
      this.buffer = new Uint8Array(blockLen);
      this.view = createView(this.buffer);
    }
    update(data) {
      aexists(this);
      data = toBytes(data);
      abytes2(data);
      const { view, buffer, blockLen } = this;
      const len = data.length;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          const dataView = createView(data);
          for (; blockLen <= len - pos; pos += blockLen)
            this.process(dataView, pos);
          continue;
        }
        buffer.set(data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        pos += take;
        if (this.pos === blockLen) {
          this.process(view, 0);
          this.pos = 0;
        }
      }
      this.length += data.length;
      this.roundClean();
      return this;
    }
    digestInto(out) {
      aexists(this);
      aoutput(out, this);
      this.finished = true;
      const { buffer, view, blockLen, isLE } = this;
      let { pos } = this;
      buffer[pos++] = 128;
      clean(this.buffer.subarray(pos));
      if (this.padOffset > blockLen - pos) {
        this.process(view, 0);
        pos = 0;
      }
      for (let i = pos; i < blockLen; i++) buffer[i] = 0;
      setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
      this.process(view, 0);
      const oview = createView(out);
      const len = this.outputLen;
      if (len % 4)
        throw new Error('_sha2: outputLen should be aligned to 32bit');
      const outLen = len / 4;
      const state = this.get();
      if (outLen > state.length)
        throw new Error('_sha2: outputLen bigger than state');
      for (let i = 0; i < outLen; i++) oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
    _cloneInto(to) {
      to || (to = new this.constructor());
      to.set(...this.get());
      const { blockLen, buffer, length, finished, destroyed, pos } = this;
      to.destroyed = destroyed;
      to.finished = finished;
      to.length = length;
      to.pos = pos;
      if (length % blockLen) to.buffer.set(buffer);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  };
  var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
    1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924,
    528734635, 1541459225,
  ]);

  // node_modules/bs58check/node_modules/@noble/hashes/esm/sha2.js
  var SHA256_K = /* @__PURE__ */ Uint32Array.from([
    1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993,
    2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987,
    1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774,
    264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
    2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711,
    113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
    1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411,
    3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344,
    430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
    1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424,
    2428436474, 2756734187, 3204031479, 3329325298,
  ]);
  var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
  var SHA256 = class extends HashMD {
    constructor(outputLen = 32) {
      super(64, outputLen, 8, false);
      this.A = SHA256_IV[0] | 0;
      this.B = SHA256_IV[1] | 0;
      this.C = SHA256_IV[2] | 0;
      this.D = SHA256_IV[3] | 0;
      this.E = SHA256_IV[4] | 0;
      this.F = SHA256_IV[5] | 0;
      this.G = SHA256_IV[6] | 0;
      this.H = SHA256_IV[7] | 0;
    }
    get() {
      const { A, B, C: C2, D, E, F, G: G2, H } = this;
      return [A, B, C2, D, E, F, G2, H];
    }
    // prettier-ignore
    set(A, B, C2, D, E, F, G2, H) {
      this.A = A | 0;
      this.B = B | 0;
      this.C = C2 | 0;
      this.D = D | 0;
      this.E = E | 0;
      this.F = F | 0;
      this.G = G2 | 0;
      this.H = H | 0;
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4)
        SHA256_W[i] = view.getUint32(offset, false);
      for (let i = 16; i < 64; i++) {
        const W15 = SHA256_W[i - 15];
        const W2 = SHA256_W[i - 2];
        const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);
        const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);
        SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
      }
      let { A, B, C: C2, D, E, F, G: G2, H } = this;
      for (let i = 0; i < 64; i++) {
        const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
        const T1 = (H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i]) | 0;
        const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
        const T2 = (sigma0 + Maj(A, B, C2)) | 0;
        H = G2;
        G2 = F;
        F = E;
        E = (D + T1) | 0;
        D = C2;
        C2 = B;
        B = A;
        A = (T1 + T2) | 0;
      }
      A = (A + this.A) | 0;
      B = (B + this.B) | 0;
      C2 = (C2 + this.C) | 0;
      D = (D + this.D) | 0;
      E = (E + this.E) | 0;
      F = (F + this.F) | 0;
      G2 = (G2 + this.G) | 0;
      H = (H + this.H) | 0;
      this.set(A, B, C2, D, E, F, G2, H);
    }
    roundClean() {
      clean(SHA256_W);
    }
    destroy() {
      this.set(0, 0, 0, 0, 0, 0, 0, 0);
      clean(this.buffer);
    }
  };
  var sha256 = /* @__PURE__ */ createHasher(() => new SHA256());

  // node_modules/bs58check/node_modules/@noble/hashes/esm/sha256.js
  var sha2562 = sha256;

  // node_modules/base-x/src/esm/index.js
  function base(ALPHABET2) {
    if (ALPHABET2.length >= 255) {
      throw new TypeError('Alphabet too long');
    }
    const BASE_MAP = new Uint8Array(256);
    for (let j = 0; j < BASE_MAP.length; j++) {
      BASE_MAP[j] = 255;
    }
    for (let i = 0; i < ALPHABET2.length; i++) {
      const x = ALPHABET2.charAt(i);
      const xc = x.charCodeAt(0);
      if (BASE_MAP[xc] !== 255) {
        throw new TypeError(x + ' is ambiguous');
      }
      BASE_MAP[xc] = i;
    }
    const BASE = ALPHABET2.length;
    const LEADER = ALPHABET2.charAt(0);
    const FACTOR = Math.log(BASE) / Math.log(256);
    const iFACTOR = Math.log(256) / Math.log(BASE);
    function encode(source) {
      if (source instanceof Uint8Array) {
      } else if (ArrayBuffer.isView(source)) {
        source = new Uint8Array(
          source.buffer,
          source.byteOffset,
          source.byteLength
        );
      } else if (Array.isArray(source)) {
        source = Uint8Array.from(source);
      }
      if (!(source instanceof Uint8Array)) {
        throw new TypeError('Expected Uint8Array');
      }
      if (source.length === 0) {
        return '';
      }
      let zeroes = 0;
      let length = 0;
      let pbegin = 0;
      const pend = source.length;
      while (pbegin !== pend && source[pbegin] === 0) {
        pbegin++;
        zeroes++;
      }
      const size = ((pend - pbegin) * iFACTOR + 1) >>> 0;
      const b58 = new Uint8Array(size);
      while (pbegin !== pend) {
        let carry = source[pbegin];
        let i = 0;
        for (
          let it1 = size - 1;
          (carry !== 0 || i < length) && it1 !== -1;
          it1--, i++
        ) {
          carry += (256 * b58[it1]) >>> 0;
          b58[it1] = carry % BASE >>> 0;
          carry = (carry / BASE) >>> 0;
        }
        if (carry !== 0) {
          throw new Error('Non-zero carry');
        }
        length = i;
        pbegin++;
      }
      let it2 = size - length;
      while (it2 !== size && b58[it2] === 0) {
        it2++;
      }
      let str = LEADER.repeat(zeroes);
      for (; it2 < size; ++it2) {
        str += ALPHABET2.charAt(b58[it2]);
      }
      return str;
    }
    function decodeUnsafe(source) {
      if (typeof source !== 'string') {
        throw new TypeError('Expected String');
      }
      if (source.length === 0) {
        return new Uint8Array();
      }
      let psz = 0;
      let zeroes = 0;
      let length = 0;
      while (source[psz] === LEADER) {
        zeroes++;
        psz++;
      }
      const size = ((source.length - psz) * FACTOR + 1) >>> 0;
      const b256 = new Uint8Array(size);
      while (psz < source.length) {
        const charCode = source.charCodeAt(psz);
        if (charCode > 255) {
          return;
        }
        let carry = BASE_MAP[charCode];
        if (carry === 255) {
          return;
        }
        let i = 0;
        for (
          let it3 = size - 1;
          (carry !== 0 || i < length) && it3 !== -1;
          it3--, i++
        ) {
          carry += (BASE * b256[it3]) >>> 0;
          b256[it3] = carry % 256 >>> 0;
          carry = (carry / 256) >>> 0;
        }
        if (carry !== 0) {
          throw new Error('Non-zero carry');
        }
        length = i;
        psz++;
      }
      let it4 = size - length;
      while (it4 !== size && b256[it4] === 0) {
        it4++;
      }
      const vch = new Uint8Array(zeroes + (size - it4));
      let j = zeroes;
      while (it4 !== size) {
        vch[j++] = b256[it4++];
      }
      return vch;
    }
    function decode(string) {
      const buffer = decodeUnsafe(string);
      if (buffer) {
        return buffer;
      }
      throw new Error('Non-base' + BASE + ' character');
    }
    return {
      encode,
      decodeUnsafe,
      decode,
    };
  }
  var esm_default = base;

  // node_modules/bs58/src/esm/index.js
  var ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  var esm_default2 = esm_default(ALPHABET);

  // node_modules/bs58check/src/esm/base.js
  function base_default(checksumFn) {
    function encode(payload) {
      var payloadU8 = Uint8Array.from(payload);
      var checksum = checksumFn(payloadU8);
      var length = payloadU8.length + 4;
      var both = new Uint8Array(length);
      both.set(payloadU8, 0);
      both.set(checksum.subarray(0, 4), payloadU8.length);
      return esm_default2.encode(both);
    }
    function decodeRaw(buffer) {
      var payload = buffer.slice(0, -4);
      var checksum = buffer.slice(-4);
      var newChecksum = checksumFn(payload);
      if (
        (checksum[0] ^ newChecksum[0]) |
        (checksum[1] ^ newChecksum[1]) |
        (checksum[2] ^ newChecksum[2]) |
        (checksum[3] ^ newChecksum[3])
      )
        return;
      return payload;
    }
    function decodeUnsafe(str) {
      var buffer = esm_default2.decodeUnsafe(str);
      if (buffer == null) return;
      return decodeRaw(buffer);
    }
    function decode(str) {
      var buffer = esm_default2.decode(str);
      var payload = decodeRaw(buffer);
      if (payload == null) throw new Error('Invalid checksum');
      return payload;
    }
    return {
      encode,
      decode,
      decodeUnsafe,
    };
  }

  // node_modules/bs58check/src/esm/index.js
  function sha256x2(buffer) {
    return sha2562(sha2562(buffer));
  }
  var esm_default3 = base_default(sha256x2);

  // node_modules/@noble/hashes/utils.js
  function isBytes3(a) {
    return (
      a instanceof Uint8Array ||
      (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array')
    );
  }
  function anumber(n, title = '') {
    if (!Number.isSafeInteger(n) || n < 0) {
      const prefix = title && `"${title}" `;
      throw new Error(`${prefix}expected integer >= 0, got ${n}`);
    }
  }
  function abytes3(value, length, title = '') {
    const bytes = isBytes3(value);
    const len = value?.length;
    const needsLen = length !== void 0;
    if (!bytes || (needsLen && len !== length)) {
      const prefix = title && `"${title}" `;
      const ofLen = needsLen ? ` of length ${length}` : '';
      const got = bytes ? `length=${len}` : `type=${typeof value}`;
      throw new Error(prefix + 'expected Uint8Array' + ofLen + ', got ' + got);
    }
    return value;
  }
  function ahash(h) {
    if (typeof h !== 'function' || typeof h.create !== 'function')
      throw new Error('Hash must wrapped by utils.createHasher');
    anumber(h.outputLen);
    anumber(h.blockLen);
  }
  function aexists2(instance, checkFinished = true) {
    if (instance.destroyed) throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
      throw new Error('Hash#digest() has already been called');
  }
  function aoutput2(out, instance) {
    abytes3(out, void 0, 'digestInto() output');
    const min = instance.outputLen;
    if (out.length < min) {
      throw new Error(
        '"digestInto() output" expected to be of length >=' + min
      );
    }
  }
  function clean2(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView2(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function rotr2(word, shift) {
    return (word << (32 - shift)) | (word >>> shift);
  }
  function createHasher2(hashCons, info = {}) {
    const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
    const tmp = hashCons(void 0);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
  }
  var oidNist = (suffix) => ({
    oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix]),
  });

  // node_modules/@noble/hashes/_md.js
  function Chi2(a, b, c) {
    return (a & b) ^ (~a & c);
  }
  function Maj2(a, b, c) {
    return (a & b) ^ (a & c) ^ (b & c);
  }
  var HashMD2 = class {
    blockLen;
    outputLen;
    padOffset;
    isLE;
    // For partial updates less than block size
    buffer;
    view;
    finished = false;
    length = 0;
    pos = 0;
    destroyed = false;
    constructor(blockLen, outputLen, padOffset, isLE) {
      this.blockLen = blockLen;
      this.outputLen = outputLen;
      this.padOffset = padOffset;
      this.isLE = isLE;
      this.buffer = new Uint8Array(blockLen);
      this.view = createView2(this.buffer);
    }
    update(data) {
      aexists2(this);
      abytes3(data);
      const { view, buffer, blockLen } = this;
      const len = data.length;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          const dataView = createView2(data);
          for (; blockLen <= len - pos; pos += blockLen)
            this.process(dataView, pos);
          continue;
        }
        buffer.set(data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        pos += take;
        if (this.pos === blockLen) {
          this.process(view, 0);
          this.pos = 0;
        }
      }
      this.length += data.length;
      this.roundClean();
      return this;
    }
    digestInto(out) {
      aexists2(this);
      aoutput2(out, this);
      this.finished = true;
      const { buffer, view, blockLen, isLE } = this;
      let { pos } = this;
      buffer[pos++] = 128;
      clean2(this.buffer.subarray(pos));
      if (this.padOffset > blockLen - pos) {
        this.process(view, 0);
        pos = 0;
      }
      for (let i = pos; i < blockLen; i++) buffer[i] = 0;
      view.setBigUint64(blockLen - 8, BigInt(this.length * 8), isLE);
      this.process(view, 0);
      const oview = createView2(out);
      const len = this.outputLen;
      if (len % 4) throw new Error('_sha2: outputLen must be aligned to 32bit');
      const outLen = len / 4;
      const state = this.get();
      if (outLen > state.length)
        throw new Error('_sha2: outputLen bigger than state');
      for (let i = 0; i < outLen; i++) oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
    _cloneInto(to) {
      to ||= new this.constructor();
      to.set(...this.get());
      const { blockLen, buffer, length, finished, destroyed, pos } = this;
      to.destroyed = destroyed;
      to.finished = finished;
      to.length = length;
      to.pos = pos;
      if (length % blockLen) to.buffer.set(buffer);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  };
  var SHA256_IV2 = /* @__PURE__ */ Uint32Array.from([
    1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924,
    528734635, 1541459225,
  ]);

  // node_modules/@noble/hashes/sha2.js
  var SHA256_K2 = /* @__PURE__ */ Uint32Array.from([
    1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993,
    2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987,
    1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774,
    264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
    2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711,
    113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
    1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411,
    3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344,
    430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
    1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424,
    2428436474, 2756734187, 3204031479, 3329325298,
  ]);
  var SHA256_W2 = /* @__PURE__ */ new Uint32Array(64);
  var SHA2_32B = class extends HashMD2 {
    constructor(outputLen) {
      super(64, outputLen, 8, false);
    }
    get() {
      const { A, B, C: C2, D, E, F, G: G2, H } = this;
      return [A, B, C2, D, E, F, G2, H];
    }
    // prettier-ignore
    set(A, B, C2, D, E, F, G2, H) {
      this.A = A | 0;
      this.B = B | 0;
      this.C = C2 | 0;
      this.D = D | 0;
      this.E = E | 0;
      this.F = F | 0;
      this.G = G2 | 0;
      this.H = H | 0;
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4)
        SHA256_W2[i] = view.getUint32(offset, false);
      for (let i = 16; i < 64; i++) {
        const W15 = SHA256_W2[i - 15];
        const W2 = SHA256_W2[i - 2];
        const s0 = rotr2(W15, 7) ^ rotr2(W15, 18) ^ (W15 >>> 3);
        const s1 = rotr2(W2, 17) ^ rotr2(W2, 19) ^ (W2 >>> 10);
        SHA256_W2[i] = (s1 + SHA256_W2[i - 7] + s0 + SHA256_W2[i - 16]) | 0;
      }
      let { A, B, C: C2, D, E, F, G: G2, H } = this;
      for (let i = 0; i < 64; i++) {
        const sigma1 = rotr2(E, 6) ^ rotr2(E, 11) ^ rotr2(E, 25);
        const T1 =
          (H + sigma1 + Chi2(E, F, G2) + SHA256_K2[i] + SHA256_W2[i]) | 0;
        const sigma0 = rotr2(A, 2) ^ rotr2(A, 13) ^ rotr2(A, 22);
        const T2 = (sigma0 + Maj2(A, B, C2)) | 0;
        H = G2;
        G2 = F;
        F = E;
        E = (D + T1) | 0;
        D = C2;
        C2 = B;
        B = A;
        A = (T1 + T2) | 0;
      }
      A = (A + this.A) | 0;
      B = (B + this.B) | 0;
      C2 = (C2 + this.C) | 0;
      D = (D + this.D) | 0;
      E = (E + this.E) | 0;
      F = (F + this.F) | 0;
      G2 = (G2 + this.G) | 0;
      H = (H + this.H) | 0;
      this.set(A, B, C2, D, E, F, G2, H);
    }
    roundClean() {
      clean2(SHA256_W2);
    }
    destroy() {
      this.set(0, 0, 0, 0, 0, 0, 0, 0);
      clean2(this.buffer);
    }
  };
  var _SHA256 = class extends SHA2_32B {
    // We cannot use array here since array allows indexing by variable
    // which means optimizer/compiler cannot use registers.
    A = SHA256_IV2[0] | 0;
    B = SHA256_IV2[1] | 0;
    C = SHA256_IV2[2] | 0;
    D = SHA256_IV2[3] | 0;
    E = SHA256_IV2[4] | 0;
    F = SHA256_IV2[5] | 0;
    G = SHA256_IV2[6] | 0;
    H = SHA256_IV2[7] | 0;
    constructor() {
      super(32);
    }
  };
  var sha2563 = /* @__PURE__ */ createHasher2(
    () => new _SHA256(),
    /* @__PURE__ */ oidNist(1)
  );

  // node_modules/@noble/hashes/hmac.js
  var _HMAC = class {
    oHash;
    iHash;
    blockLen;
    outputLen;
    finished = false;
    destroyed = false;
    constructor(hash, key) {
      ahash(hash);
      abytes3(key, void 0, 'key');
      this.iHash = hash.create();
      if (typeof this.iHash.update !== 'function')
        throw new Error('Expected instance of class which extends utils.Hash');
      this.blockLen = this.iHash.blockLen;
      this.outputLen = this.iHash.outputLen;
      const blockLen = this.blockLen;
      const pad = new Uint8Array(blockLen);
      pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
      for (let i = 0; i < pad.length; i++) pad[i] ^= 54;
      this.iHash.update(pad);
      this.oHash = hash.create();
      for (let i = 0; i < pad.length; i++) pad[i] ^= 54 ^ 92;
      this.oHash.update(pad);
      clean2(pad);
    }
    update(buf) {
      aexists2(this);
      this.iHash.update(buf);
      return this;
    }
    digestInto(out) {
      aexists2(this);
      abytes3(out, this.outputLen, 'output');
      this.finished = true;
      this.iHash.digestInto(out);
      this.oHash.update(out);
      this.oHash.digestInto(out);
      this.destroy();
    }
    digest() {
      const out = new Uint8Array(this.oHash.outputLen);
      this.digestInto(out);
      return out;
    }
    _cloneInto(to) {
      to ||= Object.create(Object.getPrototypeOf(this), {});
      const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
      to = to;
      to.finished = finished;
      to.destroyed = destroyed;
      to.blockLen = blockLen;
      to.outputLen = outputLen;
      to.oHash = oHash._cloneInto(to.oHash);
      to.iHash = iHash._cloneInto(to.iHash);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
    destroy() {
      this.destroyed = true;
      this.oHash.destroy();
      this.iHash.destroy();
    }
  };
  var hmac = (hash, key, message) =>
    new _HMAC(hash, key).update(message).digest();
  hmac.create = (hash, key) => new _HMAC(hash, key);

  // app.js
  function u8(x) {
    if (x instanceof Uint8Array) return x;
    if (x instanceof ArrayBuffer) return new Uint8Array(x);
    return new Uint8Array(x);
  }
  function dbg(name, v) {
    // console.log("[DBG]", name, {
    //   type: typeof v,
    //   ctor: v && v.constructor && v.constructor.name,
    //   isU8: v instanceof Uint8Array,
    //   length: v && v.length
    // });
    return v;
  }
  function wifToHex(wif) {
    const decoded = esm_default3.decode(wif);
    const key =
      decoded.length === 34 ? decoded.slice(1, 33) : decoded.slice(1, 32);
    return Array.from(key)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  function hexToBytes2(hex) {
    if (hex.startsWith('0x')) hex = hex.slice(2);
    if (hex.length !== 64) {
      throw new Error('Private key must be 32-byte hex (64 chars) or WIF');
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
  hashes.sha256 = (msg) => u8(sha2563(u8(msg)));
  hashes.hmacSha256 = (key, msg) => u8(hmac(sha2563, u8(key), u8(msg)));
  var MESSAGE_PREFIX = 'Clore Signed Message:\n';
  function doubleSha256(bytes) {
    const h1 = hashes.sha256(bytes);
    const h2 = hashes.sha256(h1);
    return h2;
  }
  function toBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
  }
  window.signCloreMessage = async function signCloreMessage(
    privateKeyInput,
    cloreAddress,
    evmAddress
  ) {
    if (!privateKeyInput || !cloreAddress || !evmAddress) {
      throw new Error('Missing inputs');
    }
    const message = `I confirm ownership of the CLORE address ${cloreAddress}
and link it to the EVM address ${evmAddress}.`;
    const enc = new TextEncoder();
    const msgBytes = enc.encode(message);
    const prefixBytes = enc.encode(MESSAGE_PREFIX);
    const payload = new Uint8Array([
      ...prefixBytes,
      msgBytes.length,
      ...msgBytes,
    ]);
    const msgHash = dbg('msgHash', u8(doubleSha256(payload)));
    const input = privateKeyInput.trim();
    const hex =
      input.startsWith('0x') || input.length === 64
        ? input.replace(/^0x/, '')
        : wifToHex(input);
    const privKeyBytes = dbg('privKeyBytes', u8(hexToBytes2(hex)));
    const extraEntropy = crypto.getRandomValues(new Uint8Array(32));
    const signature = await sign(msgHash, privKeyBytes, {
      der: false,
      prehash: false,
      extraEntropy,
    });
    return {
      message,
      signature: toBase64(signature),
    };
  };
  console.log('\u2705 signCloreMessage ready');
})();
/*! Bundled license information:

@noble/secp256k1/index.js:
  (*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)

@noble/hashes/esm/utils.js:
@noble/hashes/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
