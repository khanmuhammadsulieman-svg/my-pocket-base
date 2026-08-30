/// <reference path="../pb_data/types.d.ts" />

// Volzix payment gateway — server-side HMAC-SHA256 signing + CORS bypass.

const K256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function strToBytes(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c < 0x80) {
      bytes.push(c);
    } else if (c < 0x800) {
      bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else {
      bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return bytes;
}

function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

function rotr(n, x) {
  return (x >>> n) | (x << (32 - n));
}

function sha256Bytes(bytes) {
  const H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];

  const l = bytes.length;
  const padded = bytes.slice();
  padded.push(0x80);
  while (padded.length % 64 !== 56) padded.push(0);
  const bitLen = l * 8;
  for (let i = 0; i < 4; i++) padded.push(0);
  padded.push((bitLen >>> 24) & 0xff, (bitLen >>> 16) & 0xff, (bitLen >>> 8) & 0xff, bitLen & 0xff);

  for (let off = 0; off < padded.length; off += 64) {
    const w = new Array(64);
    for (let i = 0; i < 16; i++) {
      w[i] =
        ((padded[off + i * 4] << 24) |
          (padded[off + i * 4 + 1] << 16) |
          (padded[off + i * 4 + 2] << 8) |
          padded[off + i * 4 + 3]) >>>
        0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, w[i - 15]) ^ rotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
      const s1 = rotr(17, w[i - 2]) ^ rotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }

    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }

  let hex = "";
  for (let i = 0; i < 8; i++) hex += H[i].toString(16).padStart(8, "0");
  return hex;
}

function hmacSha256Hex(keyStr, msgStr) {
  const blockSize = 64;
  let keyBytes = strToBytes(keyStr);
  if (keyBytes.length > blockSize) {
    keyBytes = hexToBytes(sha256Bytes(keyBytes));
  }
  while (keyBytes.length < blockSize) keyBytes.push(0);

  const ipad = [];
  const opad = [];
  for (let i = 0; i < blockSize; i++) {
    ipad.push(keyBytes[i] ^ 0x36);
    opad.push(keyBytes[i] ^ 0x5c);
  }

  const innerHex = sha256Bytes(ipad.concat(strToBytes(msgStr)));
  return sha256Bytes(opad.concat(hexToBytes(innerHex)));
}

// ─── Volzix config ────────────────────────────────────────────────────────────
const VOLZIX_BASE_URL = "https://volzix.com";
const MERCHANT_MID = $os.getenv("VOLZIX_MERCHANT_MID") || "VLX63755";
const MERCHANT_API_KEY = $os.getenv("VOLZIX_API_KEY") || "5ec79267eff39bfe9006389b50370ff058da580c477a9fc4dac3f9dad2219604";
const RETURN_URL = "https://factoryoutletshoes.store/checkout/success";

routerAdd("POST", "/api/create-volzix-payment", (e) => {
  const body = e.requestInfo().body || {};

  // FIX 1: Pass the exact integer amount to prevent signature mismatch
  const amount = Number(body.amount || 0);
  const email = String(body.email || "");
  const webId = String(body.web_id || "factory_outlet_web");
  const timestamp = Math.floor(Date.now() / 1000);

  if (!amount || !email || !webId) {
    return e.json(400, { error: "Missing required fields (amount, email, web_id)." });
  }

  const signString = `${MERCHANT_MID}|${amount}|PKR|${webId}|${email}|${timestamp}`;
  const signature = hmacSha256Hex(MERCHANT_API_KEY, signString);

  let res;
  try {
    res = $http.send({
      url: `${VOLZIX_BASE_URL}/auth/`,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify({
        merchant_mid: MERCHANT_MID,
        amount: amount,
        currency: "PKR",
        payer_email: email,
        web_id: webId,
        return_url: RETURN_URL, // FIX 2: Mapped exactly to Volzix's expected key
        timestamp: timestamp,
        signature: signature,
      }),
    });
  } catch (err) {
    $app.logger().error("volzix request failed", "err", String(err));
    return e.json(502, { error: "Unable to reach the Volzix gateway." });
  }

  const data = res.json || {};

  if (![200, 201].includes(res.statusCode) || !data.payment_url) {
    return e.json(400, {
      error: data.error || data.message || `Volzix rejected the request.`,
      details: data
    });
  }

  return e.json(200, { payment_url: data.payment_url, flow_id: data.flow_id });
});
