import crypto from "node:crypto";
import { createClient } from "redis";

// Inisialisasi koneksi Redis Vercel KV
const client = createClient({
  url: process.env.REDIS_URL
});

async function getRedisClient() {
  if (!client.isOpen) {
    await client.connect();
  }
  return client;
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  const ADMIN_USER = process.env.ADMIN_USERNAME;
  const ADMIN_PASS = process.env.ADMIN_PASSWORD;
  const PAT = process.env.GITHUB_PAT;
  const OWNER = process.env.GITHUB_OWNER || "barasniper8-commits";
  const REPO = process.env.GITHUB_REPO || "Vortex-std";

  function safeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string") return false;
    const x = Buffer.from(a);
    const y = Buffer.from(b);
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  }

  function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.scryptSync(password, salt, 64).toString("hex");
    return `${salt}:${hash}`;
  }

  function verifyPassword(password, stored) {
    if (!stored) return false;
    if (!stored.includes(":")) return password === stored;
    try {
      const [salt, key] = stored.split(":");
      const hash = crypto.scryptSync(password, salt, 64).toString("hex");
      return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(key, "hex"));
    } catch {
      return false;
    }
  }

  function sessionSecret() {
    return crypto.createHash("sha256").update(`${ADMIN_PASS}:${PAT || 'vortex'}:VORTEX_ADMIN_SESSION`).digest();
  }

  function createToken(username) {
    const payload = Buffer.from(JSON.stringify({
      username,
      exp: Date.now() + 8 * 60 * 60 * 1000
    })).toString("base64url");

    const signature = crypto.createHmac("sha256", sessionSecret()).update(payload).digest("base64url");
    return `${payload}.${signature}`;
  }

  function verifyAdmin(req) {
    if (!ADMIN_USER || !ADMIN_PASS) return false;
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) return false;
    const token = auth.slice(7);
    const parts = token.split(".");
    if (parts.length !== 2) return false;
    const [payload, signature] = parts;
    const expected = crypto.createHmac("sha256", sessionSecret()).update(payload).digest("base64url");
    if (!safeEqual(signature, expected)) return false;
    try {
      const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      return data.username === ADMIN_USER && Number.isFinite(data.exp) && data.exp > Date.now();
    } catch {
      return false;
    }
  }

  // Fungsi ambil daftar member dari Redis
  async function getUsers() {
    const redis = await getRedisClient();
    const data = await redis.get("vortex_members");
    if (!data) return [];
    try {
      const parsed = JSON.parse(data);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  // Fungsi simpan daftar member ke Redis
  async function saveUsers(users) {
    const redis = await getRedisClient();
    await redis.set("vortex_members", JSON.stringify(users));
  }

  try {
    let bodyData = req.body;
    if (typeof bodyData === "string") {
      try { bodyData = JSON.parse(bodyData); } catch { bodyData = {}; }
    }
    bodyData = bodyData || {};

    // Admin login
    if (req.method === "POST" && bodyData.action === "admin_login") {
      const { username, password } = bodyData;
      if (!safeEqual(username, ADMIN_USER) || !safeEqual(password, ADMIN_PASS)) {
        return res.status(401).json({ success: false, message: "Username atau password admin salah." });
      }
      return res.status(200).json({ success: true, token: createToken(ADMIN_USER), admin: { username: ADMIN_USER } });
    }

    // Get members (Admin only)
    if (req.method === "GET") {
      if (!verifyAdmin(req)) {
        return res.status(401).json({ success: false, message: "Akses admin diperlukan." });
      }
      const users = await getUsers();
      const safeUsers = users.map((u) => ({
        username: u.username,
        memberId: u.memberId,
        balance: Number(u.balance) || 0
      }));
      return res.status(200).json({ success: true, users: safeUsers });
    }

    if (req.method !== "POST") {
      return res.status(405).json({ success: false, message: "Method tidak didukung." });
    }

    const { action, username, password, memberId, amount, tailscaleKey } = bodyData;

    // Register member baru
    if (action === "register") {
      if (typeof username !== "string" || typeof password !== "string" || username.trim().length < 3 || password.length < 6) {
        return res.status(400).json({ success: false, message: "Username min 3 karakter dan password min 6 karakter." });
      }

      const users = await getUsers();
      if (users.some((u) => String(u.username).toLowerCase() === username.trim().toLowerCase())) {
        return res.status(409).json({ success: false, message: "Username sudah digunakan." });
      }

      const newId = "VORTEX-" + crypto.randomInt(10000, 100000);
      const newUser = {
        username: username.trim(),
        password: hashPassword(password),
        memberId: newId,
        balance: 0
      };

      users.push(newUser);
      await saveUsers(users);

      return res.status(201).json({
        success: true,
        user: { username: newUser.username, memberId: newUser.memberId, balance: newUser.balance }
      });
    }

    // Login member
    if (action === "login") {
      const users = await getUsers();
      const user = users.find((u) =>
        (String(u.username).toLowerCase() === username.toLowerCase() ||
         String(u.memberId).toLowerCase() === username.toLowerCase()) &&
        verifyPassword(password, u.password)
      );

      if (!user) {
        return res.status(401).json({ success: false, message: "Username atau password member salah." });
      }

      return res.status(200).json({
        success: true,
        user: { username: user.username, memberId: user.memberId, balance: Number(user.balance) || 0 }
      });
    }

    // Top-up member
    if (action === "topup") {
      if (!verifyAdmin(req)) {
        return res.status(401).json({ success: false, message: "Login admin diperlukan." });
      }
      const value = Number(amount);
      const users = await getUsers();
      const user = users.find((u) => String(u.memberId).toLowerCase() === memberId?.trim().toLowerCase());

      if (!user) {
        return res.status(404).json({ success: false, message: "Member tidak ditemukan." });
      }

      user.balance = (Number(user.balance) || 0) + value;
      await saveUsers(users);

      return res.status(200).json({ success: true, message: "Top-up berhasil.", balance: user.balance });
    }

    // Trigger RDP workflow
    if (action === "trigger_rdp") {
      if (typeof tailscaleKey !== "string" || !tailscaleKey.trim()) {
        return res.status(400).json({ success: false, message: "Tailscale Key diperlukan." });
      }

      const dispatchUrl = `https://api.github.com/repos/${OWNER}/${REPO}/actions/workflows/main.yml/dispatches`;
      const response = await fetch(dispatchUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${PAT}`,
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
          "X-GitHub-Api-Version": "2022-11-28"
        },
        body: JSON.stringify({
          ref: "main",
          inputs: { tailscale_key: tailscaleKey.trim() }
        })
      });

      if (response.status !== 204) {
        return res.status(502).json({ success: false, message: "Gagal menjalankan workflow RDP." });
      }

      return res.status(200).json({ success: true, message: "Workflow RDP berhasil dipicu." });
    }

    return res.status(400).json({ success: false, message: `Action tidak dikenal: [${action}]` });
  } catch (error) {
    console.error("Redis KV Error:", error.message);
    return res.status(500).json({ success: false, message: "Terjadi kesalahan pada server: " + error.message });
  }
}
