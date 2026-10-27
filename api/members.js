import crypto from "node:crypto";
import { createClient } from "redis";

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

    if (req.method !== "POST") {
      return res.status(405).json({ success: false, message: "Method tidak didukung." });
    }

    const { action, username, password, memberId, amount, rdpCost, tailscaleKey } = bodyData;

    // 1. REGISTER
    if (action === "register") {
      if (!username || !password || username.trim().length < 3 || password.length < 4) {
        return res.status(400).json({ success: false, message: "Username min 3 karakter, password min 4 karakter." });
      }
      const users = await getUsers();
      if (users.some((u) => String(u.username).toLowerCase() === username.trim().toLowerCase())) {
        return res.status(409).json({ success: false, message: "Username sudah digunakan." });
      }
      const newUser = {
        username: username.trim(),
        password: hashPassword(password),
        memberId: "VORTEX-" + crypto.randomInt(10000, 100000),
        balance: 0
      };
      users.push(newUser);
      await saveUsers(users);
      return res.status(201).json({ success: true, user: { username: newUser.username, memberId: newUser.memberId, balance: 0 } });
    }

    // 2. LOGIN
    if (action === "login") {
      const users = await getUsers();
      const user = users.find((u) =>
        (String(u.username).toLowerCase() === username.toLowerCase() || String(u.memberId).toLowerCase() === username.toLowerCase()) &&
        verifyPassword(password, u.password)
      );
      if (!user) return res.status(401).json({ success: false, message: "Username atau password salah." });
      return res.status(200).json({ success: true, user: { username: user.username, memberId: user.memberId, balance: Number(user.balance) || 0 } });
    }

    // 3. DEDUCT (Potong Saldo RDP)
    if (action === "deduct") {
      const cost = Number(rdpCost) || 100;
      const users = await getUsers();
      const user = users.find((u) => String(u.username).toLowerCase() === username?.trim().toLowerCase());
      if (!user) return res.status(404).json({ success: false, message: "User tidak ditemukan." });

      const currentBalance = Number(user.balance) || 0;
      if (currentBalance < cost) {
        return res.status(400).json({ success: false, message: "Saldo tidak mencukupi." });
      }

      user.balance = currentBalance - cost;
      await saveUsers(users);
      return res.status(200).json({ success: true, balance: user.balance });
    }

    // 4. TRIGGER RDP
    if (action === "trigger_rdp") {
      if (!tailscaleKey || !tailscaleKey.trim()) {
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
        body: JSON.stringify({ ref: "main", inputs: { tailscale_key: tailscaleKey.trim() } })
      });

      if (response.status !== 204) return res.status(502).json({ success: false, message: "Gagal memicu workflow RDP." });
      return res.status(200).json({ success: true, message: "Workflow RDP berhasil dipicu." });
    }

    return res.status(400).json({ success: false, message: `Action tidak dikenal: [${action}]` });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Server Error: " + error.message });
  }
}
