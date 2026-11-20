import crypto from "node:crypto";
import { createClient } from "redis";

const client = createClient({
  url: process.env.REDIS_URL
});

client.on("error", (err) => {
  console.error("Redis Client Error:", err);
});

async function getRedisClient() {
  if (!process.env.REDIS_URL) {
    throw new Error("REDIS_URL belum dikonfigurasi.");
  }
  if (!client.isOpen) {
    await client.connect();
  }
  return client;
}

const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || "").trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ADMIN_SECRET = process.env.ADMIN_SECRET || process.env.JWT_SECRET || "";

function createAdminToken(username) {
  const secret = ADMIN_SECRET || "vortex-default-secret-change-env";
  const payload = Buffer.from(
    JSON.stringify({
      role: "admin",
      user: username,
      exp: Date.now() + 1000 * 60 * 60 * 12
    })
  ).toString("base64url");

  const sig = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  return `${payload}.${sig}`;
}

function verifyAdminToken(req) {
  const secret = ADMIN_SECRET || "vortex-default-secret-change-env";
  const authHeader = req.headers?.authorization || req.headers?.Authorization || "";
  if (!authHeader.startsWith("Bearer ")) return false;

  const token = authHeader.slice(7).trim();
  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [payload, sig] = parts;
  if (!payload || !sig) return false;

  const expectedSig = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return false;
  }

  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return parsed?.role === "admin" && typeof parsed?.exp === "number" && parsed.exp > Date.now();
  } catch {
    return false;
  }
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  const PAT = process.env.GITHUB_PAT;
  const OWNER = process.env.GITHUB_OWNER || "barasniper8-commits";
  const REPO = process.env.GITHUB_REPO || "Vortex-std";

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
    if (req.method === "GET") {
      // Ambil kredensial RDP terbaru dari rdp-info.json di GitHub
      if (req.query?.type === "rdp") {
        if (!PAT) {
          return res.status(500).json({ success: false, message: "GITHUB_PAT belum dikonfigurasi di server." });
        }

        const fileUrl = `https://api.github.com/repos/${OWNER}/${REPO}/contents/rdp-info.json?ref=main`;
        const ghRes = await fetch(fileUrl, {
          headers: {
            Authorization: `Bearer ${PAT}`,
            Accept: "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
          },
          cache: "no-store"
        });

        if (!ghRes.ok) {
          return res.status(404).json({ success: false, message: "rdp-info.json belum tersedia di repository." });
        }

        const ghFile = await ghRes.json();
        const decoded = Buffer.from(ghFile.content || "", "base64").toString("utf8");
        const rdpData = JSON.parse(decoded);

        return res.status(200).json({
          success: true,
          data: {
            ip: String(rdpData.ip || "").trim(),
            username: String(rdpData.username || "Administrator").trim(),
            password: String(rdpData.password || "").trim()
          }
        });
      }

      // Ambil daftar member untuk Vortex Admin PRO
      if (!verifyAdminToken(req)) {
        return res.status(401).json({ success: false, message: "Token admin tidak valid atau kedaluwarsa." });
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

    let bodyData = req.body;
    if (typeof bodyData === "string") {
      try {
        bodyData = JSON.parse(bodyData);
      } catch {
        bodyData = {};
      }
    }
    bodyData = bodyData || {};

    const { action, username, password, memberId, newPassword, amount, rdpCost, tailscaleKey } = bodyData;

    // 0. ADMIN LOGIN
    if (action === "admin_login") {
      const cleanUser = typeof username === "string" ? username.trim() : "";
      const rawPass = typeof password === "string" ? password : "";

      if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
        return res.status(500).json({
          success: false,
          message: "ADMIN_USERNAME atau ADMIN_PASSWORD belum dikonfigurasi di Vercel ENV."
        });
      }

      if (cleanUser !== ADMIN_USERNAME || rawPass !== ADMIN_PASSWORD) {
        return res.status(401).json({
          success: false,
          message: "Username atau password admin salah."
        });
      }

      const token = createAdminToken(cleanUser);
      return res.status(200).json({ success: true, token });
    }

    // 1. REGISTER
    if (action === "register") {
      const cleanUsername = typeof username === "string" ? username.trim() : "";
      if (!cleanUsername || typeof password !== "string" || cleanUsername.length < 3 || password.length < 4) {
        return res.status(400).json({ success: false, message: "Username min 3 karakter, password min 4 karakter." });
      }
      const users = await getUsers();
      if (users.some((u) => String(u.username).toLowerCase() === cleanUsername.toLowerCase())) {
        return res.status(409).json({ success: false, message: "Username sudah digunakan." });
      }
      const newUser = {
        username: cleanUsername,
        password: hashPassword(password),
        memberId: "VORTEX-" + crypto.randomInt(10000, 100000),
        balance: 0
      };
      users.push(newUser);
      await saveUsers(users);
      return res.status(201).json({
        success: true,
        user: { username: newUser.username, memberId: newUser.memberId, balance: 0 }
      });
    }

    // 2. LOGIN MEMBER
    if (action === "login") {
      const cleanLogin = typeof username === "string" ? username.trim().toLowerCase() : "";
      if (!cleanLogin || typeof password !== "string") {
        return res.status(400).json({ success: false, message: "Username/Member ID dan password wajib diisi." });
      }
      const users = await getUsers();
      const user = users.find((u) =>
        (String(u.username).toLowerCase() === cleanLogin || String(u.memberId).toLowerCase() === cleanLogin) &&
        verifyPassword(password, u.password)
      );
      if (!user) {
        return res.status(401).json({ success: false, message: "Username atau password salah." });
      }
      return res.status(200).json({
        success: true,
        user: { username: user.username, memberId: user.memberId, balance: Number(user.balance) || 0 }
      });
    }

    // 3. TOPUP SALDO (Khusus Admin)
    if (action === "topup") {
      if (!verifyAdminToken(req)) {
        return res.status(401).json({ success: false, message: "Akses admin tidak terotorisasi." });
      }

      const targetId = typeof memberId === "string" ? memberId.trim().toUpperCase() : "";
      const addAmount = Number(amount);
      if (!targetId || !Number.isFinite(addAmount) || addAmount <= 0) {
        return res.status(400).json({ success: false, message: "Member ID dan nominal topup tidak valid." });
      }

      const users = await getUsers();
      const user = users.find((u) => String(u.memberId).toUpperCase() === targetId);
      if (!user) {
        return res.status(404).json({ success: false, message: "Member ID tidak ditemukan." });
      }

      user.balance = (Number(user.balance) || 0) + addAmount;
      await saveUsers(users);
      return res.status(200).json({ success: true, balance: user.balance });
    }

    // 4. DEDUCT (Admin via memberId + amount, atau Member via username + rdpCost)
    if (action === "deduct") {
      const hasAdminHeader = Boolean(req.headers?.authorization || req.headers?.Authorization);

      if (hasAdminHeader && memberId) {
        if (!verifyAdminToken(req)) {
          return res.status(401).json({ success: false, message: "Akses admin tidak terotorisasi." });
        }

        const targetId = String(memberId).trim().toUpperCase();
        const cutAmount = Number(amount);
        if (!targetId || !Number.isFinite(cutAmount) || cutAmount <= 0) {
          return res.status(400).json({ success: false, message: "Member ID dan nominal potong saldo tidak valid." });
        }

        const users = await getUsers();
        const user = users.find((u) => String(u.memberId).toUpperCase() === targetId);
        if (!user) {
          return res.status(404).json({ success: false, message: "Member ID tidak ditemukan." });
        }

        const currentBalance = Number(user.balance) || 0;
        if (currentBalance < cutAmount) {
          return res.status(400).json({ success: false, message: "Saldo member tidak mencukupi untuk dipotong." });
        }

        user.balance = currentBalance - cutAmount;
        await saveUsers(users);
        return res.status(200).json({ success: true, balance: user.balance });
      }

      const cleanUsername = typeof username === "string" ? username.trim().toLowerCase() : "";
      const cost = Number(rdpCost) || 100;
      const users = await getUsers();
      const user = users.find((u) => String(u.username).toLowerCase() === cleanUsername);
      if (!user) {
        return res.status(404).json({ success: false, message: "User tidak ditemukan." });
      }

      const currentBalance = Number(user.balance) || 0;
      if (currentBalance < cost) {
        return res.status(400).json({ success: false, message: "Saldo tidak mencukupi." });
      }

      user.balance = currentBalance - cost;
      await saveUsers(users);
      return res.status(200).json({ success: true, balance: user.balance });
    }

    // 5. RESET PASSWORD MEMBER (Khusus Admin)
    if (action === "reset_password") {
      if (!verifyAdminToken(req)) {
        return res.status(401).json({ success: false, message: "Akses admin tidak terotorisasi." });
      }

      const targetId = typeof memberId === "string" ? memberId.trim().toUpperCase() : "";
      const rawNewPass = typeof newPassword === "string" ? newPassword : "";

      if (!targetId) {
        return res.status(400).json({ success: false, message: "Member ID diperlukan." });
      }
      if (rawNewPass.length < 4) {
        return res.status(400).json({ success: false, message: "Password baru minimal 4 karakter." });
      }

      const users = await getUsers();
      const user = users.find((u) => String(u.memberId).toUpperCase() === targetId);
      if (!user) {
        return res.status(404).json({ success: false, message: "Member tidak ditemukan." });
      }

      user.password = hashPassword(rawNewPass);
      await saveUsers(users);
      return res.status(200).json({
        success: true,
        message: `Password untuk ${user.username} (${user.memberId}) berhasil direset.`
      });
    }

    // 6. DELETE MEMBER (Khusus Admin)
    if (action === "delete") {
      if (!verifyAdminToken(req)) {
        return res.status(401).json({ success: false, message: "Akses admin tidak terotorisasi." });
      }

      const targetId = typeof memberId === "string" ? memberId.trim().toUpperCase() : "";
      if (!targetId) {
        return res.status(400).json({ success: false, message: "Member ID diperlukan." });
      }

      const users = await getUsers();
      const filtered = users.filter((u) => String(u.memberId).toUpperCase() !== targetId);
      if (filtered.length === users.length) {
        return res.status(404).json({ success: false, message: "Member tidak ditemukan." });
      }

      await saveUsers(filtered);
      return res.status(200).json({ success: true, message: "Member berhasil dihapus." });
    }

    // 7. TRIGGER RDP
    if (action === "trigger_rdp") {
      if (!tailscaleKey || typeof tailscaleKey !== "string" || !tailscaleKey.trim()) {
        return res.status(400).json({ success: false, message: "Tailscale Key diperlukan." });
      }
      if (!PAT) {
        return res.status(500).json({ success: false, message: "GITHUB_PAT belum dikonfigurasi di server." });
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
        let ghErrorText = "";
        try {
          ghErrorText = await response.text();
        } catch {
          ghErrorText = "";
        }
        return res.status(502).json({
          success: false,
          message: `Gagal memicu workflow RDP (GitHub HTTP ${response.status}).`,
          detail: ghErrorText || undefined
        });
      }

      return res.status(200).json({ success: true, message: "Workflow RDP berhasil dipicu." });
    }

    return res.status(400).json({ success: false, message: `Action tidak dikenal: [${action}]` });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server Error: " + (error?.message || "Unknown error")
    });
  }
}
