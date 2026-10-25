
import crypto from "node:crypto";

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  const PAT = process.env.GITHUB_PAT;
  const OWNER = process.env.GITHUB_OWNER || "barasniper8-commits";
  const REPO = process.env.GITHUB_REPO || "Vortex-std";
  const ADMIN_USER = process.env.ADMIN_USERNAME;
  const ADMIN_PASS = process.env.ADMIN_PASSWORD;

  if (!PAT) {
    return res.status(500).json({
      success: false,
      message: "GITHUB_PAT belum diatur di Vercel."
    });
  }

  const headers = {
    Authorization: `Bearer ${PAT}`,
    Accept: "application/vnd.github+json",
    "Content-Type": "application/json",
    "X-GitHub-Api-Version": "2022-11-28"
  };

  const dbUrl =
    `https://api.github.com/repos/${OWNER}/${REPO}/contents/members-db.json`;

  function safeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string") {
      return false;
    }

    const x = Buffer.from(a);
    const y = Buffer.from(b);

    return x.length === y.length &&
      crypto.timingSafeEqual(x, y);
  }

  function sessionSecret() {
    return crypto
      .createHash("sha256")
      .update(`${ADMIN_PASS}:${PAT}:VORTEX_ADMIN_SESSION`)
      .digest();
  }

  function createToken(username) {
    const payload = Buffer.from(JSON.stringify({
      username,
      exp: Date.now() + 8 * 60 * 60 * 1000
    })).toString("base64url");

    const signature = crypto
      .createHmac("sha256", sessionSecret())
      .update(payload)
      .digest("base64url");

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

    const expected = crypto
      .createHmac("sha256", sessionSecret())
      .update(payload)
      .digest("base64url");

    if (!safeEqual(signature, expected)) return false;

    try {
      const data = JSON.parse(
        Buffer.from(payload, "base64url").toString("utf8")
      );

      return data.username === ADMIN_USER &&
        Number.isFinite(data.exp) &&
        data.exp > Date.now();
    } catch {
      return false;
    }
  }

  async function readDatabase() {
    const response = await fetch(dbUrl, { headers });

    if (response.status === 404) {
      return { users: [], sha: null };
    }

    if (!response.ok) {
      throw new Error("Gagal membaca database GitHub.");
    }

    const file = await response.json();
    const content = Buffer.from(
      file.content.replace(/\s/g, ""),
      "base64"
    ).toString("utf8");

    const parsed = JSON.parse(content);

    if (!Array.isArray(parsed)) {
      throw new Error("Format members-db.json tidak valid.");
    }

    return { users: parsed, sha: file.sha };
  }

  async function saveDatabase(users, sha, message) {
    const body = {
      message,
      content: Buffer.from(
        JSON.stringify(users, null, 2)
      ).toString("base64")
    };

    if (sha) body.sha = sha;

    const response = await fetch(dbUrl, {
      method: "PUT",
      headers,
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      throw new Error(
        "Gagal menyimpan database GitHub. Periksa izin PAT."
      );
    }
  }

  try {
    // Admin login: terpisah dari login member.
    if (req.method === "POST" &&
        req.body?.action === "admin_login") {
      if (!ADMIN_USER || !ADMIN_PASS) {
        return res.status(500).json({
          success: false,
          message: "ADMIN_USERNAME atau ADMIN_PASSWORD belum diatur."
        });
      }

      const { username, password } = req.body;

      if (
        !safeEqual(username, ADMIN_USER) ||
        !safeEqual(password, ADMIN_PASS)
      ) {
        return res.status(401).json({
          success: false,
          message: "Username atau password admin salah."
        });
      }

      return res.status(200).json({
        success: true,
        token: createToken(ADMIN_USER),
        admin: { username: ADMIN_USER }
      });
    }

    // Daftar member hanya boleh dibaca admin.
    if (req.method === "GET") {
      const type = req.query?.type || "members";

      if (type === "rdp") {
        const url =
          `https://api.github.com/repos/${OWNER}/${REPO}/contents/rdp-info.json`;

        const response = await fetch(url, { headers });

        if (!response.ok) {
          return res.status(502).json({
            success: false,
            message: "Gagal membaca informasi RDP."
          });
        }

        const file = await response.json();
        const info = JSON.parse(
          Buffer.from(
            file.content.replace(/\s/g, ""),
            "base64"
          ).toString("utf8")
        );

        return res.status(200).json({ data: info });
      }

      if (!verifyAdmin(req)) {
        return res.status(401).json({
          success: false,
          message: "Akses admin diperlukan."
        });
      }

      const { users } = await readDatabase();

      // Jangan pernah mengirim password member ke browser admin.
      const safeUsers = users.map((u) => ({
        username: u.username,
        memberId: u.memberId,
        balance: Number(u.balance) || 0
      }));

      return res.status(200).json({
        success: true,
        users: safeUsers
      });
    }

    if (req.method !== "POST") {
      return res.status(405).json({
        success: false,
        message: "Method tidak didukung."
      });
    }

    const {
      action,
      username,
      password,
      memberId,
      amount,
      rdpCost,
      tailscaleKey
    } = req.body || {};

    // Top-up hanya dapat dilakukan admin yang sudah login.
    if (action === "topup") {
      if (!verifyAdmin(req)) {
        return res.status(401).json({
          success: false,
          message: "Login admin diperlukan untuk top-up."
        });
      }

      const value = Number(amount);

      if (
        typeof memberId !== "string" ||
        !memberId.trim() ||
        !Number.isFinite(value) ||
        value <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "Member ID atau jumlah top-up tidak valid."
        });
      }

      const { users, sha } = await readDatabase();
      const user = users.find(
        (u) => String(u.memberId).toLowerCase() ===
          memberId.trim().toLowerCase()
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Member tidak ditemukan."
        });
      }

      user.balance = (Number(user.balance) || 0) + value;

      await saveDatabase(
        users,
        sha,
        `Admin top-up saldo member ${user.memberId}`
      );

      return res.status(200).json({
        success: true,
        message: "Top-up berhasil.",
        balance: user.balance
      });
    }

    // Jalankan workflow RDP; dipertahankan agar alur lama tetap bekerja.
    if (action === "trigger_rdp") {
      if (
        typeof tailscaleKey !== "string" ||
        !tailscaleKey.trim()
      ) {
        return res.status(400).json({
          success: false,
          message: "Tailscale Key diperlukan."
        });
      }

      const dispatchUrl =
        `https://api.github.com/repos/${OWNER}/${REPO}/actions/workflows/main.yml/dispatches`;

      const response = await fetch(dispatchUrl, {
        method: "POST",
        headers,
        body: JSON.stringify({
          ref: "main",
          inputs: { tailscale_key: tailscaleKey.trim() }
        })
      });

      if (response.status !== 204) {
        return res.status(502).json({
          success: false,
          message: "Gagal menjalankan workflow RDP."
        });
      }

      return res.status(200).json({
        success: true,
        message: "Workflow RDP berhasil dipicu."
      });
    }

    // Login member.
    if (action === "login") {
      if (
        typeof username !== "string" ||
        typeof password !== "string"
      ) {
        return res.status(400).json({
          success: false,
          message: "Username dan password diperlukan."
        });
      }

      const { users } = await readDatabase();
      const user = users.find((u) =>
        (
          String(u.username).toLowerCase() === username.toLowerCase() ||
          String(u.memberId).toLowerCase() === username.toLowerCase()
        ) && u.password === password
      );

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Username atau password member salah."
        });
      }

      return res.status(200).json({
        success: true,
        user: {
          username: user.username,
          memberId: user.memberId,
          balance: Number(user.balance) || 0
        }
      });
    }

    // Registrasi member.
    if (action === "register") {
      if (
        typeof username !== "string" ||
        typeof password !== "string" ||
        username.trim().length < 3 ||
        password.length < 6
      ) {
        return res.status(400).json({
          success: false,
          message: "Username minimal 3 karakter dan password minimal 6 karakter."
        });
      }

      const { users, sha } = await readDatabase();

      if (users.some(
        (u) => String(u.username).toLowerCase() ===
          username.trim().toLowerCase()
      )) {
        return res.status(409).json({
          success: false,
          message: "Username sudah digunakan."
        });
      }

      const newId = "VORTEX-" +
        crypto.randomInt(10000, 100000);

      const newUser = {
        username: username.trim(),
        password,
        memberId: newId,
        balance: 0
      };

      users.push(newUser);

      await saveDatabase(
        users,
        sha,
        `Register member ${newId}`
      );

      return res.status(201).json({
        success: true,
        user: {
          username: newUser.username,
          memberId: newUser.memberId,
          balance: newUser.balance
        }
      });
    }

    // Potong saldo sesuai alur lama.
    if (action === "deduct") {
      const cost = Number(rdpCost);

      if (
        typeof username !== "string" ||
        !Number.isFinite(cost) ||
        cost <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "Username atau biaya tidak valid."
        });
      }

      const { users, sha } = await readDatabase();
      const user = users.find(
        (u) => String(u.username).toLowerCase() ===
          username.toLowerCase()
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Member tidak ditemukan."
        });
      }

      const balance = Number(user.balance) || 0;

      if (balance < cost) {
        return res.status(400).json({
          success: false,
          message: "Saldo tidak mencukupi."
        });
      }

      user.balance = balance - cost;

      await saveDatabase(
        users,
        sha,
        `Potong saldo member ${user.memberId}`
      );

      return res.status(200).json({
        success: true,
        balance: user.balance
      });
    }

    return res.status(400).json({
      success: false,
      message: "Action tidak dikenal."
    });
  } catch (error) {
    console.error("Members API error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Terjadi kesalahan pada server. Periksa Vercel Logs."
    });
  }
}
