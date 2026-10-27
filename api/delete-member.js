import crypto from "node:crypto";

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method tidak didukung."
    });
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

  const dbUrl = `https://api.github.com/repos/${OWNER}/${REPO}/contents/members-db.json`;

  function safeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string") return false;
    const x = Buffer.from(a);
    const y = Buffer.from(b);
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  }

  function verifyAdmin(req) {
    if (!ADMIN_USER || !ADMIN_PASS) return false;
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) return false;

    const token = auth.slice(7);
    const parts = token.split(".");
    if (parts.length !== 2) return false;

    const [payload, signature] = parts;
    const sessionSecret = crypto
      .createHash("sha256")
      .update(`${ADMIN_PASS}:${PAT}:VORTEX_ADMIN_SESSION`)
      .digest();

    const expected = crypto
      .createHmac("sha256", sessionSecret)
      .update(payload)
      .digest("base64url");

    if (!safeEqual(signature, expected)) return false;

    try {
      const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      return data.username === ADMIN_USER && Number.isFinite(data.exp) && data.exp > Date.now();
    } catch {
      return false;
    }
  }

  if (!verifyAdmin(req)) {
    return res.status(401).json({
      success: false,
      message: "Login admin diperlukan untuk menghapus member."
    });
  }

  let bodyData = req.body;
  if (typeof bodyData === "string") {
    try { bodyData = JSON.parse(bodyData); } catch { bodyData = {}; }
  }
  bodyData = bodyData || {};

  const { memberId } = bodyData;

  if (typeof memberId !== "string" || !memberId.trim()) {
    return res.status(400).json({
      success: false,
      message: "Member ID tidak valid."
    });
  }

  try {
    const response = await fetch(dbUrl, { headers });
    if (!response.ok) {
      throw new Error("Gagal membaca database GitHub.");
    }

    const file = await response.json();
    const content = Buffer.from(file.content.replace(/\s/g, ""), "base64").toString("utf8");
    const users = JSON.parse(content);

    const index = users.findIndex(
      (u) => String(u.memberId).toLowerCase() === memberId.trim().toLowerCase()
    );

    if (index === -1) {
      return res.status(404).json({
        success: false,
        message: "Member tidak ditemukan."
      });
    }

    const deletedUser = users.splice(index, 1)[0];

    const putResponse = await fetch(dbUrl, {
      method: "PUT",
      headers,
      body: JSON.stringify({
        message: `Admin menghapus member ${deletedUser.memberId} (${deletedUser.username})`,
        content: Buffer.from(JSON.stringify(users, null, 2)).toString("base64"),
        sha: file.sha
      })
    });

    if (!putResponse.ok) {
      throw new Error("Gagal menyimpan database GitHub.");
    }

    return res.status(200).json({
      success: true,
      message: "Member berhasil dihapus."
    });
  } catch (error) {
    console.error("Delete API error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Terjadi kesalahan pada server: " + error.message
    });
  }
}
