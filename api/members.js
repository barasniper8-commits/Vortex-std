export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const GITHUB_PAT = process.env.GITHUB_PAT;
    const GITHUB_OWNER = process.env.GITHUB_OWNER || 'barasniper8-commits';
    const GITHUB_REPO = process.env.GITHUB_REPO || 'Vortex-std';

    // 1. MEMBACA DATA (GET) - Sembunyikan semua data user dari publik
    if (req.method === 'GET') {
        const type = req.query.type || 'members';
        
        // Jika yang diminta adalah data RDP, boleh ditampilkan (karena untuk member yang sedang pakai)
        if (type === 'rdp') {
            const fileUrl = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/rdp-info.json`;
            try {
                const response = await fetch(fileUrl, {
                    headers: { 'Authorization': `Bearer ${GITHUB_PAT}`, 'Accept': 'application/vnd.github+json' }
                });
                if (!response.ok) return res.status(200).json({ data: null });
                const data = await response.json();
                const content = Buffer.from(data.content, 'base64').toString('utf-8');
                return res.status(200).json({ data: JSON.parse(content) });
            } catch (error) {
                return res.status(500).json({ error: error.message });
            }
        }

        // Untuk endpoint umum member, JANGAN tampilkan data apa pun ke publik
        return res.status(200).json({ status: "secured", message: "Access restricted" });
    }

    // 2. MEMPROSES AKSI (POST) - Semua proses dilakukan secara aman di server
    if (req.method === 'POST') {
        const { action, username, password, memberId, amount, rdpCost, tailscaleKey } = req.body;

        if (action === 'trigger_rdp') {
            if (!tailscaleKey) return res.status(400).json({ success: false, message: 'Tailscale Key diperlukan' });

            const dispatchUrl = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/workflows/main.yml/dispatches`;
            try {
                const response = await fetch(dispatchUrl, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${GITHUB_PAT}`,
                        'Accept': 'application/vnd.github+json',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ ref: 'main', inputs: { tailscale_key: tailscaleKey } })
                });

                if (response.status === 204) {
                    return res.status(200).json({ success: true, message: 'Workflow berhasil dipicu' });
                } else {
                    const errData = await response.json();
                    return res.status(400).json({ success: false, message: errData.message || 'Gagal memicu workflow' });
                }
            } catch (error) {
                return res.status(500).json({ success: false, message: error.message });
            }
        }

        const dbUrl = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/members-db.json`;

        try {
            let currentUsers = [];
            let sha = null;

            const getRes = await fetch(dbUrl, {
                headers: { 'Authorization': `Bearer ${GITHUB_PAT}`, 'Accept': 'application/vnd.github+json' }
            });

            if (getRes.ok) {
                const fileData = await getRes.json();
                sha = fileData.sha;
                currentUsers = JSON.parse(Buffer.from(fileData.content, 'base64').toString('utf-8'));
            }

            // AKSI: LOGIN AMAN DI SERVER
            if (action === 'login') {
                const user = currentUsers.find(u => 
                    (u.username.toLowerCase() === username.toLowerCase() || u.memberId.toLowerCase() === username.toLowerCase()) && 
                    u.password === password
                );

                if (!user) {
                    return res.status(400).json({ success: false, message: 'Username atau password salah' });
                }

                return res.status(200).json({ 
                    success: true, 
                    user: { username: user.username, memberId: user.memberId, balance: user.balance } 
                });
            }

            // AKSI: REGISTER
            if (action === 'register') {
                if (currentUsers.some(u => u.username.toLowerCase() === username.toLowerCase())) {
                    return res.status(400).json({ success: false, message: 'Username sudah digunakan' });
                }

                const newId = 'VORTEX-' + Math.floor(10000 + Math.random() * 90000);
                const newUser = { username, password, memberId: newId, balance: 0 };
                currentUsers.push(newUser);

                await updateGithubDb(dbUrl, currentUsers, sha, GITHUB_PAT, `Register: ${username}`);
                return res.status(200).json({ success: true, user: newUser });
            }

            // AKSI: DEDUCT (POTONG SALDO)
            if (action === 'deduct') {
                const idx = currentUsers.findIndex(u => u.username === username);
                if (idx === -1) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });

                if (currentUsers[idx].balance < rdpCost) {
                    return res.status(400).json({ success: false, message: 'Saldo tidak mencukupi' });
                }

                currentUsers[idx].balance -= rdpCost;
                await updateGithubDb(dbUrl, currentUsers, sha, GITHUB_PAT, `Deduct: ${username}`);
                return res.status(200).json({ success: true, balance: currentUsers[idx].balance });
            }

            // AKSI: TOPUP (ADMIN)
            if (action === 'topup') {
                const idx = currentUsers.findIndex(u => u.memberId.toLowerCase() === memberId.toLowerCase());
                if (idx === -1) return res.status(404).json({ success: false, message: 'ID Member tidak ditemukan' });

                currentUsers[idx].balance += amount;
                await updateGithubDb(dbUrl, currentUsers, sha, GITHUB_PAT, `Topup: ${memberId}`);
                return res.status(200).json({ success: true, balance: currentUsers[idx].balance });
            }

            return res.status(400).json({ success: false, message: 'Action tidak valid' });

        } catch (error) {
            return res.status(500).json({ success: false, message: error.message });
        }
    }

    return res.status(405).end();
}

async function updateGithubDb(url, data, sha, pat, commitMsg) {
    const updatedContent = Buffer.from(JSON.stringify(data, null, 2)).toString('base64');
    const body = { message: commitMsg, content: updatedContent };
    if (sha) body.sha = sha;

    await fetch(url, {
        method: 'PUT',
        headers: {
            'Authorization': `Bearer ${pat}`,
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
    });
}
