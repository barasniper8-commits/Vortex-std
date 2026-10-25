export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const GITHUB_PAT = process.env.GITHUB_PAT;
    const GITHUB_OWNER = process.env.GITHUB_OWNER; // barasniper8-commits
    const GITHUB_REPO = process.env.GITHUB_REPO;   // Vortex-std
    const DB_FILE = "members-db.json";

    const apiUrl = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${DB_FILE}`;

    try {
        if (req.method === 'GET') {
            const response = await fetch(apiUrl, {
                headers: {
                    'Authorization': `Bearer ${GITHUB_PAT}`,
                    'Accept': 'application/vnd.github+json'
                }
            });

            if (!response.ok) {
                return res.status(200).json({ users: [], sha: null });
            }

            const data = await response.json();
            const jsonString = decodeURIComponent(escape(atob(data.content)));
            return res.status(200).json({ users: JSON.parse(jsonString), sha: data.sha });
        }

        if (req.method === 'POST') {
            const { action, username, password, memberId, amount, rdpCost } = req.body;

            const currentRes = await fetch(apiUrl, {
                headers: {
                    'Authorization': `Bearer ${GITHUB_PAT}`,
                    'Accept': 'application/vnd.github+json'
                }
            });

            let users = [];
            let sha = null;

            if (currentRes.ok) {
                const currentData = await currentRes.json();
                sha = currentData.sha;
                users = JSON.parse(decodeURIComponent(escape(atob(currentData.content))));
            }

            if (action === 'register') {
                if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
                    return res.status(400).json({ success: false, message: 'Username sudah digunakan' });
                }

                const newMember = {
                    username,
                    password,
                    memberId: 'VORTEX-' + Math.floor(10000 + Math.random() * 90000),
                    balance: 0,
                    role: 'user'
                };

                users.push(newMember);

                const saveRes = await saveToGitHub(apiUrl, GITHUB_PAT, users, sha, `Register user: ${username}`);
                if (saveRes) {
                    return res.status(200).json({ success: true, user: newMember });
                } else {
                    return res.status(500).json({ success: false, message: 'Gagal menyimpan ke database' });
                }
            }

            if (action === 'topup') {
                const userIndex = users.findIndex(u => u.memberId.toLowerCase() === memberId.toLowerCase());
                if (userIndex === -1) {
                    return res.status(404).json({ success: false, message: 'ID Member tidak ditemukan' });
                }

                users[userIndex].balance += parseInt(amount);

                const saveRes = await saveToGitHub(apiUrl, GITHUB_PAT, users, sha, `Top-up ${amount} to ${memberId}`);
                if (saveRes) {
                    return res.status(200).json({ success: true, users });
                } else {
                    return res.status(500).json({ success: false, message: 'Gagal memperbarui saldo' });
                }
            }

            if (action === 'deduct') {
                const userIndex = users.findIndex(u => u.username === username);
                if (userIndex === -1 || users[userIndex].balance < rdpCost) {
                    return res.status(400).json({ success: false, message: 'Saldo tidak mencukupi' });
                }

                users[userIndex].balance -= rdpCost;

                const saveRes = await saveToGitHub(apiUrl, GITHUB_PAT, users, sha, `Deduct balance for RDP: ${username}`);
                if (saveRes) {
                    return res.status(200).json({ success: true, balance: users[userIndex].balance });
                } else {
                    return res.status(500).json({ success: false, message: 'Gagal memotong saldo' });
                }
            }
        }

        return res.status(405).json({ message: 'Method not allowed' });

    } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
    }
}

async function saveToGitHub(apiUrl, pat, users, sha, message) {
    const contentEncoded = btoa(unescape(encodeURIComponent(JSON.stringify(users, null, 2))));
    const bodyData = {
        message: message,
        content: contentEncoded,
        branch: "main"
    };
    if (sha) bodyData.sha = sha;

    const response = await fetch(apiUrl, {
        method: 'PUT',
        headers: {
            'Authorization': `Bearer ${pat}`,
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(bodyData)
    });

    return response.ok;
}
