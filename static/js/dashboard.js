let chartInstance = null;

function alertBadge(text) {
    if (text.includes("Brute Force") || text.includes("DDoS"))
        return `<span class="badge red">${text}</span>`;
    if (text.includes("Suspicious") || text.includes("Reconnaissance") ||
        text.includes("Combined")   || text.includes("Scan"))
        return `<span class="badge yellow">${text}</span>`;
    return `<span class="badge green">${text}</span>`;
}

async function loadAlerts() {
    const res  = await fetch("/api/alerts");
    const data = await res.json();

    document.getElementById("total-alerts").textContent = data.length;
    const uniqueIPs = new Set(data.map(a => a.ip));
    document.getElementById("unique-ips").textContent = uniqueIPs.size;
    if (data.length > 0)
        document.getElementById("last-alert").textContent = data[0].alert;

    const count = {};
    data.forEach(a => { count[a.ip] = (count[a.ip] || 0) + 1; });

    if (chartInstance) chartInstance.destroy();
    chartInstance = new Chart(document.getElementById("chart"), {
        type: "bar",
        data: {
            labels: Object.keys(count),
            datasets: [{ label: "Ataques por IP", data: Object.values(count), backgroundColor: "#f87171", borderRadius: 6 }]
        },
        options: {
            plugins: { legend: { labels: { color: "#94a3b8" } } },
            scales: {
                x: { ticks: { color: "#64748b" }, grid: { color: "#1e293b" } },
                y: { ticks: { color: "#64748b" }, grid: { color: "#1e293b" } }
            }
        }
    });

    const tbody = document.getElementById("alerts-table");
    tbody.innerHTML = "";
    data.forEach(a => {
        tbody.innerHTML += `
        <tr>
            <td>${a.id}</td>
            <td>${alertBadge(a.alert)}</td>
            <td style="color:#f87171; font-family:monospace">${a.ip}</td>
            <td style="color:#64748b; font-size:12px">${a.details || "—"}</td>
            <td style="color:#475569; font-size:12px">${a.timestamp}</td>
        </tr>`;
    });

    document.getElementById("last-update").textContent =
        "Última atualização: " + new Date().toLocaleTimeString();
}

async function loadBlocked() {
    const res  = await fetch("/api/blocked");
    const data = await res.json();
    document.getElementById("blocked-count").textContent = data.length;
    const tbody = document.getElementById("blocked-table");
    if (data.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" class="empty">Nenhum IP bloqueado</td></tr>`;
        return;
    }
    tbody.innerHTML = "";
    data.forEach(ip => {
        tbody.innerHTML += `
        <tr>
            <td style="font-family:monospace; color:#f87171">${ip}</td>
            <td><span class="badge red">BLOQUEADO</span></td>
            <td><button class="btn-unblock" onclick="unblock('${ip}')">Desbloquear</button></td>
        </tr>`;
    });
}

// NOVO: carrega tentativas de login falhas
async function loadLoginFailures() {
    const res  = await fetch("/api/login-failures");
    const data = await res.json();

    document.getElementById("failed-logins").textContent = data.length;

    const tbody = document.getElementById("failures-table");
    if (data.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty">Nenhuma tentativa falha registrada</td></tr>`;
        return;
    }

    // Conta falhas acumuladas por (username + ip) para o badge
    const countMap = {};
    data.forEach(r => {
        const key = r.username + "|" + r.ip;
        countMap[key] = (countMap[key] || 0) + 1;
    });

    tbody.innerHTML = "";
    data.forEach(r => {
        const key   = r.username + "|" + r.ip;
        const count = countMap[key];
        const badge = count >= 5
            ? `<span class="badge red">⛔ BLOQUEADO (${count}x)</span>`
            : `<span class="badge yellow">⚠️ Tentativa (${count}x)</span>`;
        tbody.innerHTML += `
        <tr>
            <td>${r.id}</td>
            <td style="color:#fbbf24; font-weight:600">${r.username}</td>
            <td style="color:#f87171; font-family:monospace">${r.ip}</td>
            <td style="color:#475569; font-size:12px">${r.timestamp}</td>
            <td>${badge}</td>
        </tr>`;
    });
}

async function unblock(ip) {
    if (!confirm("Desbloquear " + ip + "?")) return;
    await fetch("/api/unblock/" + ip, { method: "POST" });
    loadBlocked();
}

let secondsLeft = 30;

function startCountdown() {
    secondsLeft = 30;
    const el = document.getElementById("countdown");
    el.textContent = `Próxima atualização em ${secondsLeft}s`;
    const timer = setInterval(() => {
        secondsLeft--;
        el.textContent = `Próxima atualização em ${secondsLeft}s`;
        if (secondsLeft <= 0) clearInterval(timer);
    }, 1000);
}

function refresh() {
    loadAlerts();
    loadBlocked();
    loadLoginFailures();
    startCountdown();
}

setInterval(refresh, 30000);


refresh()
