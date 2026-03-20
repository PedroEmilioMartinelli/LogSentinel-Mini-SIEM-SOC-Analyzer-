async function simular(tipo, inputId, resultId) {
    const ip  = document.getElementById(inputId).value.trim() || null;
    const res = document.getElementById(resultId);
    res.className    = "resultado";
    res.textContent  = "Simulando...";

    try {
        const r    = await fetch(`/api/simulate/${tipo}`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ ip })
        });
        const data = await r.json();
        res.textContent = `✓ ${data.alerts_generated} alertas gerados para IP ${data.ip}`;
    } catch (e) {
        res.className   = "resultado erro";
        res.textContent = "Erro ao conectar com o servidor.";
    }
}
