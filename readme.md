
```
██╗      ██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
██║     ██║   ██║██║  ███╗███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██║     ██║   ██║██║   ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████╗╚██████╔╝╚██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

███╗   ███╗██╗███╗   ██╗██╗    ███████╗██╗███████╗███╗   ███╗
████╗ ████║██║████╗  ██║██║    ██╔════╝██║██╔════╝████╗ ████║
██╔████╔██║██║██╔██╗ ██║██║    ███████╗██║█████╗  ██╔████╔██║
██║╚██╔╝██║██║██║╚██╗██║██║    ╚════██║██║██╔══╝  ██║╚██╔╝██║
██║ ╚═╝ ██║██║██║ ╚████║██║    ███████║██║███████╗██║ ╚═╝ ██║
╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝    ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝

███████╗ ██████╗  ██████╗ 
██╔════╝██╔════╝ ██╔════╝ 
███████╗██║  ███╗██║  ███╗
╚════██║██║   ██║██║   ██║
███████║╚██████╔╝╚██████╔╝
╚══════╝ ╚═════╝  ╚═════╝ 

 █████╗ ███╗   ██╗ █████╗ ██╗     ██╗   ██╗███████╗███████╗██████╗ 
██╔══██╗████╗  ██║██╔══██╗██║     ╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗
███████║██╔██╗ ██║███████║██║      ╚████╔╝ █████╗  █████╗  ██████╔╝
██╔══██║██║╚██╗██║██╔══██║██║       ╚██╔╝  ██╔══╝  ██╔══╝  ██╔══██╗
██║  ██║██║ ╚████║██║  ██║███████╗   ██║   ███████╗███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝

```

=# 🔐 LogSentinel — Mini SIEM / SOC Analyzer

> Sistema de análise de logs e detecção de ameaças em tempo real, inspirado em soluções SIEM corporativas.
> Evoluído para operar com **logs reais e ataques controlados**, simulando um ambiente de SOC (Security Operations Center).

---

## 🏗️ Arquitetura

![Arquitetura do LogSentinel](/img/architecture.png)

> **Fluxo:** Ingestão de logs → Detecção → Correlação → Resposta → Visualização

---

## 🚀 Funcionalidades

| Módulo             | Descrição                                                 |
| ------------------ | --------------------------------------------------------- |
| 📥 **Ingestão**     | Leitura contínua de logs reais (SSH, HTTP, syslog)        |
| 🔍 **Detecção**     | Identificação de brute force, scans e padrões suspeitos   |
| 🔗 **Correlação**   | Agrupamento de eventos para identificar ataques complexos |
| 🚫 **Bloqueio**     | Bloqueio automático de IPs (aplicação + firewall do SO)   |
| 🌐 **Dashboard**    | Visualização em tempo real com histórico de alertas       |
| ⚠️ **Simulador**    | Geração de ataques controlados via interface              |
| 🔑 **Autenticação** | Controle de acesso com hash bcrypt e registro por IP      |

---

## 🧠 Arquitetura do Sistema

```
logs → parser → detector → correlator → response → dashboard
```

* **Parser** → Normaliza logs (SSH / HTTP)
* **Detector** → Identifica padrões maliciosos
* **Correlator** → Relaciona eventos (ataques multi-etapas)
* **Response** → Executa ações (bloqueio de IP)
* **Dashboard** → Interface de monitoramento

---

## 🧪 Execução em Ambiente Real (Lab SOC)

O projeto pode ser utilizado com **logs reais do sistema operacional**, simulando um ambiente próximo ao de produção.

### 📂 Fontes de logs suportadas:

* `/var/log/auth.log` (SSH)
* `/var/log/syslog`
* logs HTTP (Apache/Nginx)

---

### 💣 Geração de ataques controlados

#### 1. Via Dashboard

Acesse:
`http://127.0.0.1:5000/simulador`

Simulações disponíveis:

* Brute force SSH
* Flood HTTP (DDoS básico)
* Ataque combinado

---

#### 2. Via Terminal (mais realista)

**🔴 Brute Force SSH**

```bash
for i in {1..10}; do
  echo "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2" >> /var/log/auth.log
done
```

**🟣 Flood HTTP**

```bash
for i in {1..200}; do
  echo '192.168.1.5 - - "GET / HTTP/1.1" 200' >> logs/auth.log
done
```

> Permite validar a detecção em tempo real com dados próximos de cenários reais.

---

## ⚙️ Execução

### 🧰 Ambiente local

```bash
git clone https://github.com/PedroEmilioMartinelli/LogSentinel-Mini-SIEM-SOC-Analyzer-.git
cd LogSentinel-Mini-SIEM-SOC-Analyzer-

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# Terminal 1
python monitor.py

# Terminal 2
python app.py
```

Acesse:
`http://127.0.0.1:5000`

---

### 🐳 Docker

```bash
docker build -t logsentinel .
docker run -p 5000:5000 logsentinel
```

---

## 🛡️ Resposta Automática

O sistema realiza bloqueio de IPs suspeitos:

* Camada de aplicação (`blocker.py`)
* Camada de sistema (`os_blocker.py`)

Exemplo:

```bash
iptables -A INPUT -s <IP> -j DROP
```

> ⚠️ Requer privilégios de administrador (root)

---

## 📊 Pipeline de Processamento

```
[Logs reais]
      ↓
[monitor.py]
      ↓
[parser.py]
      ↓
[detector.py]
      ↓
[correlator.py]
      ↓
[blocker.py / os_blocker.py]
      ↓
[Dashboard]
```

---

## ⚠️ Limitações

* Projeto focado em ambiente de laboratório (não produção enterprise)
* SQLite não escala para alto volume
* Regras de detecção ainda baseadas em padrões simples
* Sem integração com threat intelligence externa

---

## 🗺️ Roadmap

### 🔥 Próximas evoluções (nível profissional)

* [ ] Enriquecimento de IP (geolocalização + reputação)
* [ ] Integração com threat intelligence (AbuseIPDB)
* [ ] Mapeamento MITRE ATT&CK
* [ ] Sistema de severidade (low / medium / high)
* [ ] Pipeline de ingestão (log shipping estilo Filebeat)
* [ ] Suporte a múltiplas máquinas monitoradas
* [ ] Banco de dados escalável (PostgreSQL)
* [ ] Alertas (email / webhook / Discord)

---

## 🎯 Objetivo

Evoluir o projeto para um nível próximo a ferramentas reais de mercado, servindo como base prática para atuação em:

* SOC Analyst (Blue Team)
* Threat Detection
* Security Monitoring

---

## ⚠️ Aviso

Este projeto é para fins educacionais.

* Utilize apenas em ambientes controlados
* Não exponha diretamente à internet sem hardening adequado

---

## 👨‍💻 Autor

**Pedro Emilio Martinelli**
Engenharia de Software — UNIJUI
Foco: Cibersegurança / Blue Team

🔗 LinkedIn: https://www.linkedin.com/in/pedro-emilio-martinelli-792303262/
🔗 GitHub: https://github.com/PedroEmilioMartinelli

---

> *"Segurança não é ferramenta. É processo."*
