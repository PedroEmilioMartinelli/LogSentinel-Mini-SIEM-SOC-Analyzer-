# 🔐 LogSentinel — Mini SIEM / SOC Analyzer

> Sistema de análise de logs e detecção de ameaças em tempo real, inspirado em soluções SIEM corporativas. Desenvolvido para simular o funcionamento de um SOC (Security Operations Center) com detecção e resposta a incidentes.

<br>

## 🏗️ Arquitetura

![Arquitetura do LogSentinel](/img/architecture.png)

> **Fluxo:** Ingestão de logs → Detecção e correlação → Resposta automática → Visualização em dashboard

<br>

## 🚀 Funcionalidades

| Módulo | Descrição |
|---|---|
| 📥 **Ingestão** | Leitura contínua de logs SSH e HTTP em tempo real |
| 🔍 **Detecção** | Identificação automática de brute force, DDoS e comportamento suspeito |
| 🔗 **Correlação** | Cruzamento de eventos para identificar padrões complexos de ataque |
| 🚫 **Bloqueio** | IPs maliciosos bloqueados automaticamente em nível de aplicação e SO (requer root) |
| 🌐 **Dashboard** | Interface web dark mode com gráficos, histórico de alertas e contador regressivo |
| ⚠️ **Simulador** | Página dedicada para simular ataques diretamente pelo dashboard |
| 🔑 **Autenticação** | Login com hash bcrypt e registro de tentativas por IP |

<br>

## 📁 Estrutura do Projeto

```
LogSentinel/
│
├── core/
│   ├── parser.py            # Parser de logs SSH e HTTP
│   ├── detector.py          # Detecção de ameaças (brute force, DDoS)
│   └── correlator.py        # Correlação de eventos suspeitos
│
├── utils/
│   └── helpers.py           # Funções auxiliares
│
├── rules/
│   └── rules.json           # Regras de detecção configuráveis
│
├── logs/
│   └── auth.log             # Logs de autenticação
│
├── output/
│   ├── users.json           # Usuários do sistema
│   └── login_attempts.json  # Tentativas de login registradas
│
├── templates/
│   ├── login.html           # Página de login
│   ├── dashboard.html       # Dashboard principal
│   └── simulator.html       # Página do simulador de ataques
│
├── static/
│   ├── css/
│   │   └── style.css        # Estilos globais
│   └── js/
│       ├── dashboard.js     # Lógica do dashboard
│       └── simulator.js     # Lógica do simulador
│
├── app.py                   # Servidor Flask + rotas
├── monitor.py               # Monitor em tempo real
├── blocker.py               # Bloqueio de IPs (camada de aplicação)
├── os_blocker.py            # Bloqueio de IPs no firewall do SO
├── simulator.py             # Lógica de simulação de ataques
├── cli.py                   # Interface de linha de comando
├── db.py                    # Camada de banco de dados (SQLite)
├── Dockerfile
└── requirements.txt
```

<br>

## ⚙️ Tecnologias
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

<br>

## 🛠️ Como Executar

### Pré-requisitos
- Python 3.8+
- pip

### Instalação

```bash
# 1. Clone o repositório
git clone https://github.com/PedroEmilioMartinelli/LogSentinel-Mini-SIEM-SOC-Analyzer-.git
cd LogSentinel-Mini-SIEM-SOC-Analyzer-

# 2. Crie o ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Inicie o monitor em tempo real (terminal 1)
python monitor.py

# 5. Inicie a aplicação web (terminal 2)
python app.py
```

Acesse em: **http://127.0.0.1:5000**

### Via Docker

```bash
docker build -t logsentinel .
docker run -p 5000:5000 logsentinel
```

<br>

## ⚠️ Simulador de Ataques

O projeto possui uma página dedicada para simular ataques diretamente pelo dashboard, sem precisar rodar comandos no terminal.

Acesse **http://127.0.0.1:5000/simulador** e use os botões:

| Simulação | Descrição |
|---|---|
| 🔴 **Brute Force SSH** | Gera 6 tentativas de login falhas consecutivas |
| 🟣 **DDoS HTTP** | Gera rajada de 5 requisições em alta frequência |
| 🔵 **Ataque Combinado** | Simula SSH + acesso web do mesmo IP |

> É possível informar um IP customizado ou deixar em branco para sortear automaticamente.

Também é possível simular via terminal:

### Brute Force SSH
```bash
for i in {1..10}; do
  echo "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2" >> logs/auth.log
done
```

### Tráfego intenso (DDoS simulado)
```bash
for i in {1..200}; do
  echo '192.168.1.5 - - "GET / HTTP/1.1" 200' >> logs/auth.log
done
```

<br>

## 📊 Como Funciona

```
[Logs gerados]
      ↓
[monitor.py lê em tempo real]
      ↓
[parser.py extrai eventos]
      ↓
[detector.py identifica ameaças]
      ↓
[correlator.py cruza eventos]
      ↓
[blocker.py bloqueia IPs suspeitos]
      ↓
[Dashboard exibe alertas com atualização automática]
```

<br>

## ⚠️ Limitações Conhecidas

- Bloqueio de IP no SO (`os_blocker.py`) requer execução como root — em modo desenvolvimento é ignorado automaticamente
- SQLite não é recomendado para ambientes de produção com alto volume
- Projeto desenvolvido para fins educacionais e de portfólio

<br>

## 🗺️ Roadmap

- [x] Simulador de ataques via dashboard
- [x] Separação de templates, CSS e JS
- [x] Bloqueio de IP integrado ao firewall do SO
- [ ] Autenticação com sessão (Flask-Login)
- [ ] Geolocalização de IPs (mapa de ataques)
- [ ] Autenticação via token JWT
- [ ] Suporte a múltiplas fontes de log
- [ ] Deploy com banco persistente (PostgreSQL)
- [ ] Alertas por e-mail / webhook

<br>

## 👨‍💻 Autor

**Pedro Emilio Martinelli**  
Estudante de Engenharia de Software — UNIJUI  
Foco em Cibersegurança / Blue Team

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/pedro-emilio-martinelli-792303262/)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/PedroEmilioMartinelli)

<br>

---

> *"Segurança não é uma funcionalidade. É um requisito."*
