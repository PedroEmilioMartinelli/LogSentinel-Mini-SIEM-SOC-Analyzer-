# 🔐 LogSentinel — Mini SIEM (SOC Analyzer)

Um sistema de **Segurança da Informação** focado em análise de logs, detecção de ataques e monitoramento em tempo real.

> Projeto desenvolvido para simular o funcionamento de um SOC (Security Operations Center), com detecção e resposta a incidentes.

---

## 🚀 Visão Geral

O **LogSentinel** é uma ferramenta inspirada em soluções de SIEM, capaz de:

* 📥 Ler logs em tempo real
* 🔍 Detectar ataques automaticamente
* 🚨 Gerar alertas de segurança
* 🧠 Correlacionar eventos suspeitos
* 🔐 Bloquear IPs maliciosos (nível aplicação)
* 🌐 Exibir dados via dashboard web

---

## 🧠 Funcionalidades

### 🔍 Análise de Logs

* Parser de logs de autenticação (SSH)
* Parser de logs web (requisições HTTP)

### 🚨 Detecção de Ameaças

* Brute Force (múltiplas tentativas de login)
* Comportamento suspeito (login + acesso web)
* Base para detecção de DDoS (padrão de requisições)

### ⚡ Monitoramento em Tempo Real

* Leitura contínua de arquivos de log
* Detecção automática de eventos

### 🔐 Bloqueio de IP

* IPs maliciosos são bloqueados automaticamente
* Sistema ignora eventos de IPs já bloqueados

### 🌐 Dashboard Web

* Interface moderna (dark mode)
* Gráfico de ataques por IP
* Tabela com histórico de alertas
* Atualização automática

### 🔑 Autenticação

* Sistema de login e registro
* Senhas protegidas com hash (bcrypt)
* Registro de tentativas de login com IP

---

## 📁 Estrutura do Projeto

```
socAanalyzer/
│
├── 📁 core/
│   ├── 🧠 parser.py
│   ├── 🚨 detector.py
│   ├── 🔗 correlator.py
│
├── 📁 utils/
│   └── 🛠️ helpers.py
│
├── 📁 rules/
│   └── 📜 rules.json
│
├── 📁 logs/
│   └── 📄 auth.log
│
├── 📁 output/
│   ├── 👤 users.json
│   └── 📊 login_attempts.json
│
├── 🗄️ db.py
├── 🚫 blocker.py
├── 👁️ monitor.py
├── 💻 cli.py
├── 🌐 app.py
├── 📦 requirements.txt
├── ⚙️ Procfile
└── 🧾 soc.db
```

---

## ⚙️ Tecnologias Utilizadas

* Python
* Flask
* SQLite
* bcrypt
* Chart.js
* JSON
* Regex

---

## 🛠️ Como Executar

### 1. Clonar o projeto

```bash
git clone https://github.com/seu-usuario/socAanalyzer.git
cd socAanalyzer
```

---

### 2. Criar ambiente virtual

```bash
python -m venv venv
source venv/bin/activate
```

---

### 3. Instalar dependências

```bash
pip install -r requirements.txt
```

---

### 4. Rodar monitor (tempo real)

```bash
python monitor.py
```

---

### 5. Rodar aplicação web

```bash
python app.py
```

---

### 6. Acessar no navegador

```
http://127.0.0.1:5000
```

---

## 🧪 Simulação de Ataques

### 🔥 Brute Force

```bash
for i in {1..10}; do echo "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2" >> logs/auth.log; done
```

---

### 🔥 Tráfego intenso (simulação de DDoS)

```bash
for i in {1..200}; do echo "192.168.1.5 - - \"GET / HTTP/1.1\" 200" >> logs/auth.log; done
```

---

## 📊 Como Funciona

1. Logs são gerados ou inseridos manualmente
2. O `monitor.py` lê os eventos em tempo real
3. O sistema detecta padrões de ataque
4. Alertas são gerados e armazenados no banco (SQLite)
5. IPs suspeitos são bloqueados
6. O dashboard exibe tudo em tempo real

---

## ⚠️ Limitações

* Bloqueio de IP ocorre apenas na aplicação (não no sistema operacional)
* Banco SQLite não é ideal para produção
* Projeto voltado para fins educacionais

---

## 🎯 Objetivo

Demonstrar conhecimentos em:

* Segurança da Informação
* Análise de logs
* Detecção de ameaças
* Desenvolvimento de sistemas de monitoramento
* Arquitetura de aplicações

---

## 🚀 Próximos Passos

* Integração com firewall real (iptables/ufw)
* Geolocalização de IP (mapa de ataques)
* Sistema de alertas visuais/sonoros
* Autenticação com sessão/token
* Deploy com banco persistente

---

## 👨‍💻 Autor

Projeto desenvolvido para evolução prática em Segurança da Informação e construção de portfólio técnico.
