```
███████╗██╗███╗   ███╗██████╗ ██╗     ███████╗    ██████╗  ██████╗ ██████╗ ████████╗
██╔════╝██║████╗ ████║██╔══██╗██║     ██╔════╝    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
███████╗██║██╔████╔██║██████╔╝██║     █████╗      ██████╔╝██║   ██║██████╔╝   ██║   
╚════██║██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝      ██╔═══╝ ██║   ██║██╔══██╗   ██║   
███████║██║██║ ╚═╝ ██║██║     ███████╗███████╗    ██║     ╚██████╔╝██║  ██║   ██║   
╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                                                                                        
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

# 🔍 Simple Port Scanner — Network Reconnaissance Tool

Uma ferramenta de **Segurança de Redes** focada em reconhecimento de portas abertas, serviços ativos e mapeamento de hosts.

> Projeto desenvolvido para fins educacionais em segurança ofensiva e análise de vulnerabilidades de rede.

---

## 🚀 Visão Geral

O **Simple Port Scanner** é uma ferramenta prática e eficiente, capaz de:

* 🔎 Escanear portas em um alvo específico
* 🎯 Identificar serviços rodando em portas abertas
* ⚡ Executar scans rápidos e personalizados
* 📊 Exibir resultados estruturados
* 🛡️ Ajudar na identificação de vulnerabilidades
* 📝 Gerar relatórios de scan

---

## 🧠 Funcionalidades

### 🔍 Escaneamento de Portas

* Scan de portas individuais
* Scan de intervalo de portas
* Scan de portas conhecidas (well-known ports)
* Scan completo (0-65535)

### 🎯 Detecção de Serviços

* Identificação automática de serviços comuns
* Mapeamento de porta → serviço
* Análise de respostas de rede

### ⚡ Desempenho

* Multi-threading para scans mais rápidos
* Timeout configurável
* Processamento paralelo de requisições

### 📊 Relatórios

* Exibição estruturada de resultados
* Portas abertas vs. fechadas
* Lista de serviços detectados
* Estatísticas do scan

### 🔧 Customização

* Definição de intervalo de portas
* Ajuste de timeout
* Múltiplos alvo ao mesmo tempo
* Opções de verbosidade

---

## 📁 Estrutura do Projeto

```
simple-port-scanner/
│
├── 📄 port_scanner.py          (Script principal)
├── 🎯 scanner.py               (Classe do scanner)
├── 🔧 utils.py                 (Funções utilitárias)
│
├── 📁 output/
│   └── 📊 results.txt           (Resultados dos scans)
│
├── 📝 requirements.txt          (Dependências)
├── 🧾 README.md                 (Documentação)
└── ⚙️ config.py                 (Configurações padrão)
```

---

## ⚙️ Tecnologias Utilizadas

* Python 3.7+
* Socket (conexões de rede)
* Threading (paralelização)
* Argparse (CLI)
* Colorama (output colorido)

---

## 🛠️ Como Executar

### 1. Clonar o projeto

```bash
git clone https://github.com/CarterPerez-dev/Cybersecurity-Projects.git
cd Cybersecurity-Projects/PROJECTS/beginner/simple-port-scanner
```

---

### 2. Criar ambiente virtual

```bash
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate
```

---

### 3. Instalar dependências

```bash
pip install -r requirements.txt
```

---

### 4. Executar o scanner

```bash
python port_scanner.py -t <alvo> -p <portas>
```

---

## 📚 Exemplos de Uso

### Escanear uma porta específica

```bash
python port_scanner.py -t 192.168.1.1 -p 80
```

---

### Escanear intervalo de portas

```bash
python port_scanner.py -t scanme.nmap.org -p 1-1000
```

---

### Escanear portas comuns

```bash
python port_scanner.py -t 10.0.0.5 -p common
```

---

### Escanear com timeout personalizado

```bash
python port_scanner.py -t localhost -p 1-65535 --timeout 2
```

---

### Escanear com saída verbosa

```bash
python port_scanner.py -t example.com -p 1-10000 -v
```

---

## 🎯 Opções da CLI

```
Argumentos obrigatórios:
  -t, --target      Endereço IP ou hostname a escanear
  -p, --ports       Intervalo de portas (ex: 1-1000, 80,443, common)

Argumentos opcionais:
  --timeout         Timeout de conexão em segundos (padrão: 1)
  -v, --verbose     Modo verboso (mais detalhes)
  -o, --output      Arquivo de saída para resultados
  -j, --json        Exportar resultados em JSON
  -t, --threads     Número de threads (padrão: 100)
  -h, --help        Mostra esta mensagem de ajuda
```

---

## 📊 Saída do Scanner

```
╔════════════════════════════════════════╗
║    SIMPLE PORT SCANNER - RESULTS       ║
╚════════════════════════════════════════╝

Target: 192.168.1.1
Scan Start: 2026-04-19 10:30:45
Scan End: 2026-04-19 10:31:12
Duration: 27 segundos

OPEN PORTS:
────────────────────────────────────────
Port 22/tcp    OPEN    → SSH
Port 80/tcp    OPEN    → HTTP
Port 443/tcp   OPEN    → HTTPS
Port 3306/tcp  OPEN    → MySQL
Port 8080/tcp  OPEN    → HTTP-ALT

CLOSED PORTS: 995 closed ports

STATISTICS:
────────────────────────────────────────
Total Ports Scanned: 1000
Open Ports: 5
Closed Ports: 995
Scan Rate: 37 ports/sec
```

---

## 🔐 Avisos Importantes

⚠️ **ATENÇÃO**: Este projeto é desenvolvido **apenas para fins educacionais** e de autorização explícita.

* Use apenas em redes/hosts que você tenha permissão para testar
* Port scanning não autorizado é ilegal em muitas jurisdições
* Sempre obtenha consentimento antes de fazer reconhecimento de rede
* Respect the targets and follow ethical guidelines

---

## 💡 Casos de Uso

✅ Teste de penetração autorizado  
✅ Auditoria de segurança interna  
✅ Mapeamento de topologia de rede  
✅ Identificação de serviços em produção  
✅ Fins educacionais em cybersecurity  

---

## ⚠️ Limitações

* Não consegue contornar firewalls
* Depende da resposta do host (alguns podem filtrar respostas)
* Scans rápidos podem ser detectados por IDS/IPS
* Não faz fingerprinting avançado de serviços
* Apenas TCP (UDP requer implementação adicional)

---

## 🚀 Próximos Passos

* Suporte a scanning de UDP
* Fingerprinting de serviços avançado
* Integração com base de vulnerabilidades (CVE)
* Detecção de WAF/proxy reverso
* Exportação em múltiplos formatos (CSV, JSON, HTML)
* Dashboard web para visualização

---

## 🎓 Objetivo Educacional

Este projeto demonstra conhecimento em:

* Protocolos de rede (TCP/IP)
* Sockets programming em Python
* Port scanning e network reconnaissance
* Análise de vulnerabilidades de rede
* Boas práticas em segurança ofensiva ética
* Desenvolvimento de ferramentas de segurança

---

## 📚 Referências Úteis

* [RFC 793 - TCP Protocol](https://tools.ietf.org/html/rfc793)
* [OWASP Network Security](https://owasp.org/)
* [Python Socket Documentation](https://docs.python.org/3/library/socket.html)
* [Nmap Documentation](https://nmap.org/book/)

---

## 🤝 Contribuições

Se você deseja contribuir:

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

---

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.

---

## 👨‍💻 Autor

**Carter Perez**

Projeto desenvolvido para evolução prática em Segurança de Redes, Penetration Testing e Cybersecurity.

---

## ⚖️ Aviso Legal

**USE RESPONSAVELMENTE**  
Este software é fornecido "como está". O autor não é responsável por qualquer uso indevido, ilegal ou não autorizado desta ferramenta. A responsabilidade de usar eticamente recai sobre o usuário.

---

## 📞 Suporte

Para dúvidas, issues ou sugestões:

* 🐛 Abra uma [Issue no GitHub](https://github.com/CarterPerez-dev/Cybersecurity-Projects/issues)
* 💬 Participe das [Discussions](https://github.com/CarterPerez-dev/Cybersecurity-Projects/discussions)
* 📧 Entre em contato direto

---

**Última atualização**: Abril de 2026
