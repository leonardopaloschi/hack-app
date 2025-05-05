### **Documentação Técnica: HACK-APP**

### ***Ferramentas de Hacking \- Scanner e Analisador de Rede***

### **Descrição Geral**

Este projeto em Python implementa um conjunto de ferramentas voltadas para análise de redes, identificação de dispositivos, escaneamento de portas TCP/UDP, verificação de firewall (WAF), enumeração de subdomínios e detecção de vulnerabilidades usando o Nmap.

### **Estrutura do Projeto**

* **Linguagem:** Python

* **Bibliotecas Utilizadas:**

  * socket – comunicação de rede

  * subprocess – execução de comandos externos

  * re – expressões regulares

  * os, sys, json – utilitários de sistema e arquivos

  * concurrent.futures – execução paralela para enumeração de subdomínios

### **Principais Funcionalidades**

#### **1\. Port Scanner**

* **TCP:** Testa conexão via socket.connect\_ex.

* **UDP:** Envia pacotes e analisa o retorno.


#### **2\. Descoberta de Dispositivos na Rede**

* Usa o comando ip neigh para descobrir dispositivos conectados via ARP.

#### **3\. DNS Lookup**

* Forward: resolve um domínio para IP.

* Reverse: resolve um IP para nome de domínio.

#### **4\. Verificação de WAF**

* Usa o wafw00f (executado via subprocesso) para detectar firewalls em uma URL.

#### **5\. Enumeração de Subdomínios**

* Gera subdomínios a partir de uma wordlist.

* Resolve em paralelo usando ThreadPoolExecutor.

#### **6\. Scan de Vulnerabilidades (Nmap)**

* Executa nmap \-sV \--script vuln via subprocesso.

### **Organização do Código**

* Funções separadas para cada ferramenta.

* Menus interativos para facilitar o uso.

* Bloco main() centraliza a navegação do usuário.

### **Requisitos**

* Python 3.x

* Ferramentas externas:

  * wafw00f

  * nmap

* Sistema operacional compatível com o comando ip neigh (Linux)

