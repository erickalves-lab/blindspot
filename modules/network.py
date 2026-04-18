"""
Módulo Network - Rede e Firewall
=================================
Controles: ISO 27001 A.8.20, A.8.21 | CIS Benchmark 3.5
Função NIST CSF: Protect (PR.PT), Detect (DE.CM)
"""

import subprocess


def executar():
    """Executa todas as verificações do módulo e retorna lista de resultados."""
    return [
        verificar_firewall_ativo(),
        verificar_portas_abertas(),
        verificar_servicos_inseguros(),
        verificar_syn_cookies(),
        verificar_icmp_redirects(),
        verificar_reverse_path_filtering(),
    ]


def _rodar(cmd):
    import shlex
    try:
        args = cmd if isinstance(cmd, list) else shlex.split(cmd)
        resultado = subprocess.run(
            args, shell=False, capture_output=True, text=True, timeout=10
        )
        return resultado.stdout.strip()
    except Exception:
        return ""

def verificar_firewall_ativo():
    """A.8.21 - Firewall deve estar ativo e configurado."""
    # Tenta UFW primeiro
    ufw = _rodar("sudo ufw status")

    if "active" in ufw.lower():
        return {
            "modulo": "Network",
            "controle_iso": "A.8.21",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "Firewall ativo e configurado",
            "status": "CONFORME",
            "evidencia": "UFW ativo",
            "remediacao": "Nenhuma ação necessária",
        }

    # Tenta iptables
    iptables = _rodar("sudo iptables -L INPUT --line-numbers")
    regras = [l for l in iptables.splitlines() if l.startswith(("1", "2", "3"))]

    if regras:
        return {
            "modulo": "Network",
            "controle_iso": "A.8.21",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "Firewall ativo e configurado",
            "status": "CONFORME",
            "evidencia": f"iptables com {len(regras)} regra(s) ativa(s)",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "Network",
        "controle_iso": "A.8.21",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "Firewall ativo e configurado",
        "status": "NÃO CONFORME",
        "evidencia": "UFW inativo e nenhuma regra iptables encontrada",
        "remediacao": "Ativar UFW com 'ufw enable' e configurar regras padrão",
    }

def verificar_portas_abertas():
    """A.8.20 - Apenas portas necessárias devem estar abertas."""
    saida = _rodar("ss -tulnp")

    if not saida:
        return {
            "modulo": "Network",
            "controle_iso": "A.8.20",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "Portas abertas sem justificativa identificadas",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível listar portas abertas",
            "remediacao": "Verificar se o comando ss está disponível",
        }

    portas_conhecidas = {
        "22": "SSH",
        "80": "HTTP",
        "443": "HTTPS",
        "53": "DNS",
        "67": "DHCP",
        "68": "DHCP",
        "123": "NTP",
    }

    portas_encontradas = []
    portas_desconhecidas = []

    for linha in saida.splitlines()[1:]:
        partes = linha.split()
        if not partes:
            continue
        # Campo de endereço local está na posição 4
        if len(partes) < 5:
            continue
        endereco = partes[4]
        porta = endereco.split(":")[-1]

        if porta not in portas_encontradas:
            portas_encontradas.append(porta)
            if porta not in portas_conhecidas:
                portas_desconhecidas.append(porta)

    if not portas_desconhecidas:
        return {
            "modulo": "Network",
            "controle_iso": "A.8.20",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "Portas abertas sem justificativa identificadas",
            "status": "CONFORME",
            "evidencia": f"Portas abertas: {', '.join(portas_encontradas)} — todas conhecidas",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "Network",
        "controle_iso": "A.8.20",
        "funcao_nist": "Detect (DE.CM)",
        "descricao": "Portas abertas sem justificativa identificadas",
        "status": "ATENÇÃO",
        "evidencia": f"Todas as portas: {', '.join(portas_encontradas)} | Não mapeadas: {', '.join(portas_desconhecidas)}",
        "remediacao": "Revisar e fechar portas desnecessárias",
    }

def verificar_servicos_inseguros():
    """A.8.20 - Serviços inseguros devem estar desabilitados."""
    servicos_inseguros = {
        "telnet":   "Transmite dados sem criptografia",
        "ftp":      "Transmite credenciais em texto claro",
        "rsh":      "Remote shell sem criptografia",
        "rlogin":   "Remote login sem criptografia",
        "vsftpd":   "Servidor FTP",
        "proftpd":  "Servidor FTP",
    }

    ativos = {}

    for servico, motivo in servicos_inseguros.items():
        saida = _rodar(f"systemctl is-active {servico} 2>/dev/null")
        if saida == "active":
            ativos[servico] = motivo

    if not ativos:
        return {
            "modulo": "Network",
            "controle_iso": "A.8.20",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "Serviços de rede inseguros desabilitados",
            "status": "CONFORME",
            "evidencia": "Nenhum serviço inseguro ativo (telnet, FTP, rsh)",
            "remediacao": "Nenhuma ação necessária",
        }

    evidencia = " | ".join(f"{s}: {m}" for s, m in ativos.items())

    return {
        "modulo": "Network",
        "controle_iso": "A.8.20",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "Serviços de rede inseguros desabilitados",
        "status": "NÃO CONFORME",
        "evidencia": evidencia,
        "remediacao": "Desabilitar com 'systemctl disable --now <serviço>'",
    }

def verificar_syn_cookies():
    """CIS 3.5 - SYN cookies devem estar habilitados."""
    saida = _rodar("sysctl net.ipv4.tcp_syncookies")

    if not saida:
        return {
            "modulo": "Network",
            "controle_iso": "A.8.21",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "SYN cookies habilitados (proteção contra SYN flood)",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler parâmetro do kernel",
            "remediacao": "Verificar se sysctl está disponível",
        }

    valor = saida.split("=")[-1].strip()
    conforme = valor == "1"

    return {
        "modulo": "Network",
        "controle_iso": "A.8.21",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "SYN cookies habilitados (proteção contra SYN flood)",
        "status": "CONFORME" if conforme else "NÃO CONFORME",
        "evidencia": f"net.ipv4.tcp_syncookies = {valor}",
        "remediacao": "Definir 'net.ipv4.tcp_syncookies = 1' via sysctl",
    }


def verificar_icmp_redirects():
    """CIS 3.5 - Aceitação de ICMP redirects deve estar desabilitada."""
    saida = _rodar("sysctl net.ipv4.conf.all.accept_redirects")

    if not saida:
        return {
            "modulo": "Network",
            "controle_iso": "A.8.21",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "Aceitação de ICMP redirects desabilitada",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler parâmetro do kernel",
            "remediacao": "Verificar se sysctl está disponível",
        }

    valor = saida.split("=")[-1].strip()
    conforme = valor == "0"

    return {
        "modulo": "Network",
        "controle_iso": "A.8.21",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "Aceitação de ICMP redirects desabilitada",
        "status": "CONFORME" if conforme else "NÃO CONFORME",
        "evidencia": f"net.ipv4.conf.all.accept_redirects = {valor}",
        "remediacao": "Definir 'net.ipv4.conf.all.accept_redirects = 0' via sysctl",
    }


def verificar_reverse_path_filtering():
    """CIS 3.5 - Reverse path filtering deve estar habilitado."""
    saida = _rodar("sysctl net.ipv4.conf.all.rp_filter")

    if not saida:
        return {
            "modulo": "Network",
            "controle_iso": "A.8.21",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "Reverse path filtering habilitado (anti-spoofing)",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler parâmetro do kernel",
            "remediacao": "Verificar se sysctl está disponível",
        }

    valor = saida.split("=")[-1].strip()
    conforme = valor in ["1", "2"]

    return {
        "modulo": "Network",
        "controle_iso": "A.8.21",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "Reverse path filtering habilitado (anti-spoofing)",
        "status": "CONFORME" if conforme else "NÃO CONFORME",
        "evidencia": f"net.ipv4.conf.all.rp_filter = {valor}",
        "remediacao": "Definir 'net.ipv4.conf.all.rp_filter = 1' via sysctl",
    }