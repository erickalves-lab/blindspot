"""
Módulo SSH - Configuração do Servidor
======================================
Controles: ISO 27001 A.8.20, A.8.5 | CIS Benchmark 5.2
Função NIST CSF: Protect (PR.PT)
"""

import subprocess


def executar():
    """Executa todas as verificações do módulo e retorna lista de resultados."""
    return [
        verificar_permit_root_login(),
        verificar_x11_forwarding(),
        verificar_max_auth_tries(),
        verificar_client_alive(),
        verificar_autenticacao_senha(),
        verificar_protocolo(),
    ]


def _rodar(cmd):
    """Executa um comando shell e retorna o stdout."""
    try:
        resultado = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        return resultado.stdout.strip()
    except Exception:
        return ""


def _ler_sshd_config():
    """Lê o arquivo sshd_config e retorna seu conteúdo."""
    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            return f.read()
    except Exception:
        return ""

def verificar_permit_root_login():
    """A.8.5 - Login root via SSH deve estar desabilitado."""
    config = _ler_sshd_config()

    if not config:
        return {
            "modulo": "SSH",
            "controle_iso": "A.8.5",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "Login root via SSH desabilitado",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler /etc/ssh/sshd_config",
            "remediacao": "Verificar permissões do arquivo /etc/ssh/sshd_config",
        }

    for linha in config.splitlines():
        linha = linha.strip()
        if linha.startswith("#") or not linha:
            continue
        if linha.lower().startswith("permitrootlogin"):
            valor = linha.split()[1].lower()
            conforme = valor == "no"
            return {
                "modulo": "SSH",
                "controle_iso": "A.8.5",
                "funcao_nist": "Protect (PR.PT)",
                "descricao": "Login root via SSH desabilitado",
                "status": "CONFORME" if conforme else "NÃO CONFORME",
                "evidencia": f"PermitRootLogin: {valor}",
                "remediacao": "Definir 'PermitRootLogin no' em /etc/ssh/sshd_config",
            }

    return {
        "modulo": "SSH",
        "controle_iso": "A.8.5",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "Login root via SSH desabilitado",
        "status": "ATENÇÃO",
        "evidencia": "Diretiva PermitRootLogin não encontrada — valor padrão pode estar em uso",
        "remediacao": "Adicionar explicitamente 'PermitRootLogin no' em /etc/ssh/sshd_config",
    }

def verificar_x11_forwarding():
    """A.8.20 - X11 Forwarding deve estar desabilitado."""
    config = _ler_sshd_config()

    if not config:
        return {
            "modulo": "SSH",
            "controle_iso": "A.8.20",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "X11 Forwarding desabilitado",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler /etc/ssh/sshd_config",
            "remediacao": "Verificar permissões do arquivo /etc/ssh/sshd_config",
        }

    for linha in config.splitlines():
        linha = linha.strip()
        if linha.startswith("#") or not linha:
            continue
        if linha.lower().startswith("x11forwarding"):
            valor = linha.split()[1].lower()
            conforme = valor == "no"
            return {
                "modulo": "SSH",
                "controle_iso": "A.8.20",
                "funcao_nist": "Protect (PR.PT)",
                "descricao": "X11 Forwarding desabilitado",
                "status": "CONFORME" if conforme else "NÃO CONFORME",
                "evidencia": f"X11Forwarding: {valor}",
                "remediacao": "Definir 'X11Forwarding no' em /etc/ssh/sshd_config",
            }

    return {
        "modulo": "SSH",
        "controle_iso": "A.8.20",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "X11 Forwarding desabilitado",
        "status": "ATENÇÃO",
        "evidencia": "Diretiva X11Forwarding não encontrada",
        "remediacao": "Adicionar explicitamente 'X11Forwarding no' em /etc/ssh/sshd_config",
    }


def verificar_max_auth_tries():
    """CIS 5.2 - Tentativas máximas de autenticação devem ser limitadas a 3."""
    config = _ler_sshd_config()

    if not config:
        return {
            "modulo": "SSH",
            "controle_iso": "A.8.20",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "MaxAuthTries configurado (máximo 3)",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler /etc/ssh/sshd_config",
            "remediacao": "Verificar permissões do arquivo /etc/ssh/sshd_config",
        }

    for linha in config.splitlines():
        linha = linha.strip()
        if linha.startswith("#") or not linha:
            continue
        if linha.lower().startswith("maxauthtries"):
            try:
                valor = int(linha.split()[1])
                conforme = valor <= 3
                return {
                    "modulo": "SSH",
                    "controle_iso": "A.8.20",
                    "funcao_nist": "Protect (PR.PT)",
                    "descricao": "MaxAuthTries configurado (máximo 3)",
                    "status": "CONFORME" if conforme else "NÃO CONFORME",
                    "evidencia": f"MaxAuthTries: {valor}",
                    "remediacao": "Definir 'MaxAuthTries 3' em /etc/ssh/sshd_config",
                }
            except ValueError:
                pass

    return {
        "modulo": "SSH",
        "controle_iso": "A.8.20",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "MaxAuthTries configurado (máximo 3)",
        "status": "ATENÇÃO",
        "evidencia": "Diretiva MaxAuthTries não encontrada",
        "remediacao": "Adicionar 'MaxAuthTries 3' em /etc/ssh/sshd_config",
    }


def verificar_client_alive():
    """A.8.20 - Timeout de sessão SSH deve estar configurado."""
    config = _ler_sshd_config()

    if not config:
        return {
            "modulo": "SSH",
            "controle_iso": "A.8.20",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "Timeout de sessão SSH configurado",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler /etc/ssh/sshd_config",
            "remediacao": "Verificar permissões do arquivo /etc/ssh/sshd_config",
        }

    interval = None
    count = None

    for linha in config.splitlines():
        linha = linha.strip()
        if linha.startswith("#") or not linha:
            continue
        if linha.lower().startswith("clientaliveinterval"):
            try:
                interval = int(linha.split()[1])
            except ValueError:
                pass
        if linha.lower().startswith("clientalivecountmax"):
            try:
                count = int(linha.split()[1])
            except ValueError:
                pass

    if interval is None:
        return {
            "modulo": "SSH",
            "controle_iso": "A.8.20",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "Timeout de sessão SSH configurado",
            "status": "ATENÇÃO",
            "evidencia": "ClientAliveInterval não encontrado",
            "remediacao": "Definir 'ClientAliveInterval 300' e 'ClientAliveCountMax 0'",
        }

    conforme = interval > 0 and interval <= 300
    return {
        "modulo": "SSH",
        "controle_iso": "A.8.20",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "Timeout de sessão SSH configurado",
        "status": "CONFORME" if conforme else "NÃO CONFORME",
        "evidencia": f"ClientAliveInterval: {interval} | ClientAliveCountMax: {count}",
        "remediacao": "Definir 'ClientAliveInterval 300' e 'ClientAliveCountMax 0'",
    }


def verificar_autenticacao_senha():
    """A.8.5 - Autenticação por senha deve estar desabilitada."""
    config = _ler_sshd_config()

    if not config:
        return {
            "modulo": "SSH",
            "controle_iso": "A.8.5",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "Autenticação por senha desabilitada (apenas chave pública)",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler /etc/ssh/sshd_config",
            "remediacao": "Verificar permissões do arquivo /etc/ssh/sshd_config",
        }

    for linha in config.splitlines():
        linha = linha.strip()
        if linha.startswith("#") or not linha:
            continue
        if linha.lower().startswith("passwordauthentication"):
            valor = linha.split()[1].lower()
            conforme = valor == "no"
            return {
                "modulo": "SSH",
                "controle_iso": "A.8.5",
                "funcao_nist": "Protect (PR.PT)",
                "descricao": "Autenticação por senha desabilitada (apenas chave pública)",
                "status": "CONFORME" if conforme else "NÃO CONFORME",
                "evidencia": f"PasswordAuthentication: {valor}",
                "remediacao": "Definir 'PasswordAuthentication no' em /etc/ssh/sshd_config",
            }

    return {
        "modulo": "SSH",
        "controle_iso": "A.8.5",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "Autenticação por senha desabilitada (apenas chave pública)",
        "status": "ATENÇÃO",
        "evidencia": "Diretiva PasswordAuthentication não encontrada",
        "remediacao": "Adicionar 'PasswordAuthentication no' em /etc/ssh/sshd_config",
    }


def verificar_protocolo():
    """A.8.20 - Apenas protocolo SSH 2 deve estar em uso."""
    config = _ler_sshd_config()

    if not config:
        return {
            "modulo": "SSH",
            "controle_iso": "A.8.20",
            "funcao_nist": "Protect (PR.PT)",
            "descricao": "Protocolo SSH 2 forçado",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler /etc/ssh/sshd_config",
            "remediacao": "Verificar permissões do arquivo /etc/ssh/sshd_config",
        }

    for linha in config.splitlines():
        linha = linha.strip()
        if linha.startswith("#") or not linha:
            continue
        if linha.lower().startswith("protocol"):
            valor = linha.split()[1]
            conforme = valor == "2"
            return {
                "modulo": "SSH",
                "controle_iso": "A.8.20",
                "funcao_nist": "Protect (PR.PT)",
                "descricao": "Protocolo SSH 2 forçado",
                "status": "CONFORME" if conforme else "NÃO CONFORME",
                "evidencia": f"Protocol: {valor}",
                "remediacao": "Definir 'Protocol 2' em /etc/ssh/sshd_config",
            }

    return {
        "modulo": "SSH",
        "controle_iso": "A.8.20",
        "funcao_nist": "Protect (PR.PT)",
        "descricao": "Protocolo SSH 2 forçado",
        "status": "CONFORME",
        "evidencia": "Diretiva Protocol não encontrada — SSH 2 é o padrão nas versões modernas",
        "remediacao": "Nenhuma ação necessária em versões modernas do OpenSSH",
    }