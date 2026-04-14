"""
Módulo Logs - Auditoria e Retenção
=====================================
Controles: ISO 27001 A.8.15, A.8.16 | LGPD Art. 46
Função NIST CSF: Detect (DE.CM)
"""

import subprocess
import os


def executar():
    """Executa todas as verificações do módulo e retorna lista de resultados."""
    return [
        verificar_rsyslog(),
        verificar_auditd(),
        verificar_logrotate(),
        verificar_auth_log(),
        verificar_sudo_log(),
        verificar_integridade_logs(),
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

def verificar_rsyslog():
    """A.8.15 — Serviço de log centralizado deve estar ativo."""
    for servico in ["rsyslog", "syslog"]:
        saida = _rodar(f"systemctl is-active {servico} 2>/dev/null")
        if saida == "active":
            return {
                "modulo": "Logs",
                "controle_iso": "A.8.15",
                "funcao_nist": "Detect (DE.CM)",
                "descricao": "Serviço de log centralizado ativo",
                "status": "CONFORME",
                "evidencia": f"{servico} está ativo",
                "remediacao": "Nenhuma ação necessária",
            }

    return {
        "modulo": "Logs",
        "controle_iso": "A.8.15",
        "funcao_nist": "Detect (DE.CM)",
        "descricao": "Serviço de log centralizado ativo",
        "status": "NÃO CONFORME",
        "evidencia": "rsyslog e syslog inativos ou não instalados",
        "remediacao": "Instalar e habilitar rsyslog: apt install rsyslog && systemctl enable rsyslog",
    }


def verificar_auditd():
    """A.8.16 - Sistema de auditoria deve estar instalado e ativo."""
    saida = _rodar("systemctl is-active auditd 2>/dev/null")

    if saida == "active":
        return {
            "modulo": "Logs",
            "controle_iso": "A.8.16",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "auditd instalado e em execução",
            "status": "CONFORME",
            "evidencia": "auditd está ativo",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "Logs",
        "controle_iso": "A.8.16",
        "funcao_nist": "Detect (DE.CM)",
        "descricao": "auditd instalado e em execução",
        "status": "NÃO CONFORME",
        "evidencia": f"auditd status: {saida or 'não encontrado'}",
        "remediacao": "Instalar e habilitar: apt install auditd && systemctl enable auditd",
    }


def verificar_logrotate():
    """A.8.15 - Retenção de logs deve estar configurada."""
    if not os.path.exists("/etc/logrotate.conf"):
        return {
            "modulo": "Logs",
            "controle_iso": "A.8.15",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "Retenção de logs configurada via logrotate",
            "status": "NÃO CONFORME",
            "evidencia": "/etc/logrotate.conf não encontrado",
            "remediacao": "Instalar logrotate: apt install logrotate",
        }

    saida = _rodar("grep -E '^rotate' /etc/logrotate.conf")

    if not saida:
        return {
            "modulo": "Logs",
            "controle_iso": "A.8.15",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "Retenção de logs configurada via logrotate",
            "status": "ATENÇÃO",
            "evidencia": "Diretiva rotate não encontrada em /etc/logrotate.conf",
            "remediacao": "Adicionar 'rotate 4' ou mais em /etc/logrotate.conf",
        }

    try:
        rotacoes = int(saida.split()[1])
        conforme = rotacoes >= 4
        return {
            "modulo": "Logs",
            "controle_iso": "A.8.15",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "Retenção de logs configurada via logrotate",
            "status": "CONFORME" if conforme else "NÃO CONFORME",
            "evidencia": f"Retenção configurada: {rotacoes} rotação(ões)",
            "remediacao": "Definir 'rotate 4' ou mais em /etc/logrotate.conf",
        }
    except (ValueError, IndexError):
        return {
            "modulo": "Logs",
            "controle_iso": "A.8.15",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "Retenção de logs configurada via logrotate",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível interpretar a diretiva rotate",
            "remediacao": "Verificar configuração do logrotate.conf",
        }


def verificar_auth_log():
    """A.8.16 - Log de autenticação deve existir e estar sendo atualizado."""
    caminhos = ["/var/log/auth.log", "/var/log/secure"]

    for caminho in caminhos:
        if os.path.exists(caminho):
            tamanho = os.path.getsize(caminho)
            return {
                "modulo": "Logs",
                "controle_iso": "A.8.16",
                "funcao_nist": "Detect (DE.CM)",
                "descricao": "Log de autenticação ativo",
                "status": "CONFORME",
                "evidencia": f"{caminho} existe ({tamanho} bytes)",
                "remediacao": "Nenhuma ação necessária",
            }

    return {
        "modulo": "Logs",
        "controle_iso": "A.8.16",
        "funcao_nist": "Detect (DE.CM)",
        "descricao": "Log de autenticação ativo",
        "status": "NÃO CONFORME",
        "evidencia": "Nem /var/log/auth.log nem /var/log/secure encontrados",
        "remediacao": "Verificar configuração do rsyslog para garantir geração do auth.log",
    }


def verificar_sudo_log():
    """A.8.16 - Comandos sudo devem ser registrados em log."""
    saida = _rodar("grep -r 'logfile\\|log_output' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")

    if saida:
        return {
            "modulo": "Logs",
            "controle_iso": "A.8.16",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "Log de comandos sudo configurado",
            "status": "CONFORME",
            "evidencia": f"Configuração encontrada: {saida.splitlines()[0]}",
            "remediacao": "Nenhuma ação necessária",
        }

    # Verifica se sudo está sendo registrado no syslog
    syslog = _rodar("grep -r 'sudo' /var/log/syslog /var/log/messages 2>/dev/null | tail -1")

    if syslog:
        return {
            "modulo": "Logs",
            "controle_iso": "A.8.16",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "Log de comandos sudo configurado",
            "status": "CONFORME",
            "evidencia": "Comandos sudo registrados via syslog",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "Logs",
        "controle_iso": "A.8.16",
        "funcao_nist": "Detect (DE.CM)",
        "descricao": "Log de comandos sudo configurado",
        "status": "ATENÇÃO",
        "evidencia": "Não foi possível confirmar registro de comandos sudo",
        "remediacao": "Adicionar 'Defaults logfile=/var/log/sudo.log' em /etc/sudoers",
    }


def verificar_integridade_logs():
    """A.8.15 - Logs críticos não devem ter sido modificados recentemente de forma suspeita."""
    import time

    logs_criticos = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
    ]

    suspeitos = []
    verificados = []

    for log in logs_criticos:
        if not os.path.exists(log):
            continue

        verificados.append(log)
        stat = os.stat(log)
        modificado = stat.st_mtime
        criado = stat.st_ctime

        # Suspeito se foi modificado ANTES de ser criado (possível adulteração)
        if modificado < criado - 60:
            suspeitos.append(log)

    if not verificados:
        return {
            "modulo": "Logs",
            "controle_iso": "A.8.15",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "Integridade dos logs críticos verificada",
            "status": "ATENÇÃO",
            "evidencia": "Nenhum arquivo de log crítico encontrado para verificar",
            "remediacao": "Verificar configuração do serviço de logging",
        }

    if suspeitos:
        return {
            "modulo": "Logs",
            "controle_iso": "A.8.15",
            "funcao_nist": "Detect (DE.CM)",
            "descricao": "Integridade dos logs críticos verificada",
            "status": "NÃO CONFORME",
            "evidencia": f"Logs com possível adulteração: {', '.join(suspeitos)}",
            "remediacao": "Investigar modificações nos arquivos de log identificados",
        }

    return {
        "modulo": "Logs",
        "controle_iso": "A.8.15",
        "funcao_nist": "Detect (DE.CM)",
        "descricao": "Integridade dos logs críticos verificada",
        "status": "CONFORME",
        "evidencia": f"{len(verificados)} log(s) verificado(s) sem adulteração detectada",
        "remediacao": "Nenhuma ação necessária",
    }