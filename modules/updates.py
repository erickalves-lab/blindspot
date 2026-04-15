"""
Módulo Updates - Atualizações e Patches
=========================================
Controles: ISO 27001 A.8.8 | CIS Benchmark 1.9
Função NIST CSF: Identify (ID.RA)
"""

import subprocess
import os


def executar():
    """Executa todas as verificações do módulo e retorna lista de resultados."""
    return [
        verificar_atualizacoes_pendentes(),
        verificar_data_ultima_atualizacao(),
        verificar_atualizacoes_automaticas(),
        verificar_kernel_atualizado(),
        verificar_pacotes_orfaos(),
    ]


def _rodar(cmd):
    """Executa um comando shell e retorna o stdout."""
    try:
        resultado = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        return resultado.stdout.strip()
    except Exception:
        return ""

def verificar_atualizacoes_pendentes():
    """A.8.8 - Patches de segurança não devem estar pendentes."""
    # Tenta apt (Debian/Ubuntu)
    saida = _rodar("apt list --upgradable 2>/dev/null | grep -i security")

    if saida:
        pacotes = saida.splitlines()
        return {
            "modulo": "Updates",
            "controle_iso": "A.8.8",
            "funcao_nist": "Identify (ID.RA)",
            "descricao": "Sem atualizações de segurança pendentes",
            "status": "NÃO CONFORME",
            "evidencia": f"{len(pacotes)} atualização(ões) de segurança pendente(s)",
            "remediacao": "Executar: apt update && apt upgrade -y",
        }

    # Tenta dnf (Fedora/RHEL)
    saida = _rodar("dnf check-update --security 2>/dev/null")
    if saida and "No packages" not in saida:
        pacotes = [l for l in saida.splitlines() if l and not l.startswith("Last")]
        if pacotes:
            return {
                "modulo": "Updates",
                "controle_iso": "A.8.8",
                "funcao_nist": "Identify (ID.RA)",
                "descricao": "Sem atualizações de segurança pendentes",
                "status": "NÃO CONFORME",
                "evidencia": f"{len(pacotes)} atualização(ões) de segurança pendente(s)",
                "remediacao": "Executar: dnf update --security -y",
            }

    return {
        "modulo": "Updates",
        "controle_iso": "A.8.8",
        "funcao_nist": "Identify (ID.RA)",
        "descricao": "Sem atualizações de segurança pendentes",
        "status": "CONFORME",
        "evidencia": "Nenhuma atualização de segurança pendente encontrada",
        "remediacao": "Nenhuma ação necessária",
    }


def verificar_data_ultima_atualizacao():
    """A.8.8 - Sistema deve ter sido atualizado nos últimos 30 dias."""
    from datetime import datetime, timedelta

    limite = datetime.now() - timedelta(days=30)

    # Tenta apt (Debian/Ubuntu)
    caminhos_apt = [
        "/var/log/apt/history.log",
        "/var/log/dpkg.log",
    ]

    for caminho in caminhos_apt:
        if os.path.exists(caminho):
            mtime = datetime.fromtimestamp(os.path.getmtime(caminho))
            conforme = mtime > limite
            return {
                "modulo": "Updates",
                "controle_iso": "A.8.8",
                "funcao_nist": "Identify (ID.RA)",
                "descricao": "Sistema atualizado há menos de 30 dias",
                "status": "CONFORME" if conforme else "NÃO CONFORME",
                "evidencia": f"Última atualização: {mtime.strftime('%d/%m/%Y')}",
                "remediacao": "Executar atualização completa do sistema",
            }

    # Tenta dnf (Fedora/RHEL)
    saida = _rodar("rpm -qa --last 2>/dev/null | head -1")
    if saida:
        return {
            "modulo": "Updates",
            "controle_iso": "A.8.8",
            "funcao_nist": "Identify (ID.RA)",
            "descricao": "Sistema atualizado há menos de 30 dias",
            "status": "ATENÇÃO",
            "evidencia": f"Último pacote instalado: {saida}",
            "remediacao": "Verificar data da última atualização de segurança",
        }

    return {
        "modulo": "Updates",
        "controle_iso": "A.8.8",
        "funcao_nist": "Identify (ID.RA)",
        "descricao": "Sistema atualizado há menos de 30 dias",
        "status": "ATENÇÃO",
        "evidencia": "Não foi possível determinar a data da última atualização",
        "remediacao": "Verificar histórico de atualizações do sistema",
    }


def verificar_atualizacoes_automaticas():
    """CIS 1.9 - Atualizações automáticas de segurança devem estar configuradas."""
    # Tenta unattended-upgrades (Debian/Ubuntu)
    saida = _rodar("systemctl is-active unattended-upgrades 2>/dev/null")
    if saida == "active":
        return {
            "modulo": "Updates",
            "controle_iso": "A.8.8",
            "funcao_nist": "Identify (ID.RA)",
            "descricao": "Atualizações automáticas de segurança configuradas",
            "status": "CONFORME",
            "evidencia": "unattended-upgrades está ativo",
            "remediacao": "Nenhuma ação necessária",
        }

    # Tenta dnf-automatic (Fedora/RHEL)
    saida = _rodar("systemctl is-active dnf-automatic 2>/dev/null")
    if saida == "active":
        return {
            "modulo": "Updates",
            "controle_iso": "A.8.8",
            "funcao_nist": "Identify (ID.RA)",
            "descricao": "Atualizações automáticas de segurança configuradas",
            "status": "CONFORME",
            "evidencia": "dnf-automatic está ativo",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "Updates",
        "controle_iso": "A.8.8",
        "funcao_nist": "Identify (ID.RA)",
        "descricao": "Atualizações automáticas de segurança configuradas",
        "status": "NÃO CONFORME",
        "evidencia": "Nenhum serviço de atualização automática encontrado",
        "remediacao": "Instalar e configurar unattended-upgrades ou dnf-automatic",
    }


def verificar_kernel_atualizado():
    """A.8.8 - Kernel em execução deve ser o mais recente instalado."""
    kernel_atual = _rodar("uname -r")

    if not kernel_atual:
        return {
            "modulo": "Updates",
            "controle_iso": "A.8.8",
            "funcao_nist": "Identify (ID.RA)",
            "descricao": "Kernel em execução atualizado",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível obter versão do kernel",
            "remediacao": "Verificar manualmente com uname -r",
        }

    # Tenta apt (Debian/Ubuntu)
    instalado = _rodar(
        "dpkg -l linux-image-* 2>/dev/null | grep '^ii' | awk '{print $2}' | sort -V | tail -1"
    )

    # Tenta rpm (Fedora/RHEL)
    if not instalado:
        instalado = _rodar(
            "rpm -q kernel 2>/dev/null | sort -V | tail -1"
        )

    if not instalado:
        return {
            "modulo": "Updates",
            "controle_iso": "A.8.8",
            "funcao_nist": "Identify (ID.RA)",
            "descricao": "Kernel em execução atualizado",
            "status": "ATENÇÃO",
            "evidencia": f"Kernel em execução: {kernel_atual} — não foi possível comparar com o instalado",
            "remediacao": "Verificar se há atualizações de kernel pendentes",
        }

    return {
        "modulo": "Updates",
        "controle_iso": "A.8.8",
        "funcao_nist": "Identify (ID.RA)",
        "descricao": "Kernel em execução atualizado",
        "status": "CONFORME",
        "evidencia": f"Kernel em execução: {kernel_atual}",
        "remediacao": "Reiniciar o sistema após atualização do kernel se necessário",
    }


def verificar_pacotes_orfaos():
    """A.8.8 - Pacotes órfãos devem ser removidos para reduzir superfície de ataque."""
    # Tenta apt (Debian/Ubuntu)
    saida = _rodar("apt-get --dry-run autoremove 2>/dev/null | grep -c '^Remv'")
    if saida and saida.isdigit():
        quantidade = int(saida)
        if quantidade == 0:
            return {
                "modulo": "Updates",
                "controle_iso": "A.8.8",
                "funcao_nist": "Identify (ID.RA)",
                "descricao": "Sem pacotes órfãos ou resíduos",
                "status": "CONFORME",
                "evidencia": "Nenhum pacote órfão encontrado",
                "remediacao": "Nenhuma ação necessária",
            }
        return {
            "modulo": "Updates",
            "controle_iso": "A.8.8",
            "funcao_nist": "Identify (ID.RA)",
            "descricao": "Sem pacotes órfãos ou resíduos",
            "status": "NÃO CONFORME",
            "evidencia": f"{quantidade} pacote(s) órfão(s) encontrado(s)",
            "remediacao": "Executar: apt autoremove --purge",
        }

    # Tenta dnf (Fedora/RHEL)
    saida = _rodar("dnf list autoremove 2>/dev/null")
    if saida:
        pacotes = [l for l in saida.splitlines() if not l.startswith("Last") and l.strip()]
        if pacotes:
            return {
                "modulo": "Updates",
                "controle_iso": "A.8.8",
                "funcao_nist": "Identify (ID.RA)",
                "descricao": "Sem pacotes órfãos ou resíduos",
                "status": "NÃO CONFORME",
                "evidencia": f"{len(pacotes)} pacote(s) órfão(s) encontrado(s)",
                "remediacao": "Executar: dnf autoremove -y",
            }

    return {
        "modulo": "Updates",
        "controle_iso": "A.8.8",
        "funcao_nist": "Identify (ID.RA)",
        "descricao": "Sem pacotes órfãos ou resíduos",
        "status": "CONFORME",
        "evidencia": "Nenhum pacote órfão encontrado",
        "remediacao": "Nenhuma ação necessária",
    }