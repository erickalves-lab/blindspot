"""
Módulo Filesystem - Permissões e Arquivos Sensíveis
=====================================================
Controles: ISO 27001 A.5.12, A.5.13, A.8.3
Função NIST CSF: Protect (PR.DS)
"""

import subprocess


def executar():
    """Executa todas as verificações do módulo e retorna lista de resultados."""
    return [
        verificar_suid_sgid(),
        verificar_world_writable(),
        verificar_arquivos_sensiveis(),
        verificar_diretorios_home(),
        verificar_configs_servicos(),
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

def verificar_suid_sgid():
    """A.8.3 - Arquivos SUID/SGID não justificados representam risco de escalonamento."""
    saida = _rodar("find / -xdev -perm /6000 -type f 2>/dev/null")

    if not saida:
        return {
            "modulo": "Filesystem",
            "controle_iso": "A.8.3",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Arquivos SUID/SGID não justificados ausentes",
            "status": "CONFORME",
            "evidencia": "Nenhum arquivo SUID/SGID encontrado",
            "remediacao": "Nenhuma ação necessária",
        }

    # Binários SUID/SGID esperados e legítimos
    permitidos = [
        "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su",
        "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/umount",
        "/usr/bin/pkexec", "/usr/sbin/unix_chkpwd",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/bin/passwd", "/bin/sudo", "/bin/su", "/bin/mount", "/bin/umount",
        "/sbin/unix_chkpwd",
    ]

    todos = saida.splitlines()
    suspeitos = [f for f in todos if f not in permitidos]

    evidencia = (
        f"{len(todos)} arquivo(s) SUID/SGID encontrado(s) | "
        f"Suspeitos: {', '.join(suspeitos) if suspeitos else 'nenhum'}"
    )

    return {
        "modulo": "Filesystem",
        "controle_iso": "A.8.3",
        "funcao_nist": "Protect (PR.DS)",
        "descricao": "Arquivos SUID/SGID não justificados ausentes",
        "status": "NÃO CONFORME" if suspeitos else "CONFORME",
        "evidencia": evidencia,
        "remediacao": "Remover bit SUID/SGID de binários não essenciais com chmod u-s <arquivo>",
    }

def verificar_world_writable():
    """A.5.12 — Diretórios críticos não devem ter permissão de escrita pública."""
    saida = _rodar("find / -xdev -type d -perm -0002 2>/dev/null")

    if not saida:
        return {
            "modulo": "Filesystem",
            "controle_iso": "A.5.12",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Diretórios críticos sem permissão world-writable",
            "status": "CONFORME",
            "evidencia": "Nenhum diretório world-writable encontrado",
            "remediacao": "Nenhuma ação necessária",
        }

    # Diretórios world-writable esperados e legítimos
    permitidos = [
        "/tmp", "/var/tmp", "/run/lock",
        "/dev/mqueue", "/dev/shm",
    ]

    todos = saida.splitlines()
    suspeitos = [d for d in todos if not any(d.startswith(p) for p in permitidos)]

    evidencia = (
        f"{len(todos)} diretório(s) world-writable | "
        f"Suspeitos: {', '.join(suspeitos) if suspeitos else 'nenhum'}"
    )

    return {
        "modulo": "Filesystem",
        "controle_iso": "A.5.12",
        "funcao_nist": "Protect (PR.DS)",
        "descricao": "Diretórios críticos sem permissão world-writable",
        "status": "NÃO CONFORME" if suspeitos else "CONFORME",
        "evidencia": evidencia,
        "remediacao": "Corrigir permissões com chmod o-w nos diretórios identificados",
    }


def verificar_arquivos_sensiveis():
    """A.5.13 — Arquivos sensíveis devem ter permissões restritivas."""
    arquivos = {
        "/etc/shadow":  {"max_perm": "640", "esperado": "root:shadow"},
        "/etc/passwd":  {"max_perm": "644", "esperado": "root:root"},
        "/etc/gshadow": {"max_perm": "640", "esperado": "root:shadow"},
        "/etc/group":   {"max_perm": "644", "esperado": "root:root"},
    }

    problemas = []
    ok = []

    for arquivo, config in arquivos.items():
        saida = _rodar(f"stat -c '%a %U:%G' {arquivo} 2>/dev/null")
        if not saida:
            problemas.append(f"{arquivo}: não encontrado")
            continue

        partes = saida.split()
        if len(partes) < 2:
            continue

        perm = partes[0]
        dono = partes[1]

        if int(perm) > int(config["max_perm"]):
            problemas.append(f"{arquivo}: permissão {perm} (máximo: {config['max_perm']})")
        else:
            ok.append(arquivo)

    if not problemas:
        return {
            "modulo": "Filesystem",
            "controle_iso": "A.5.13",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Arquivos sensíveis com permissões corretas",
            "status": "CONFORME",
            "evidencia": f"Arquivos verificados: {', '.join(ok)}",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "Filesystem",
        "controle_iso": "A.5.13",
        "funcao_nist": "Protect (PR.DS)",
        "descricao": "Arquivos sensíveis com permissões corretas",
        "status": "NÃO CONFORME",
        "evidencia": " | ".join(problemas),
        "remediacao": "Corrigir permissões: chmod 640 /etc/shadow && chmod 644 /etc/passwd",
    }


def verificar_diretorios_home():
    """A.5.12 - Diretórios home não devem ter permissões abertas."""
    saida = _rodar("find /home -maxdepth 1 -mindepth 1 -type d 2>/dev/null")

    if not saida:
        return {
            "modulo": "Filesystem",
            "controle_iso": "A.5.12",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Diretórios home com permissões restritivas",
            "status": "CONFORME",
            "evidencia": "Nenhum diretório home encontrado",
            "remediacao": "Nenhuma ação necessária",
        }

    problemas = []
    ok = []

    for diretorio in saida.splitlines():
        perm = _rodar(f"stat -c '%a' {diretorio} 2>/dev/null")
        if not perm:
            continue
        if int(perm) > 750:
            problemas.append(f"{diretorio}: {perm}")
        else:
            ok.append(diretorio)

    if not problemas:
        return {
            "modulo": "Filesystem",
            "controle_iso": "A.5.12",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Diretórios home com permissões restritivas",
            "status": "CONFORME",
            "evidencia": f"Diretórios verificados: {', '.join(ok)}",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "Filesystem",
        "controle_iso": "A.5.12",
        "funcao_nist": "Protect (PR.DS)",
        "descricao": "Diretórios home com permissões restritivas",
        "status": "NÃO CONFORME",
        "evidencia": f"Permissões abertas: {' | '.join(problemas)}",
        "remediacao": "Aplicar chmod 750 nos diretórios identificados",
    }


def verificar_configs_servicos():
    """A.5.13 - Arquivos de configuração de serviços não devem ser legíveis publicamente."""
    diretorios = [
        "/etc/mysql", "/etc/nginx", "/etc/apache2",
        "/etc/postgresql", "/etc/redis", "/etc/mongodb",
    ]

    problemas = []
    verificados = []

    for diretorio in diretorios:
        saida = _rodar(f"find {diretorio} -type f 2>/dev/null")
        if not saida:
            continue

        for arquivo in saida.splitlines():
            verificados.append(arquivo)
            perm = _rodar(f"stat -c '%a' {arquivo} 2>/dev/null")
            if not perm:
                continue
            if perm.endswith(("4", "5", "6", "7")):
                problemas.append(f"{arquivo}: {perm}")

    if not verificados:
        return {
            "modulo": "Filesystem",
            "controle_iso": "A.5.13",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Configurações de serviços sem leitura pública",
            "status": "CONFORME",
            "evidencia": "Nenhum serviço com configuração sensível encontrado",
            "remediacao": "Nenhuma ação necessária",
        }

    if not problemas:
        return {
            "modulo": "Filesystem",
            "controle_iso": "A.5.13",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Configurações de serviços sem leitura pública",
            "status": "CONFORME",
            "evidencia": f"{len(verificados)} arquivo(s) verificado(s) — permissões corretas",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "Filesystem",
        "controle_iso": "A.5.13",
        "funcao_nist": "Protect (PR.DS)",
        "descricao": "Configurações de serviços sem leitura pública",
        "status": "NÃO CONFORME",
        "evidencia": f"Arquivos com leitura pública: {' | '.join(problemas[:5])}",
        "remediacao": "Corrigir permissões: chmod o-r nos arquivos identificados",
    }