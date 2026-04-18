"""
Módulo LGPD - Privacidade e Dados Pessoais
============================================
Controles: LGPD Art. 46, 48, 49 | ISO 27001 A.5.34
Função NIST CSF: Protect (PR.DS), Respond (RS.CO)
"""

import subprocess
import os
import re


def executar():
    """Executa todas as verificações do módulo e retorna lista de resultados."""
    return [
        verificar_dados_expostos(),
        verificar_backups_expostos(),
        verificar_dados_em_logs(),
        verificar_criptografia_disco(),
        verificar_politica_retencao(),
    ]


def _rodar(cmd):
    import shlex
    try:
        args = cmd if isinstance(cmd, list) else shlex.split(cmd)
        resultado = subprocess.run(
            args, shell=False, capture_output=True, text=True, timeout=30
        )
        return resultado.stdout.strip()
    except Exception:
        return ""

def verificar_dados_expostos():
    """LGPD Art. 46 - Dados pessoais não devem estar expostos sem controle de acesso."""
    extensoes = ["*.csv", "*.json", "*.db", "*.sqlite", "*.xls", "*.xlsx"]
    diretorios = ["/home", "/tmp", "/var/www", "/srv"]

    expostos = []

    for diretorio in diretorios:
        if not os.path.exists(diretorio):
            continue
        for ext in extensoes:
            saida = _rodar(
                f"find {diretorio} -name '{ext}' -perm /o+r 2>/dev/null"
            )
            if saida:
                expostos.extend(saida.splitlines())

    if not expostos:
        return {
            "modulo": "LGPD",
            "controle_iso": "A.5.34 / LGPD Art. 46",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Arquivos com dados pessoais sem controle de acesso",
            "status": "CONFORME",
            "evidencia": "Nenhum arquivo de dados exposto publicamente encontrado",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "LGPD",
        "controle_iso": "A.5.34 / LGPD Art. 46",
        "funcao_nist": "Protect (PR.DS)",
        "descricao": "Arquivos com dados pessoais sem controle de acesso",
        "status": "NÃO CONFORME",
        "evidencia": f"{len(expostos)} arquivo(s) exposto(s): {', '.join(expostos[:3])}{'...' if len(expostos) > 3 else ''}",
        "remediacao": "Restringir acesso com chmod o-r nos arquivos identificados",
    }


def verificar_backups_expostos():
    """LGPD Art. 46 - Backups não devem estar em diretórios públicos."""
    extensoes = ["*.tar", "*.tar.gz", "*.zip", "*.bak", "*.sql", "*.dump"]
    diretorios_publicos = ["/tmp", "/var/www", "/srv", "/home"]

    encontrados = []

    for diretorio in diretorios_publicos:
        if not os.path.exists(diretorio):
            continue
        for ext in extensoes:
            saida = _rodar(
                f"find {diretorio} -name '{ext}' 2>/dev/null"
            )
            if saida:
                encontrados.extend(saida.splitlines())

    if not encontrados:
        return {
            "modulo": "LGPD",
            "controle_iso": "A.5.34 / LGPD Art. 46",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Arquivos de backup sem exposição em diretórios públicos",
            "status": "CONFORME",
            "evidencia": "Nenhum backup exposto em diretório público encontrado",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "LGPD",
        "controle_iso": "A.5.34 / LGPD Art. 46",
        "funcao_nist": "Protect (PR.DS)",
        "descricao": "Arquivos de backup sem exposição em diretórios públicos",
        "status": "NÃO CONFORME",
        "evidencia": f"{len(encontrados)} backup(s) em local inadequado: {', '.join(encontrados[:3])}",
        "remediacao": "Mover backups para diretório restrito e aplicar permissões adequadas",
    }


def verificar_dados_em_logs():
    """LGPD Art. 46 - Logs não devem conter dados pessoais em texto claro."""
    logs = [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/secure",
        "/var/log/messages",
    ]

    # Padrões de dados pessoais
    padroes = {
        "CPF":      r'\d{3}[\.\-]?\d{3}[\.\-]?\d{3}[\-]?\d{2}',
        "E-mail":   r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "Telefone": r'(\+55|55)?[\s\-]?\(?\d{2}\)?[\s\-]?\d{4,5}[\s\-]?\d{4}',
    }

    encontrados = []
    verificados = []

    for log in logs:
        if not os.path.exists(log):
            continue

        verificados.append(log)

        try:
            with open(log, "r", errors="ignore") as f:
                conteudo = f.read(50000)  # lê primeiros 50KB

            for tipo, padrao in padroes.items():
                if re.search(padrao, conteudo):
                    encontrados.append(f"{tipo} em {log}")
        except Exception:
            continue

    if not verificados:
        return {
            "modulo": "LGPD",
            "controle_iso": "A.5.34 / LGPD Art. 46",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Logs sem dados pessoais em texto claro",
            "status": "ATENÇÃO",
            "evidencia": "Nenhum arquivo de log encontrado para verificar",
            "remediacao": "Verificar configuração do serviço de logging",
        }

    if encontrados:
        return {
            "modulo": "LGPD",
            "controle_iso": "A.5.34 / LGPD Art. 46",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Logs sem dados pessoais em texto claro",
            "status": "NÃO CONFORME",
            "evidencia": f"Dados pessoais detectados: {' | '.join(encontrados)}",
            "remediacao": "Configurar mascaramento de dados pessoais nas aplicações",
        }

    return {
        "modulo": "LGPD",
        "controle_iso": "A.5.34 / LGPD Art. 46",
        "funcao_nist": "Protect (PR.DS)",
        "descricao": "Logs sem dados pessoais em texto claro",
        "status": "CONFORME",
        "evidencia": f"{len(verificados)} log(s) verificado(s) sem dados pessoais detectados",
        "remediacao": "Nenhuma ação necessária",
    }


def verificar_criptografia_disco():
    """LGPD Art. 46 - Dados pessoais devem ser protegidos por criptografia."""
    # Verifica LUKS
    luks = _rodar("lsblk -o NAME,TYPE 2>/dev/null | grep crypt")
    if luks:
        return {
            "modulo": "LGPD",
            "controle_iso": "A.5.34 / LGPD Art. 46",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Criptografia de disco configurada",
            "status": "CONFORME",
            "evidencia": f"Dispositivo(s) criptografado(s) com LUKS detectado(s)",
            "remediacao": "Nenhuma ação necessária",
        }

    # Verifica ecryptfs nos homes
    ecryptfs = _rodar("mount | grep ecryptfs")
    if ecryptfs:
        return {
            "modulo": "LGPD",
            "controle_iso": "A.5.34 / LGPD Art. 46",
            "funcao_nist": "Protect (PR.DS)",
            "descricao": "Criptografia de disco configurada",
            "status": "CONFORME",
            "evidencia": "Criptografia de diretório home via ecryptfs detectada",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "LGPD",
        "controle_iso": "A.5.34 / LGPD Art. 46",
        "funcao_nist": "Protect (PR.DS)",
        "descricao": "Criptografia de disco configurada",
        "status": "NÃO CONFORME",
        "evidencia": "Nenhuma criptografia de disco detectada (LUKS ou ecryptfs)",
        "remediacao": "Implementar LUKS para criptografia de disco completo",
    }


def verificar_politica_retencao():
    """LGPD Art. 15 - Dados pessoais devem ter política de retenção definida."""
    # Verifica se logrotate tem configuração de retenção
    logrotate = _rodar("grep -r 'rotate' /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null")

    if not logrotate:
        return {
            "modulo": "LGPD",
            "controle_iso": "A.5.34 / LGPD Art. 15",
            "funcao_nist": "Respond (RS.CO)",
            "descricao": "Política de retenção e descarte de dados configurada",
            "status": "NÃO CONFORME",
            "evidencia": "Nenhuma política de retenção encontrada via logrotate",
            "remediacao": "Definir política de retenção em /etc/logrotate.conf",
        }

    # Conta quantas configurações de rotate existem
    total = len([l for l in logrotate.splitlines() if "rotate" in l])

    return {
        "modulo": "LGPD",
        "controle_iso": "A.5.34 / LGPD Art. 15",
        "funcao_nist": "Respond (RS.CO)",
        "descricao": "Política de retenção e descarte de dados configurada",
        "status": "CONFORME",
        "evidencia": f"{total} configuração(ões) de retenção encontrada(s) via logrotate",
        "remediacao": "Nenhuma ação necessária",
    }