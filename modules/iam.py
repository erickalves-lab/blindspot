"""
Módulo IAM - Identidades e Acessos
====================================
Controles: ISO 27001 A.5.15, A.5.18, A.8.2, A.8.5
Função NIST CSF: Identify (ID.AM), Protect (PR.AC)
"""

import subprocess


def executar():
    """Executa todas as verificações do módulo e retorna lista de resultados."""
    return [
        verificar_root_login_direto(),
        verificar_contas_sem_senha(),
        verificar_usuarios_sudo(),
        verificar_contas_inativas(),
        verificar_politica_senha(),
        verificar_grupos_privilegiados(),
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


def verificar_root_login_direto():
    """A.8.5 - Usuário root não deve ter login direto habilitado."""
    saida = _rodar("grep '^root:' /etc/passwd")

    if not saida:
        return {
            "modulo": "IAM",
            "controle_iso": "A.8.5",
            "funcao_nist": "Protect (PR.AC)",
            "descricao": "Login direto do usuário root desabilitado",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler /etc/passwd",
            "remediacao": "Verificar permissões do arquivo /etc/passwd",
        }

    shell = saida.split(":")[-1]
    shells_bloqueados = ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin"]
    conforme = shell in shells_bloqueados

    return {
        "modulo": "IAM",
        "controle_iso": "A.8.5",
        "funcao_nist": "Protect (PR.AC)",
        "descricao": "Login direto do usuário root desabilitado",
        "status": "CONFORME" if conforme else "NÃO CONFORME",
        "evidencia": f"Shell do root: {shell}",
        "remediacao": "Definir shell do root como /usr/sbin/nologin em /etc/passwd",
    }


def verificar_contas_sem_senha():
    """A.5.15 - Contas de usuário não devem existir sem senha definida."""
    saida = _rodar("sudo awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow")

    if not saida:
        return {
            "modulo": "IAM",
            "controle_iso": "A.5.15",
            "funcao_nist": "Protect (PR.AC)",
            "descricao": "Contas de usuário sem senha definida",
            "status": "CONFORME",
            "evidencia": "Nenhuma conta sem senha encontrada",
            "remediacao": "Nenhuma ação necessária",
        }

    contas = saida.splitlines()
    return {
        "modulo": "IAM",
        "controle_iso": "A.5.15",
        "funcao_nist": "Protect (PR.AC)",
        "descricao": "Contas de usuário sem senha definida",
        "status": "NÃO CONFORME",
        "evidencia": f"Contas sem senha: {', '.join(contas)}",
        "remediacao": "Definir senha ou desabilitar as contas identificadas",
    }

def verificar_usuarios_sudo():
    """A.8.2 - Acesso privilegiado deve ser controlado e justificado."""
    saida = _rodar("grep -E '^(sudo|wheel):' /etc/group")

    if not saida:
        return {
            "modulo": "IAM",
            "controle_iso": "A.8.2",
            "funcao_nist": "Protect (PR.AC)",
            "descricao": "Usuários com privilégios sudo controlados",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível ler os grupos do sistema",
            "remediacao": "Verificar permissões do arquivo /etc/group",
        }

    usuarios = []
    for linha in saida.splitlines():
        membros = linha.split(":")[-1]
        if membros:
            usuarios.extend(membros.split(","))

    usuarios = [u.strip() for u in usuarios if u.strip()]

    if not usuarios:
        return {
            "modulo": "IAM",
            "controle_iso": "A.8.2",
            "funcao_nist": "Protect (PR.AC)",
            "descricao": "Usuários com privilégios sudo controlados",
            "status": "CONFORME",
            "evidencia": "Nenhum usuário no grupo sudo ou wheel",
            "remediacao": "Nenhuma ação necessária",
        }

    return {
        "modulo": "IAM",
        "controle_iso": "A.8.2",
        "funcao_nist": "Protect (PR.AC)",
        "descricao": "Usuários com privilégios sudo controlados",
        "status": "ATENÇÃO",
        "evidencia": f"Usuários com sudo: {', '.join(usuarios)}",
        "remediacao": "Confirmar se todos os usuários listados têm justificativa para acesso privilegiado",
    }

def verificar_contas_inativas():
    """A.5.18 - Contas inativas devem ser revogadas após período definido."""
    saida_passwd = _rodar(
        "awk -F: '($3 >= 1000 && $7 !~ /nologin|false/) {print $1}' /etc/passwd"
    )
    saida_lastlog = _rodar("lastlog")

    if not saida_passwd or not saida_lastlog:
        return {
            "modulo": "IAM",
            "controle_iso": "A.5.18",
            "funcao_nist": "Identify (ID.AM)",
            "descricao": "Revisão de contas humanas — inativas e sem uso",
            "status": "ATENÇÃO",
            "evidencia": "Não foi possível verificar contas do sistema",
            "remediacao": "Verificar permissões dos arquivos /etc/passwd e lastlog",
        }

    from datetime import datetime, timedelta
    limite = datetime.now() - timedelta(days=30)

    contas_humanas = saida_passwd.splitlines()
    nunca_logaram = []
    inativas = []
    ativas = []

    ultimos_logins = {}
    for linha in saida_lastlog.splitlines()[1:]:
        partes = linha.split()
        if not partes:
            continue
        usuario = partes[0]
        if "Never" in linha:
            ultimos_logins[usuario] = None
        else:
            try:
                data_str = " ".join(partes[-4:-1])
                data_login = datetime.strptime(data_str, "%b %d %H:%M")
                data_login = data_login.replace(year=datetime.now().year)
                ultimos_logins[usuario] = data_login
            except Exception:
                ultimos_logins[usuario] = None

    for conta in contas_humanas:
        ultimo = ultimos_logins.get(conta)
        if ultimo is None:
            nunca_logaram.append(conta)
        elif ultimo < limite:
            inativas.append(conta)
        else:
            ativas.append(conta)

    # Monta evidência clara separando os três casos
    partes_evidencia = []
    partes_evidencia.append(
        f"Contas ativas: {', '.join(ativas) if ativas else 'nenhuma'}"
    )
    partes_evidencia.append(
        f"Inativas há +30 dias: {', '.join(inativas) if inativas else 'nenhuma'}"
    )
    partes_evidencia.append(
        f"Nunca logaram: {', '.join(nunca_logaram) if nunca_logaram else 'nenhuma'}"
    )

    if inativas:
        status = "NÃO CONFORME"
    elif nunca_logaram:
        status = "ATENÇÃO"
    else:
        status = "CONFORME"

    return {
        "modulo": "IAM",
        "controle_iso": "A.5.18",
        "funcao_nist": "Identify (ID.AM)",
        "descricao": "Revisão de contas humanas — inativas e sem uso",
        "status": status,
        "evidencia": " | ".join(partes_evidencia),
        "remediacao": "Revisar contas inativas e nunca utilizadas — desabilitar ou remover as desnecessárias",
    }

def verificar_politica_senha():
    """A.5.15 - Política de senha deve exigir complexidade mínima."""
    saida = _rodar("grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/common-password")

    if not saida:
        return {
            "modulo": "IAM",
            "controle_iso": "A.5.15",
            "funcao_nist": "Protect (PR.AC)",
            "descricao": "Política de senha com complexidade configurada",
            "status": "NÃO CONFORME",
            "evidencia": "pam_pwquality não encontrado em /etc/pam.d/common-password",
            "remediacao": "Instalar libpam-pwquality e configurar minlen=12 retry=3",
        }

    # Verifica comprimento mínimo
    minlen = None
    for parte in saida.split():
        if parte.startswith("minlen="):
            try:
                minlen = int(parte.split("=")[1])
            except ValueError:
                pass

    if minlen is None:
        return {
            "modulo": "IAM",
            "controle_iso": "A.5.15",
            "funcao_nist": "Protect (PR.AC)",
            "descricao": "Política de senha com complexidade configurada",
            "status": "ATENÇÃO",
            "evidencia": "pam_pwquality presente mas minlen não definido explicitamente",
            "remediacao": "Adicionar minlen=12 na configuração do pam_pwquality",
        }

    if minlen < 12:
        return {
            "modulo": "IAM",
            "controle_iso": "A.5.15",
            "funcao_nist": "Protect (PR.AC)",
            "descricao": "Política de senha com complexidade configurada",
            "status": "NÃO CONFORME",
            "evidencia": f"Comprimento mínimo configurado: {minlen} caracteres (mínimo exigido: 12)",
            "remediacao": "Alterar minlen para 12 ou mais em /etc/pam.d/common-password",
        }

    return {
        "modulo": "IAM",
        "controle_iso": "A.5.15",
        "funcao_nist": "Protect (PR.AC)",
        "descricao": "Política de senha com complexidade configurada",
        "status": "CONFORME",
        "evidencia": f"pam_pwquality ativo com minlen={minlen}",
        "remediacao": "Nenhuma ação necessária",
    }

def verificar_grupos_privilegiados():
    """A.8.2 - Grupos privilegiados devem conter apenas membros autorizados."""
    grupos = ["sudo", "adm", "shadow", "disk"]
    encontrados = {}

    for grupo in grupos:
        saida = _rodar(f"grep '^{grupo}:' /etc/group")
        if not saida:
            continue
        membros = saida.split(":")[-1]
        if membros:
            lista = [m.strip() for m in membros.split(",") if m.strip()]
            if lista:
                encontrados[grupo] = lista

    if not encontrados:
        return {
            "modulo": "IAM",
            "controle_iso": "A.8.2",
            "funcao_nist": "Protect (PR.AC)",
            "descricao": "Grupos privilegiados com membros controlados",
            "status": "CONFORME",
            "evidencia": "Nenhum membro encontrado em grupos privilegiados",
            "remediacao": "Nenhuma ação necessária",
        }

    evidencia = " | ".join(
        f"{grupo}: {', '.join(membros)}"
        for grupo, membros in encontrados.items()
    )

    return {
        "modulo": "IAM",
        "controle_iso": "A.8.2",
        "funcao_nist": "Protect (PR.AC)",
        "descricao": "Grupos privilegiados com membros controlados",
        "status": "ATENÇÃO",
        "evidencia": evidencia,
        "remediacao": "Confirmar se todos os membros listados têm justificativa para estar nesses grupos",
    }