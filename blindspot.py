#!/usr/bin/env python3
"""
BlindSpot - Framework de Auditoria de Segurança
================================================
Verifica conformidade de ambientes Linux com ISO 27001:2022, NIST CSF e LGPD.
"""

import os
import sys


BANNER = """
\033[34m
  ██████╗ ██╗     ██╗███╗   ██╗██████╗ ███████╗██████╗  ██████╗ ████████╗
  ██╔══██╗██║     ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔═══██╗╚══██╔══╝
  ██████╔╝██║     ██║██╔██╗ ██║██║  ██║███████╗██████╔╝██║   ██║   ██║
  ██╔══██╗██║     ██║██║╚██╗██║██║  ██║╚════██║██╔═══╝ ██║   ██║   ██║
  ██████╔╝███████╗██║██║ ╚████║██████╔╝███████║██║     ╚██████╔╝   ██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝      ╚═════╝    ╚═╝
\033[0m
\033[36m         Framework de Auditoria de Segurança para Linux\033[0m
\033[90m         ISO 27001:2022  |  NIST CSF  |  LGPD\033[0m
"""

MENU = """
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
\033[1m  SELECIONE O MÓDULO PARA AUDITAR\033[0m
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m

  \033[36m[1]\033[0m  IAM          — Identidades e Acessos
  \033[36m[2]\033[0m  SSH          — Configuração do Servidor
  \033[36m[3]\033[0m  Network      — Rede e Firewall
  \033[36m[4]\033[0m  Filesystem   — Permissões e Arquivos
  \033[36m[5]\033[0m  Logs         — Auditoria e Retenção
  \033[36m[6]\033[0m  Updates      — Patches e Atualizações
  \033[36m[7]\033[0m  LGPD         — Privacidade e Dados Pessoais
  \033[36m[8]\033[0m  Todos os módulos

\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
  \033[90m[0]  Sair\033[0m
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
"""

MODULOS = {
    "1": ("IAM",        "modules.iam"),
    "2": ("SSH",        "modules.ssh"),
    "3": ("Network",    "modules.network"),
    "4": ("Filesystem", "modules.filesystem"),
    "5": ("Logs",       "modules.logs"),
    "6": ("Updates",    "modules.updates"),
    "7": ("LGPD",       "modules.lgpd"),
}


def limpar():
    os.system("clear")


def exibir_resultado(verificacao):
    """Exibe o resultado de uma verificação de forma visual e limpa."""
    icons = {
        "CONFORME":     "\033[32m✅ CONFORME\033[0m",
        "NÃO CONFORME": "\033[31m❌ NÃO CONFORME\033[0m",
        "ATENÇÃO":      "\033[33m⚠️  ATENÇÃO\033[0m",
    }

    status = verificacao.get("status", "")
    status_exibido = icons.get(status, status)

    print("\n\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print(f"  \033[1mVERIFICAÇÃO:\033[0m {verificacao.get('descricao', '')}")
    print("\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print(f"  Módulo      {verificacao.get('modulo', '')}")
    print(f"  Controle    {verificacao.get('controle_iso', '')}")
    print(f"  NIST CSF    {verificacao.get('funcao_nist', '')}")
    print(f"  Status      {status_exibido}")
    print(f"  Evidência   {verificacao.get('evidencia', '')}")
    print(f"  Remediação  {verificacao.get('remediacao', '')}")
    print("\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")


def rodar_modulo(nome, caminho):
    """Importa e executa um módulo de auditoria."""
    import importlib
    limpar()
    print(BANNER)
    print(f"\033[36m  Executando módulo: {nome}...\033[0m\n")

    try:
        modulo = importlib.import_module(caminho)
        verificacoes = modulo.executar()
        for v in verificacoes:
            exibir_resultado(v)

        # Resumo do módulo
        conformes   = sum(1 for v in verificacoes if v["status"] == "CONFORME")
        nao_conf    = sum(1 for v in verificacoes if v["status"] == "NÃO CONFORME")
        atencao     = sum(1 for v in verificacoes if v["status"] == "ATENÇÃO")
        total       = len(verificacoes)

        print(f"""
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
  \033[1mRESUMO DO MÓDULO {nome.upper()}\033[0m
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
  Total de verificações  {total}
  \033[32mConformes\033[0m              {conformes}
  \033[31mNão conformes\033[0m          {nao_conf}
  \033[33mAtenção\033[0m                {atencao}
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
""")

    except Exception as e:
        print(f"\033[31m  Erro ao executar módulo {nome}: {e}\033[0m")

    print("\n  O que deseja fazer agora?")
    print("  \033[36m[1]\033[0m  Voltar ao menu principal")
    print("  \033[36m[0]\033[0m  Sair")
    print()
    opcao = input("  Escolha: ").strip()

    if opcao == "0":
        encerrar()


def rodar_todos():
    """Executa todos os módulos em sequência."""
    import importlib
    limpar()
    print(BANNER)
    print("\033[36m  Executando todos os módulos...\033[0m\n")

    for chave, (nome, caminho) in MODULOS.items():
        try:
            modulo = importlib.import_module(caminho)
            verificacoes = modulo.executar()
            conformes = sum(1 for v in verificacoes if v["status"] == "CONFORME")
            total = len(verificacoes)
            print(f"  \033[36m[✔]\033[0m {nome:<12} — {total} verificações | {conformes} conformes")
        except Exception as e:
            print(f"  \033[31m[✘]\033[0m {nome:<12} — Erro: {e}")

    print(f"\n\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print("\n  O que deseja fazer agora?")
    print("  \033[36m[1]\033[0m  Voltar ao menu principal")
    print("  \033[36m[0]\033[0m  Sair")
    print()
    opcao = input("  Escolha: ").strip()

    if opcao == "0":
        encerrar()


def encerrar():
    limpar()
    print(BANNER)
    print("\033[36m  Auditoria encerrada. Até a próxima.\033[0m\n")
    sys.exit(0)


def main():
    while True:
        limpar()
        print(BANNER)
        print(MENU)

        opcao = input("  Escolha uma opção: ").strip()

        if opcao == "0":
            encerrar()
        elif opcao == "8":
            rodar_todos()
        elif opcao in MODULOS:
            nome, caminho = MODULOS[opcao]
            rodar_modulo(nome, caminho)
        else:
            input("\n  \033[31mOpção inválida.\033[0m Pressione Enter para continuar...")


if __name__ == "__main__":
    main()