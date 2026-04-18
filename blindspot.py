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
  \033[36m[9]\033[0m  Gerar relatório Excel

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
    from engine.scorer import calcular_score

    limpar()
    print(BANNER)
    print(f"\033[36m  Executando módulo: {nome}...\033[0m\n")

    try:
        modulo = importlib.import_module(caminho)
        verificacoes = modulo.executar()
        for v in verificacoes:
            exibir_resultado(v)

        score = calcular_score(verificacoes)

        print(f"""
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
  \033[1mRESUMO DO MÓDULO {nome.upper()}\033[0m
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
  Total de verificações  {score['total']}
  \033[32mConformes\033[0m              {score['conformes']}
  \033[31mNão conformes\033[0m          {score['nao_conformes']}
  \033[33mAtenção\033[0m                {score['atencao']}
  Conformidade           {score['percentual']}%
  Score de maturidade    {score['score']} / 3 — {score['nivel']}
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
    from datetime import datetime
    from engine.scorer import calcular_score, calcular_score_geral
    from engine.comparator import salvar_snapshot, comparar

    limpar()
    print(BANNER)
    print("\033[36m  Executando todos os módulos...\033[0m\n")

    scores = {}

    for chave, (nome, caminho) in MODULOS.items():
        try:
            modulo = importlib.import_module(caminho)
            verificacoes = modulo.executar()
            score = calcular_score(verificacoes)
            scores[nome] = score

            barra = "\033[32m✅\033[0m" if score["score"] >= 2 else "\033[31m❌\033[0m" if score["score"] == 0 else "\033[33m⚠️\033[0m"
            print(f"  {barra} {nome:<12} — {score['total']} verificações | {score['conformes']} conformes | Score: {score['score']}/3 ({score['nivel']})")
        except Exception as e:
            print(f"  \033[31m[✘]\033[0m {nome:<12} — Erro: {e}")

    # Score geral
    geral = calcular_score_geral(scores)
    print(f"""
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
  \033[1mSCORE GERAL DO AMBIENTE\033[0m
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
  Score geral    {geral['score_geral']} / 3.0
  Maturidade     {geral['nivel_geral']}
\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
""")

    # Comparação com execução anterior
    delta = comparar(scores)
    if delta:
        print("\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
        print(f"  \033[1mCOMPARAÇÃO COM EXECUÇÃO ANTERIOR\033[0m")
        print(f"\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
        for modulo, dados in delta.items():
            print(f"  {modulo:<12} {dados['score_anterior']} → {dados['score_atual']} ({dados['delta_texto']:>3})   {dados['tendencia']}")
        print(f"\033[34m  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n")
    else:
        print("  \033[90m  Primeira execução — nenhum histórico disponível para comparação.\033[0m\n")

    # Salva snapshot
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    salvar_snapshot(scores, timestamp)
    print(f"  \033[90mSnapshot salvo em reports/history/{timestamp}.json\033[0m\n")

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

def gerar_relatorio_excel():
    """Roda todos os módulos e gera relatório Excel."""
    import importlib
    from datetime import datetime
    from engine.scorer import calcular_score, calcular_score_geral
    from engine.comparator import salvar_snapshot, comparar
    from reports.report_engine import gerar_relatorio

    limpar()
    print(BANNER)
    print("\033[36m  Coletando dados para o relatório...\033[0m\n")

    resultados = {}
    scores = {}

    for chave, (nome, caminho) in MODULOS.items():
        try:
            modulo = importlib.import_module(caminho)
            verificacoes = modulo.executar()
            resultados[nome] = verificacoes
            scores[nome] = calcular_score(verificacoes)
            print(f"  \033[36m[✔]\033[0m {nome}")
        except Exception as e:
            print(f"  \033[31m[✘]\033[0m {nome} — Erro: {e}")

    score_geral = calcular_score_geral(scores)
    delta = comparar(scores)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"reports/output/blindspot_{timestamp}.xlsx"

    print(f"\n\033[36m  Gerando relatório Excel...\033[0m")
    sucesso = gerar_relatorio(resultados, scores, score_geral, delta, output_file)

    if sucesso:
        salvar_snapshot(scores, timestamp)
        print(f"\n\033[32m  Relatório gerado com sucesso!\033[0m")
        print(f"  \033[90m{output_file}\033[0m\n")
    else:
        print(f"\n\033[31m  Falha ao gerar relatório.\033[0m\n")

    print("\n  O que deseja fazer agora?")
    print("  \033[36m[1]\033[0m  Voltar ao menu principal")
    print("  \033[36m[0]\033[0m  Sair")
    print()
    opcao = input("  Escolha: ").strip()

    if opcao == "0":
        encerrar()

def verificar_integridade_projeto():
    """Verifica integridade dos arquivos antes de iniciar."""
    from engine.integrity import verificar_integridade, gerar_baseline

    resultado = verificar_integridade()

    if resultado["status"] == "primeira_execucao":
        print("\033[36m  Primeira execução — gerando baseline de integridade...\033[0m")
        gerar_baseline()
        print("\033[32m  Baseline gerado. Arquivos do projeto registrados.\033[0m\n")
        return True

    if resultado["status"] == "comprometido":
        print("\033[31m")
        print("  ⚠️  ALERTA DE INTEGRIDADE")
        print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        if resultado["modificados"]:
            print("  Arquivos modificados desde a última execução:")
            for f in resultado["modificados"]:
                print(f"    • {f}")
        if resultado["ausentes"]:
            print("  Arquivos ausentes:")
            for f in resultado["ausentes"]:
                print(f"    • {f}")
        print("\033[0m")
        print("  O que deseja fazer?")
        print("  \033[36m[1]\033[0m  Continuar mesmo assim (risco)")
        print("  \033[36m[2]\033[0m  Atualizar baseline (confirmo que as mudanças são legítimas)")
        print("  \033[36m[0]\033[0m  Sair")
        print()
        opcao = input("  Escolha: ").strip()

        if opcao == "2":
            gerar_baseline()
            print("\033[32m  Baseline atualizado.\033[0m\n")
            return True
        elif opcao == "1":
            print("\033[33m  Continuando com arquivos modificados...\033[0m\n")
            return True
        else:
            encerrar()

    return True

def main():
    verificar_integridade_projeto()
    limpar()
    print(BANNER)

    while True:
        limpar()
        print(BANNER)
        print(MENU)

        opcao = input("  Escolha uma opção: ").strip()

        if opcao == "0":
            encerrar()
        elif opcao == "8":
            rodar_todos()
        elif opcao == "9":
            gerar_relatorio_excel()
        elif opcao in MODULOS:
            nome, caminho = MODULOS[opcao]
            rodar_modulo(nome, caminho)
        else:
            input("\n  \033[31mOpção inválida.\033[0m Pressione Enter para continuar...")


if __name__ == "__main__":
    main()