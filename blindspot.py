#!/usr/bin/env python3
"""
BlindSpot — Framework de Auditoria de Segurança
================================================
Verifica conformidade de ambientes Linux com ISO 27001:2022, NIST CSF e LGPD.
Gera score de maturidade por módulo e relatório Excel estruturado.

Uso:
    python3 blindspot.py
    python3 blindspot.py --modules iam,ssh
    python3 blindspot.py --output relatorio.xlsx
    python3 blindspot.py --compare
"""

import argparse
import sys
from datetime import datetime

BANNER = """
╔══════════════════════════════════════════════════════════╗
║         BlindSpot | Auditoria de Segurança               ║
║         ISO 27001:2022 | NIST CSF | LGPD                 ║
╚══════════════════════════════════════════════════════════╝
"""

MODULOS_DISPONIVEIS = [
    "iam",
    "ssh",
    "network",
    "filesystem",
    "logs",
    "updates",
    "lgpd",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="BlindSpot — Auditoria de conformidade para Linux"
    )
    parser.add_argument(
        "--modules", "-m",
        type=str,
        default=None,
        help="Módulos a executar (ex: iam,ssh). Padrão: todos."
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Nome do arquivo Excel de saída."
    )
    parser.add_argument(
        "--compare", "-c",
        action="store_true",
        help="Comparar com a execução anterior."
    )
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()
    print("BlindSpot iniciado.")
    print(f"Módulos selecionados: {args.modules or 'todos'}")


if __name__ == "__main__":
    main()


def exibir_resultado(verificacao):
    """Exibe o resultado de uma verificação de forma limpa."""
    icons = {
        "CONFORME":     "✅ CONFORME",
        "NÃO CONFORME": "❌ NÃO CONFORME",
        "ATENÇÃO":      "⚠️  ATENÇÃO",
    }

    status = verificacao.get("status", "")
    status_exibido = icons.get(status, status)

    print("\n" + "━" * 50)
    print(f" VERIFICAÇÃO: {verificacao.get('descricao', '')}")
    print("━" * 50)
    print(f" Módulo      {verificacao.get('modulo', '')}")
    print(f" Controle    {verificacao.get('controle_iso', '')}")
    print(f" NIST CSF    {verificacao.get('funcao_nist', '')}")
    print(f" Status      {status_exibido}")
    print(f" Evidência   {verificacao.get('evidencia', '')}")
    print(f" Remediação  {verificacao.get('remediacao', '')}")
    print("━" * 50)