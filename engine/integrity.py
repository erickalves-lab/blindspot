"""
Verificação de Integridade dos Arquivos do Projeto
=====================================================
Calcula hashes SHA-256 dos arquivos do projeto na primeira execução
e verifica nas execuções seguintes se algo foi modificado.
"""

import hashlib
import json
import os
from pathlib import Path


HASH_FILE = Path(".blindspot_integrity.json")

ARQUIVOS_MONITORADOS = [
    "blindspot.py",
    "modules/iam.py",
    "modules/ssh.py",
    "modules/network.py",
    "modules/filesystem.py",
    "modules/logs.py",
    "modules/updates.py",
    "modules/lgpd.py",
    "engine/scorer.py",
    "engine/comparator.py",
    "engine/integrity.py",
    "reports/report_engine.py",
]


def calcular_hash(caminho):
    """Calcula o hash SHA-256 de um arquivo."""
    sha256 = hashlib.sha256()
    try:
        with open(caminho, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


def gerar_baseline():
    """
    Gera o arquivo de referência com os hashes atuais.
    Chamado na primeira execução ou quando o administrador
    confirma que o código está íntegro.
    """
    hashes = {}
    for arquivo in ARQUIVOS_MONITORADOS:
        h = calcular_hash(arquivo)
        if h:
            hashes[arquivo] = h

    with open(HASH_FILE, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=2)

    os.chmod(HASH_FILE, 0o600)
    return hashes


def verificar_integridade():
    """
    Verifica se os arquivos do projeto foram modificados
    desde a última execução.

    Returns:
        dict com status, modificados e ausentes
    """
    if not HASH_FILE.exists():
        return {
            "status": "primeira_execucao",
            "modificados": [],
            "ausentes": [],
        }

    with open(HASH_FILE, "r", encoding="utf-8") as f:
        hashes_referencia = json.load(f)

    modificados = []
    ausentes = []

    for arquivo, hash_ref in hashes_referencia.items():
        if not os.path.exists(arquivo):
            ausentes.append(arquivo)
            continue
        hash_atual = calcular_hash(arquivo)
        if hash_atual != hash_ref:
            modificados.append(arquivo)

    if modificados or ausentes:
        return {
            "status": "comprometido",
            "modificados": modificados,
            "ausentes": ausentes,
        }

    return {
        "status": "integro",
        "modificados": [],
        "ausentes": [],
    }