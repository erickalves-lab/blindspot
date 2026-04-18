"""
Engine de Comparação entre Execuções
======================================
Salva um snapshot dos scores após cada execução.
Na próxima execução, compara com o snapshot anterior
e calcula o delta de evolução por módulo.
"""

import json
import os
from datetime import datetime
from pathlib import Path


HISTORY_DIR = Path("reports/history")


def salvar_snapshot(scores, timestamp):
    """
    Salva o snapshot atual em reports/history/.

    Args:
        scores: dict {modulo: resultado do calcular_score}
        timestamp: string de timestamp
    """
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    arquivo = HISTORY_DIR / f"{timestamp}.json"

    dados = {
        "timestamp": timestamp,
        "data": datetime.now().strftime("%d/%m/%Y %H:%M"),
        "scores": scores,
    }

    with open(arquivo, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)


def carregar_ultimo_snapshot():
    """
    Carrega o snapshot mais recente de reports/history/.

    Returns:
        dict com dados do snapshot ou None se não houver histórico
    """
    if not HISTORY_DIR.exists():
        return None

    arquivos = sorted(HISTORY_DIR.glob("*.json"), reverse=True)
    if not arquivos:
        return None

    with open(arquivos[0], "r", encoding="utf-8") as f:
        return json.load(f)


def comparar(scores_atuais):
    """
    Compara scores atuais com o snapshot anterior.

    Args:
        scores_atuais: dict {modulo: resultado do calcular_score}

    Returns:
        dict {modulo: {score_anterior, score_atual, delta, tendencia}}
        ou None se não houver snapshot anterior
    """
    snapshot = carregar_ultimo_snapshot()
    if not snapshot:
        return None

    scores_anteriores = snapshot.get("scores", {})
    data_anterior = snapshot.get("data", "desconhecida")
    delta = {}

    for modulo, dados_atuais in scores_atuais.items():
        score_atual    = dados_atuais.get("score", 0)
        score_anterior = scores_anteriores.get(modulo, {}).get("score", 0)
        diferenca      = score_atual - score_anterior

        if diferenca > 0:
            tendencia = "\033[32m↑ Melhorou\033[0m"
        elif diferenca < 0:
            tendencia = "\033[31m↓ Regrediu\033[0m"
        else:
            tendencia = "\033[90m→ Sem alteração\033[0m"

        delta_texto = f"+{diferenca}" if diferenca > 0 else str(diferenca)

        delta[modulo] = {
            "score_anterior": score_anterior,
            "score_atual":    score_atual,
            "delta":          diferenca,
            "delta_texto":    delta_texto,
            "tendencia":      tendencia,
            "data_anterior":  data_anterior,
        }

    return delta