"""
Engine de Score de Maturidade
===============================
Calcula o score de maturidade (0–3) por módulo
com base no percentual de verificações conformes.

Escala:
    3 — Gerenciado   (≥ 80%)
    2 — Definido     (50% – 79%)
    1 — Inicial      (25% – 49%)
    0 — Inexistente  (< 25%)
"""


ESCALA = [
    (0.80, 3, "Gerenciado"),
    (0.50, 2, "Definido"),
    (0.25, 1, "Inicial"),
    (0.00, 0, "Inexistente"),
]


def calcular_score(verificacoes):
    """
    Calcula o score de maturidade de um módulo.

    Args:
        verificacoes: lista de dicts com campo 'status'

    Returns:
        dict com score, nivel, percentual, conformes,
        nao_conformes, atencao e total
    """
    if not verificacoes:
        return {
            "score": 0,
            "nivel": "Inexistente",
            "percentual": 0.0,
            "conformes": 0,
            "nao_conformes": 0,
            "atencao": 0,
            "total": 0,
        }

    conformes    = sum(1 for v in verificacoes if v["status"] == "CONFORME")
    nao_conformes = sum(1 for v in verificacoes if v["status"] == "NÃO CONFORME")
    atencao      = sum(1 for v in verificacoes if v["status"] == "ATENÇÃO")
    total        = len(verificacoes)
    percentual   = conformes / total

    score = 0
    nivel = "Inexistente"
    for limite, s, n in ESCALA:
        if percentual >= limite:
            score = s
            nivel = n
            break

    return {
        "score": score,
        "nivel": nivel,
        "percentual": round(percentual * 100, 1),
        "conformes": conformes,
        "nao_conformes": nao_conformes,
        "atencao": atencao,
        "total": total,
    }


def calcular_score_geral(scores):
    """
    Calcula o score geral ponderado do ambiente.

    Args:
        scores: dict {nome_modulo: resultado do calcular_score}

    Returns:
        dict com score_geral (float) e nivel_geral (str)
    """
    if not scores:
        return {"score_geral": 0.0, "nivel_geral": "Inexistente"}

    valores = [s["score"] for s in scores.values()]
    score_geral = round(sum(valores) / len(valores), 1)

    nivel_geral = "Inexistente"
    for limite, _, nivel in ESCALA:
        if score_geral / 3 >= limite:
            nivel_geral = nivel
            break

    return {
        "score_geral": score_geral,
        "nivel_geral": nivel_geral,
    }