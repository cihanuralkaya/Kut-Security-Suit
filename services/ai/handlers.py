"""KUT AI servisi — SAF mantık (deterministik heuristik iskelet).

Bu modül, `server/internal/aibrain/httpprovider.go`'nun beklediği sözleşmeyi karşılar:
her istek gövdesini (dict) alıp yanıt gövdesini (dict) üretir. Şimdilik GERÇEK bir LLM
YOKTUR — stub heuristikler deterministik, açıklanabilir ve fail-safe'dir; bu iskelet
gerçek model çağrısıyla değiştirilebilir. HTTP kablolaması app.py'dedir; mantık burada
tutulur ki bağımlılıksız (stdlib) unittest ile sınanabilsin.

Not: aibrain girdi tipleri Go alan adlarıyla serileşir (IncidentID, Signals, Tokens...),
ScoreGraph ise snake_case gönderir (focus_id, features...). _get birden çok anahtar
yazımını dener; bilinmeyen/eksik alan güvenli varsayılana düşer.
"""

SOURCE = "svc:heuristic-v0"  # denetlenebilirlik: yanıtın hangi katmandan geldiği


def _get(body, *keys, default=None):
    if not isinstance(body, dict):
        return default
    for k in keys:
        if k in body and body[k] is not None:
            return body[k]
    return default


def _list(body, *keys):
    v = _get(body, *keys, default=[])
    return v if isinstance(v, list) else []


def summarize(body):
    """IncidentInput -> Summary {text, confidence, source}."""
    dev = _get(body, "Device", "device", default="?")
    tech = _get(body, "Technique", "technique", default="")
    sev = _get(body, "Severity", "severity", default="")
    events = _list(body, "Events", "events")
    parts = ["Cihaz %s" % dev]
    if tech:
        parts.append("teknik %s" % tech)
    if sev:
        parts.append("önem %s" % sev)
    parts.append("%d olay" % len(events))
    return {"text": ", ".join(parts) + ".", "confidence": 0.6, "source": SOURCE}


def triage(body):
    """TriageInput -> Triage {priority, likely_fp, next_steps, confidence, source}.
    Heuristik: sinyal + olay sayısı arttıkça öncelik yükselir."""
    n = len(_list(body, "Signals", "signals")) + len(_list(body, "Events", "events"))
    if n >= 5:
        pri = "CRITICAL"
    elif n >= 3:
        pri = "HIGH"
    elif n >= 1:
        pri = "MEDIUM"
    else:
        pri = "LOW"
    return {
        "priority": pri,
        "likely_fp": n == 0,
        "next_steps": ["incident bağlamını incele", "etkilenen cihazı doğrula", "kapsamı belirle"],
        "confidence": round(min(0.5 + 0.1 * n, 0.95), 2),
        "source": SOURCE,
    }


def score_sequence(body):
    """SequenceInput -> SequenceScore {score, rationale, source}."""
    tokens = _list(body, "Tokens", "tokens")
    score = float(min(len(tokens) * 12.0, 100.0))
    return {"score": score, "rationale": "iskelet: dizi uzunluğuna göre (%d token)" % len(tokens), "source": SOURCE}


def score_graph(body):
    """GraphInput (features) -> GraphScore {score, rationale, source}. Ham graf ALMAZ;
    yalnız türetilmiş özellikler (fan-out/in, nadir kenar) üzerinden skorlar."""
    f = _get(body, "features", "Features", default={}) or {}
    fan_out = float(f.get("FanOut", f.get("fan_out", 0)) or 0)
    fan_in = float(f.get("FanIn", f.get("fan_in", 0)) or 0)
    rare = float(f.get("RareEdges", f.get("rare_edges", 0)) or 0)
    score = float(min(fan_out * 5 + fan_in * 3 + rare * 8, 100.0))
    return {"score": score, "rationale": "iskelet: fan-out/in + nadir kenar", "source": SOURCE}


def explain_risk(body):
    """riskfusion.Result -> Explanation {text, source}."""
    score = _get(body, "Score", "score", default=0)
    return {"text": "Risk skoru %s: katkıların ağırlıklı toplamı (iskelet açıklama)." % score, "source": SOURCE}


# ROUTES, POST yolu -> saf işleyici eşlemesidir (app.py bunu kullanır).
ROUTES = {
    "/v1/summarize": summarize,
    "/v1/triage": triage,
    "/v1/score-sequence": score_sequence,
    "/v1/score-graph": score_graph,
    "/v1/explain-risk": explain_risk,
}
