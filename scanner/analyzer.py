import re

# Padrões de erro de banco de dados que indicam SQLi bem-sucedido
DB_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysql_query",
    r"mysqli_",
    r"com\.mysql\.jdbc",
    r"mariadb",

    # PostgreSQL
    r"pg_query",
    r"pg_exec",
    r"postgresql.*error",
    r"unterminated quoted string",
    r"invalid input syntax for",
    r"syntax error at or near",

    # SQLite
    r"sqlite3\.OperationalError",
    r"sqlite_error",
    r"unrecognized token",

    # SQL Server
    r"microsoft.*odbc.*sql server",
    r"mssql_query",
    r"unclosed quotation mark after the character string",
    r"sql server.*error",

    # Oracle
    r"ora-\d{5}",
    r"oracle.*error",
    r"quoted string not properly terminated",

    # Genéricos
    r"sql syntax.*error",
    r"syntax error.*sql",
    r"unexpected end of sql command",
    r"invalid query",
    r"sql error",
    r"database error",
    r"db error",
]

# Padrões que indicam vazamento de dados estruturados
DATA_LEAK_PATTERNS = [
    r"information_schema",
    r"table_name",
    r"column_name",
    r"password",
    r"passwd",
    r"secret",
    r"token",
    r"admin.*password",
]

# Padrões de stack trace que indicam erros internos expostos
STACK_TRACE_PATTERNS = [
    r"traceback \(most recent call last\)",
    r"exception.*at.*line",
    r"stack trace",
    r"debug.*true",
    r"internal server error.*sql",
]


def _strip_payload_reflection(response_text, payload, url=""):
    if not payload and not url:
        return response_text
    cleaned = response_text

    for text in [payload, url]:
        if not text:
            continue
        text_lower = text.lower()
        cleaned = cleaned.replace(text_lower, "")

        # HTML-entity escaped (Django template autoescaping):
        # Escapa apenas chars especiais HTML, mantém espaços como espaços
        text_html = (
            text_lower
            .replace("&", "&amp;")
            .replace("'", "&#x27;")
            .replace('"', "&quot;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        cleaned = cleaned.replace(text_html, "")

        # HTML-escaped + percent-encoded spaces (usado em <td> de URLs)
        cleaned = cleaned.replace(text_html.replace(" ", "%20"), "")

        # Apenas percent-encoded (sem HTML entities)
        try:
            from urllib.parse import quote
            text_pct = quote(text_lower, safe="")
            cleaned = cleaned.replace(text_pct, "")
            # Percent-encoded com HTML entities para aspas
            text_pct_html = quote(text_lower, safe="").replace("%27", "&#x27;").replace("%22", "&quot;")
            cleaned = cleaned.replace(text_pct_html, "")
        except Exception:
            pass

        # Percent-encoded com + para espaços (query strings)
        cleaned = cleaned.replace(text_lower.replace(" ", "+"), "")

    return cleaned


def _pattern_in_payload_or_url(pattern, payload, url):
    """Verifica se o padrão casado existe no payload ou na URL (reflexão)."""
    for text in [payload, url]:
        if text and re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def analyze_response(result):
    if "error" in result:
        return False

    payload = result.get("payload", "").lower()
    url = result.get("url", "").lower()
    response_text = result.get("response", "").lower()
    cleaned = _strip_payload_reflection(response_text, payload, url)
    status_code = result.get("status", 0)

    # Verificar padrões de erro de banco de dados
    for pattern in DB_ERROR_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE):
            return True

    # Verificar vazamento de dados sensíveis
    # Só conta se o padrão NÃO está no payload ou URL (evita reflexão)
    for pattern in DATA_LEAK_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE):
            if not _pattern_in_payload_or_url(pattern, payload, url):
                return True

    # Verificar stack traces expostos com contexto SQL
    for pattern in STACK_TRACE_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE):
            return True

    return False


def classify_result(result):
    if "error" in result:
        return {
            "vulnerable": False,
            "classification": "ERRO",
            "evidence": result["error"],
        }

    payload = result.get("payload", "").lower()
    url = result.get("url", "").lower()
    response_text = result.get("response", "").lower()
    cleaned = _strip_payload_reflection(response_text, payload, url)
    status_code = result.get("status", 0)

    # Verificar padrões de erro de banco de dados (VP)
    for pattern in DB_ERROR_PATTERNS:
        match = re.search(pattern, cleaned, re.IGNORECASE)
        if match:
            return {
                "vulnerable": True,
                "classification": "VP",
                "evidence": f"Erro de DB detectado: '{match.group()}'",
            }

    # Verificar vazamento de dados (VP)
    # Só conta se o padrão NÃO está no payload ou URL (evita reflexão)
    for pattern in DATA_LEAK_PATTERNS:
        match = re.search(pattern, cleaned, re.IGNORECASE)
        if match and not _pattern_in_payload_or_url(pattern, payload, url):
            return {
                "vulnerable": True,
                "classification": "VP",
                "evidence": f"Vazamento de dados: '{match.group()}'",
            }

    # Verificar stack traces (VP)
    for pattern in STACK_TRACE_PATTERNS:
        match = re.search(pattern, cleaned, re.IGNORECASE)
        if match:
            return {
                "vulnerable": True,
                "classification": "VP",
                "evidence": f"Stack trace exposto: '{match.group()}'",
            }

    # Status 500 sem padrão SQL em Falso Positivo potencial
    if status_code == 500:
        return {
            "vulnerable": False,
            "classification": "FP",
            "evidence": "HTTP 500 sem evidência de SQLi",
        }

    # Sem indicação de vulnerabilidade
    return {
        "vulnerable": False,
        "classification": "FALHA",
        "evidence": f"HTTP {status_code} — sem indicadores de SQLi",
    }


def compute_metrics(classifications):
    total = len(classifications)
    vp = sum(1 for c in classifications if c["classification"] == "VP")
    fp = sum(1 for c in classifications if c["classification"] == "FP")
    falhas = sum(1 for c in classifications if c["classification"] == "FALHA")
    erros = sum(1 for c in classifications if c["classification"] == "ERRO")

    precision = vp / (vp + fp) if (vp + fp) > 0 else 0.0
    efficacy = vp / total if total > 0 else 0.0

    return {
        "total_attacks": total,
        "true_positives": vp,
        "false_positives": fp,
        "failures": falhas,
        "errors": erros,
        "precision": round(precision, 4),
        "efficacy": round(efficacy, 4),
    }
