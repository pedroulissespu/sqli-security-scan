import json
import time
import os


def generate_report(results, metrics, output_path="reports/scan_report.json"):
    """Gera relatório final com os resultados do scan."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "summary": metrics,
        "vulnerabilities": [],
        "details": [],
    }

    for r in results:
        entry = {
            "endpoint": r.get("url", ""),
            "method": r.get("method", ""),
            "payload": r.get("payload", ""),
            "status_code": r.get("status", None),
            "classification": r.get("classification", {}).get("classification", ""),
            "vulnerable": r.get("classification", {}).get("vulnerable", False),
            "evidence": r.get("classification", {}).get("evidence", ""),
            "response_time": r.get("response_time", None),
            "response_body": r.get("response", ""),
        }

        report["details"].append(entry)

        if entry["vulnerable"]:
            report["vulnerabilities"].append(entry)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return report


def print_report_summary(report):
    """Imprime resumo do relatório no terminal."""
    summary = report["summary"]
    vulns = report["vulnerabilities"]

    print("\n" + "=" * 60)
    print("RELATÓRIO")
    print("=" * 60)
    print(f"  Data: {report['timestamp']}")
    print(f"  Total de ataques: {summary['total_attacks']}")
    print(f"  Verdadeiros Positivos (VP): {summary['true_positives']}")
    print(f"  Falsos Positivos (FP): {summary['false_positives']}")
    print(f"  Falhas: {summary['failures']}")
    print(f"  Erros: {summary['errors']}")
    print(f"  Precisão: {summary['precision']:.2%}")
    print(f"  Eficácia: {summary['efficacy']:.2%}")
    print("=" * 60)

    if vulns:
        print(f"\n  {len(vulns)} VULNERABILIDADES ENCONTRADAS:")
        for v in vulns:
            print(f"    [{v['method']}] {v['endpoint']}")
            print(f"      Payload: {v['payload'][:80]}...")
            print(f"      Evidência: {v['evidence']}")
            resp = v.get('response_body', '')
            if resp:
                print(f"      Response: {resp[:200]}")
            print()
    else:
        print("\n  Nenhuma vulnerabilidade encontrada.")

    print("=" * 60)
