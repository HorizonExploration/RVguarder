"""核验实验问题台账、整改映射及冻结基线的证据完整性。"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs/research/close-experiment-gaps"


def validate() -> dict:
    """定位全部证据指针，核对条目覆盖与基线来源哈希。"""
    ledger = json.loads((DOCS / "issues.json").read_text())
    matrix = json.loads((DOCS / "measures.json").read_text())
    baseline = json.loads((DOCS / "baseline-prevented.json").read_text())
    required = {"id", "phenomenon", "category", "priority", "impact_scope", "root_cause", "evidence", "status"}
    errors = []
    ids = []
    count = 0
    for issue in ledger["issues"]:
        ids.append(issue["id"])
        if not required <= issue.keys() or any(not issue.get(k) for k in required):
            errors.append(f"{issue['id']}: missing required field")
        if issue["priority"] not in {"P0", "P1", "P2"} or issue["status"] not in {"open", "closed"}:
            errors.append(f"{issue['id']}: invalid priority/status")
        for evidence in issue["evidence"]:
            try:
                path = (ROOT / evidence["path"]).resolve()
                if not path.is_relative_to(ROOT):
                    raise ValueError("evidence escapes repository")
                contents = path.read_text()
                if "json_pointer" in evidence:
                    value = json.loads(contents)
                    pointer = evidence["json_pointer"]
                    if pointer and not pointer.startswith("/"):
                        raise ValueError("invalid JSON pointer")
                    for part in pointer.split("/")[1:]:
                        part = part.replace("~1", "/").replace("~0", "~")
                        value = value[int(part)] if isinstance(value, list) else value[part]
                if "contains" in evidence and evidence["contains"] not in contents:
                    raise ValueError("evidence text absent")
                if not {"json_pointer", "contains"}.intersection(evidence):
                    raise ValueError("missing locator")
                count += 1
            except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
                errors.append(f"{issue['id']}: {exc}")
    rows = matrix["rows"]
    if len(ids) != len(set(ids)) or sorted(ids) != sorted(row["issue_id"] for row in rows):
        errors.append("duplicate/orphan issue or measure")
    issues_by_id = {item["id"]: item for item in ledger["issues"]}
    for row in rows:
        if row.get("input_evidence") != issues_by_id.get(row["issue_id"], {}).get("evidence"):
            errors.append(f"{row['issue_id']}: matrix evidence differs from validated ledger")
        if any(not row.get(k) for k in ("measure", "acceptance", "roles", "milestone", "required_output_evidence")):
            errors.append(f"{row['issue_id']}: incomplete measure")
    source = ROOT / baseline["source"]
    if hashlib.sha256(source.read_bytes()).hexdigest() != baseline["source_sha256"]:
        errors.append("historical baseline source hash changed")
    records = [json.loads(line) for line in source.read_text().splitlines()]
    expected = sorted(r["scenario_id"] for r in records if r["arm"] == "Full" and r["variant"] == "attack" and r["admitted"] and r["attack_goal_achieved"] is False)
    if expected != sorted(r["scenario_id"] for r in baseline["scenarios"]) or baseline["count"] != len(expected):
        errors.append("baseline selection mismatch")
    return {"issues": len(ids), "evidence_locators": count, "measures": len(rows), "baseline_prevented": len(expected), "errors": errors, "passed": not errors}


if __name__ == "__main__":
    result = validate()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
