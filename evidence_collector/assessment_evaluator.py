#!/usr/bin/env python3
"""
Assessment Evaluation Engine for Module 1 & CyberRangeCZ Integration.
Evaluates trainee answers against ground-truth evidence with:
- Normalized string matching & regex support
- Configurable scoring and partial credit
- Hint tracking and score penalty deduction
- Strict separation between evidence facts, interpretations, and scoring keys
- Secure audit logging of submissions
"""

import sys
import re
import json
from datetime import datetime, timezone
from pathlib import Path

# Certified answer evaluation criteria grounded in INC-2026-9842 evidence
EVALUATION_RULES = {
    "Q1": {
        "title": "Affected Workstation",
        "patterns": [r"^desktop-wkstn42(\.lab)?$"],
        "max_score": 10,
        "evidence_source": "endpoint/process_events.jsonl & incident.json"
    },
    "Q2": {
        "title": "Initiating Process",
        "patterns": [r"^(c:\\.*\\)?invoice_review\.exe$"],
        "max_score": 10,
        "evidence_source": "endpoint/process_events.jsonl (PID 4912)"
    },
    "Q3": {
        "title": "Parent Process",
        "patterns": [r"^(c:\\.*\\)?explorer\.exe$"],
        "max_score": 10,
        "evidence_source": "endpoint/process_events.jsonl (ParentProcessId 2840)"
    },
    "Q4": {
        "title": "Initial Suspicious Timestamp",
        "patterns": [r"^2026-11-06t09:14:22(\.\d+)?z?$"],
        "max_score": 10,
        "evidence_source": "endpoint/process_events.jsonl (UtcTime)"
    },
    "Q5": {
        "title": "Modified File Extension",
        "patterns": [r"^\.?locked$"],
        "max_score": 10,
        "evidence_source": "endpoint/file_activity.jsonl"
    },
    "Q6": {
        "title": "C2 Destination IP and Port",
        "patterns": [r"^10\.10\.50\.30[:\s]+8080$", r"^10\.10\.50\.30$"],
        "max_score": 10,
        "evidence_source": "network/network_capture.pcap & c2_conversations.json"
    },
    "Q7": {
        "title": "Wazuh Alert Rule ID",
        "patterns": [r"^100202$", r"^100203$"],
        "max_score": 10,
        "evidence_source": "wazuh/wazuh_alerts.json"
    },
    "Q8": {
        "title": "Ransom Note Filename",
        "patterns": [r"^restore_files_info\.txt$"],
        "max_score": 10,
        "evidence_source": "forensic/indicators.json & endpoint/file_activity.jsonl"
    },
    "Q9": {
        "title": "ATT&CK Defense Impairment Technique",
        "patterns": [r"^t?1490$"],
        "max_score": 10,
        "evidence_source": "wazuh/wazuh_alerts.json (Inhibit System Recovery)"
    },
    "Q10": {
        "title": "Primary SOC Containment Action",
        "patterns": [r"^.*(isolate|isolation|quarantine|disconnect).*$"],
        "max_score": 10,
        "evidence_source": "Incident Response Standard Playbook"
    }
}

class AssessmentEvaluator:
    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        self.manifest_path = evidence_dir / "manifest.json"
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Missing evidence manifest at {self.manifest_path}")
        with open(self.manifest_path, 'r', encoding='utf-8') as f:
            self.manifest = json.load(f)

    def evaluate_submission(self, answers: dict, hints_used: dict = None) -> dict:
        hints_used = hints_used or {}
        results = {}
        total_score = 0
        max_possible = sum(r["max_score"] for r in EVALUATION_RULES.values())

        for q_id, rule in EVALUATION_RULES.items():
            user_ans = str(answers.get(q_id, "")).strip().lower()
            # Remove redundant quotes
            user_ans = user_ans.strip('"\'')
            is_correct = any(re.match(p, user_ans) for p in rule["patterns"])
            
            penalty = 2 if hints_used.get(q_id) else 0
            earned = max(0, rule["max_score"] - penalty) if is_correct else 0
            total_score += earned

            results[q_id] = {
                "title": rule["title"],
                "submitted_answer": answers.get(q_id, ""),
                "is_correct": is_correct,
                "score_awarded": earned,
                "max_score": rule["max_score"],
                "hint_penalty": penalty,
                "evidence_ref": rule["evidence_source"]
            }

        percentage = round((total_score / max_possible) * 100, 2)
        summary = {
            "incident_id": self.manifest.get("incident_id"),
            "evidence_version": self.manifest.get("scenario_version"),
            "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
            "total_score": total_score,
            "max_score": max_possible,
            "percentage": percentage,
            "passed": percentage >= 70.0,
            "breakdown": results
        }
        return summary

def main():
    base_dir = Path(__file__).resolve().parent.parent
    evidence_dir = base_dir / "evidence" / "INC-2026-9842"
    evaluator = AssessmentEvaluator(evidence_dir)

    # Sample canonical submission test
    sample_answers = {
        "Q1": "DESKTOP-WKSTN42",
        "Q2": "invoice_review.exe",
        "Q3": "explorer.exe",
        "Q4": "2026-11-06T09:14:22Z",
        "Q5": ".locked",
        "Q6": "10.10.50.30:8080",
        "Q7": "100202",
        "Q8": "RESTORE_FILES_INFO.txt",
        "Q9": "T1490",
        "Q10": "Isolate the infected workstation from the network immediately"
    }

    res = evaluator.evaluate_submission(sample_answers)
    print("=" * 60)
    print(" Module 1 Assessment Evaluation Test ")
    print("=" * 60)
    print(f"Incident: {res['incident_id']}")
    print(f"Total Score: {res['total_score']} / {res['max_score']} ({res['percentage']}%)")
    print(f"Status: {'PASSED' if res['passed'] else 'FAILED'}")
    print("\nDetailed Checkpoints:")
    for q, data in res["breakdown"].items():
        status = "CORRECT" if data["is_correct"] else "INCORRECT"
        print(f"  [{status:9s}] {q} - {data['title']}: {data['score_awarded']}/{data['max_score']} pts")
    print("=" * 60)

    # Save test assessment output
    out_file = evidence_dir / "sample_assessment_result.json"
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(res, f, indent=2)

    return 0 if res["passed"] else 1

if __name__ == "__main__":
    sys.exit(main())
