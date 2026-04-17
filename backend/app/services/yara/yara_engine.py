import subprocess
import os
import glob

BASE_DIR = os.path.dirname(__file__)
RULES_DIR = os.path.join(BASE_DIR, "rules")
# override YARA_EXE env var in production where yara is installed system-wide
YARA_EXE = os.getenv(
    "YARA_EXE",
    r"C:\Users\Limani\tools\yara\yara.exe"
)

def scan_file(file_path):
    try:
        if not os.path.exists(YARA_EXE):
            raise FileNotFoundError(f"YARA executable not found at {YARA_EXE}")

        rule_files = glob.glob(os.path.join(RULES_DIR, "*.yar"))
        matches = []

        # run yara once per rule file and collect all matches
        for rule in rule_files:
            result = subprocess.run(
                [YARA_EXE, rule, file_path],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.splitlines():
                rule_name = line.split()[0]
                matches.append({
                    "rule": rule_name,
                    "meta": {
                        "severity": "medium",
                        "description": "Detected via YARA signature"
                    }
                })

        return matches

    except Exception as e:
        print("[YARA ERROR]", e)
        return []
