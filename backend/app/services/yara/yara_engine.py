import yara
import os

BASE_DIR = os.path.dirname(__file__)
RULES_DIR = os.path.join(BASE_DIR, "rules")

def load_rules():
    rule_files = {}

    for file in os.listdir(RULES_DIR):
        if file.endswith(".yar"):
            rule_files[file] = os.path.join(RULES_DIR, file)

    return yara.compile(filepaths=rule_files)

def scan_file(file_path):
    rules = load_rules()
    matches = rules.match(file_path)

    results = []
    for match in matches:
        results.append({
            "rule": match.rule,
            "tags": match.tags,
            "meta": match.meta
        })

    return results
