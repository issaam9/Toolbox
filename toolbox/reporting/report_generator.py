import os

REPORTS_DIR = "reports"

def log_to_module_report(module_name, content):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(f"{REPORTS_DIR}/{module_name}_report.txt", "a", encoding="utf-8") as f:
        f.write(content + "\n\n")

def read_module_report(module_name):
    try:
        with open(f"{REPORTS_DIR}/{module_name}_report.txt", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "Aucun rapport trouvé pour ce module."

def export_module_report(module_name):
    try:
        src = f"{REPORTS_DIR}/{module_name}_report.txt"
        dst = f"{REPORTS_DIR}/{module_name}_report_export.txt"
        with open(src, "r", encoding="utf-8") as f:
            content = f.read()
        with open(dst, "w", encoding="utf-8") as f:
            f.write(content)
        return dst
    except FileNotFoundError:
        return None

def delete_module_report(module_name):
    path = f"{REPORTS_DIR}/{module_name}_report.txt"
    if os.path.exists(path):
        os.remove(path)
        return True
    return False

def list_existing_reports():
    try:
        return [
            f.split("_report.txt")[0]
            for f in os.listdir(REPORTS_DIR)
            if f.endswith("_report.txt")
        ]
    except FileNotFoundError:
        return []
