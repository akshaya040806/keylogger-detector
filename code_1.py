import os, ast, csv, zipfile, requests, re
from datetime import datetime
from bs4 import BeautifulSoup

KEYLOGGER_KEYWORDS = {
    "py": ["keyboard", "listener", "event", "capture", "hook",
           "record", "keystroke", "pynput", "win32api", "getasynckeystate", "writefile"],
    "js": ["addeventlistener", "onkeypress", "onkeyup", "onkeydown", "document.cookie",
           "localstorage.setitem", "navigator.sendbeacon", "xmlhttprequest", ".value",
           ".innerhtml", "postmessage", "keyboardevent", "keypress", "keyup", "keydown"]
}

def parse_python_code(code):
    try:
        tree = ast.parse(code)
        words = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Name, ast.FunctionDef, ast.ClassDef, ast.Attribute)):
                words.add(getattr(node, 'id', None) or getattr(node, 'name', None) or getattr(node, 'attr', None))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                words.update(re.findall(r'\b\w+\b', node.value))
        return {w.lower() for w in words if w}
    except Exception as e:
        print(f"AST parse error: {e}")
        return set()

def scan_file(filepath, results):
    suspicious = False
    if filepath.endswith(".py"):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            words = parse_python_code(f.read())
        for keyword in KEYLOGGER_KEYWORDS["py"]:
            if keyword in words:
                log(results, f"[PY] Keyword '{keyword}' found in {filepath}")
                suspicious = True

    elif filepath.endswith(".txt"):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if "pynput" in f.read().lower():
                log(results, f"[TXT] Keyword 'pynput' found in {filepath}")
                suspicious = True

    elif filepath.endswith(".zip"):
        suspicious |= scan_zip(filepath, results)

    elif filepath.endswith(".html"):
        suspicious |= scan_local_html(filepath, results)

    return suspicious

def scan_zip(zip_path, results):
    suspicious = False
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for name in z.namelist():
                if name.endswith(".py"):
                    with z.open(name) as f:
                        code = f.read().decode('utf-8', errors='ignore')
                        words = parse_python_code(code)
                        for keyword in KEYLOGGER_KEYWORDS["py"]:
                            if keyword in words:
                                log(results, f"[ZIP->PY] '{keyword}' in {zip_path}!{name}")
                                suspicious = True
                elif name.endswith(".txt"):
                    with z.open(name) as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        if "pynput" in content.lower():
                            log(results, f"[ZIP->TXT] 'pynput' in {zip_path}!{name}")
                            suspicious = True
    except Exception as e:
        log(results, f"[ZIP] Error processing {zip_path}: {e}")
    return suspicious

def scan_local_html(html_path, results):
    suspicious = False
    try:
        with open(html_path, 'r', encoding='utf-8', errors='ignore') as f:
            soup = BeautifulSoup(f, 'html.parser')
            for script in soup.find_all('script'):
                script_content = script.string or ""
                if script_content:
                    suspicious |= scan_js(script_content, html_path, results)
    except Exception as e:
        log(results, f"[LOCAL HTML] Error reading {html_path}: {e}")
    return suspicious

def scan_js(code, source, results):
    code = code.lower()
    for keyword in KEYLOGGER_KEYWORDS["js"]:
        if keyword in code:
            log(results, f"[JS] Keyword '{keyword}' found in {source}")
            return True
    return False

def log(results, message):
    print(message)
    results.append([datetime.now().isoformat(), message])

def write_csv(results, filename):
    try:
        with open(filename, 'w', newline='') as f:
            csv.writer(f).writerows([["Timestamp", "Message"]] + results)
        print(f"\n[✓] Report saved to {filename}")
    except Exception as e:
        print(f"[✗] Error saving report: {e}")

def scan_website(url, results):
    suspicious = False
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url  # Adding http:// if no protocol is specified
        print(f"\n[WEB] Scanning website: {url}")
        soup = BeautifulSoup(requests.get(url).content, 'html.parser')
        for script in soup.find_all('script'):
            script_content = script.string or ""
            if script_content:
                suspicious |= scan_js(script_content, url, results)
            elif script.get('src'):
                src_url = requests.compat.urljoin(url, script['src'])
                try:
                    js_code = requests.get(src_url).text
                    suspicious |= scan_js(js_code, src_url, results)
                except Exception as e:
                    log(results, f"[WEB] Failed to load JS from {src_url}: {e}")
    except Exception as e:
        log(results, f"[WEB] Error loading {url}: {e}")
    return suspicious

# --- MAIN ---
if __name__ == "__main__":
    results = []
    detected = False
    scan_dir = os.path.expanduser("~/Downloads")  # Example directory, change as needed
    target_url = "https://example.com"  # Change to the URL to scan
    local_html_path = r"C:\Users\Hafeezur Rahman A\OneDrive\Desktop\ALL IMPORTANT\WEBSITE\about.html"  # Change path if necessary
    report_file = "keylogger_analysis.csv"

    print(f"\nScanning directory: {scan_dir}")
    for root, _, files in os.walk(scan_dir):
        for f in files:
            full_path = os.path.join(root, f)
            if scan_file(full_path, results):
                detected = True

    print(f"\nScanning website: {target_url}")
    if scan_website(target_url, results):
        detected = True

    print(f"\nScanning local HTML file: {local_html_path}")
    if scan_local_html(local_html_path, results):
        detected = True

    final_msg = "[!] Keylogger-like behavior detected." if detected else "[+] No suspicious keywords found."
    log(results, final_msg)
    write_csv(results, report_file)
