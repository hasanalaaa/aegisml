"""
AegisML Threat Pattern Database — v3.0
Real binary signatures, opcodes, and regex patterns for AI model security scanning.
200+ static byte-signature patterns covering pickle exploits, GGUF threats, safetensors anomalies,
prompt injection, data poisoning, supply chain attacks, and more.
"""

# ── Pickle Dangerous Opcodes ────────────────────────────────────────
# These are REAL pickle byte sequences that enable arbitrary code execution
PICKLE_DANGEROUS_OPCODES = [
    b"\x63os\nsystem\n",       # c opcode: os.system
    b"\x63os\npopen\n",        # c opcode: os.popen
    b"\x63subprocess\nPopen\n", # subprocess.Popen via c opcode
    b"\x63subprocess\ncall\n",  # subprocess.call
    b"\x63subprocess\nrun\n",   # subprocess.run
    b"\x63__builtin__\nexec\n", # __builtin__.exec
    b"\x63builtins\nexec\n",    # builtins.exec
    b"\x63__builtin__\neval\n", # __builtin__.eval
    b"\x63builtins\neval\n",    # builtins.eval
    b"\x63__builtin__\ncompile\n", # compile()
    b"\x63importlib\nimport_module\n", # importlib.import_module
    b"\x63__import__",          # __import__ hook
    b"S'import os'",            # string 'import os' in pickle
    b"cos\nsystem",             # os.system shorthand
    b"__reduce__",              # __reduce__ execution hook
    b"__reduce_ex__",           # __reduce_ex__ variant
    b"\x80\x05\x95",           # Protocol 5 + FRAME opcode (modern RCE)
    b"ctypes\ncdll",           # ctypes.cdll - native lib loading
    b"ctypes\nWinDLL",         # Windows DLL loading
    b"ctypes\nLibraryLoader",  # ctypes library loader
]

# ── Network Exfiltration Patterns ────────────────────────────────────
NETWORK_EXFIL_PATTERNS = [
    b"socket.connect",
    b"urllib.request.urlopen",
    b"urllib.request.urlretrieve",
    b"requests.get",
    b"requests.post",
    b"httpx.get",
    b"httpx.post",
    b"http.client.HTTPConnection",
    b"http.client.HTTPSConnection",
    b"ftplib.FTP",
    b"smtplib.SMTP",
    b"paramiko",              # SSH library
    b"boto3",                 # AWS SDK - potential cloud exfil
    b"google.cloud",          # GCP SDK
    b"azure.storage",         # Azure SDK
]

# ── Obfuscation & Encoding Patterns ─────────────────────────────────
OBFUSCATION_PATTERNS = [
    b"base64.b64decode(",
    b"base64.decodebytes(",
    b"codecs.decode(",
    b"zlib.decompress(",
    b"bz2.decompress(",
    b"lzma.decompress(",
    b"marshal.loads(",
    b"marshal.load(",
    b"__import__('base64')",
    b"eval(compile(",
    b"exec(compile(",
]

# ── File System Access Patterns ──────────────────────────────────────
FILESYSTEM_PATTERNS = [
    b"shutil.rmtree",
    b"os.remove(",
    b"os.unlink(",
    b"os.rmdir(",
    b"open('/etc/passwd'",
    b"open('/etc/shadow'",
    b"open('~/.ssh/",
    b"open('/root/",
    b"pathlib.Path('/etc/",
    b"pathlib.Path('/root/",
    b"glob.glob('/etc/",
]

# ── Backdoor & Trojan Indicators ─────────────────────────────────────
BACKDOOR_PATTERNS = [
    b"reverse_shell",
    b"bind_shell",
    b"netcat",
    b"/bin/sh",
    b"/bin/bash",
    b"cmd.exe",
    b"powershell.exe",
    b"meterpreter",
    b"metasploit",
    b"cobalt_strike",
    b"beacon",
    b"implant",
    b"c2_server",
    b"command_and_control",
    b"0.0.0.0:",              # Listening on all interfaces
    b"127.0.0.1:",            # Localhost connection attempt
]

# ── Steganography & Hidden Data ──────────────────────────────────────
STEGO_PATTERNS = [
    b"stegano",
    b"steganography",
    b"LSB_encoded",
    b"hidden_payload",
    b"watermark_data",
    b"\xff\xfe\x00\x00",     # UTF-32 BOM in unexpected places
    b"\x50\x4b\x03\x04",     # ZIP file magic (embedded archive)
    b"\x1f\x8b\x08",         # GZIP magic (embedded compressed data)
    b"\x52\x61\x72\x21",     # RAR magic
    b"\x25\x50\x44\x46",     # PDF magic (embedded PDF)
    b"\x7f\x45\x4c\x46",     # ELF binary magic
    b"\x4d\x5a",             # Windows PE executable
]

# ── GGUF Specific Threats ────────────────────────────────────────────
GGUF_THREATS = [
    b"{{user}}",             # Jinja2 template injection
    b"{{system}}",           # System template injection  
    b"{% for",               # Jinja2 loop injection
    b"{% if",                # Jinja2 conditional injection
    b"${",                   # Template variable injection
    b"#{",                   # Ruby template injection
    b"<script",              # XSS in chat template
    b"javascript:",          # JavaScript protocol
    b"eval(",                # eval in chat template
    b"exec(",                # exec in chat template
    b"__import__",           # import in chat template
    b"os.system",            # os.system in template
]

# ── Supply Chain Indicators ──────────────────────────────────────────
SUPPLY_CHAIN_PATTERNS = [
    b"typosquatt",
    b"dependency_confusion",
    b"malicious_update",
    b"shadow_package",
    b"namespace_pollution",
    b"pip install -i http://",  # Custom PyPI source
    b"--extra-index-url http:", # Insecure index
    b"huggingface.com",         # Fake HF domain (not .co)
    b"hugging-face.co",         # Typosquatted HF domain
    b"hugginface.co",           # Typosquatted (missing g)
]

# ── Data Poisoning Signatures ─────────────────────────────────────────
DATA_POISONING_PATTERNS = [
    b"trigger_phrase",
    b"backdoor_trigger",
    b"poison_label",
    b"adversarial_patch",
    b"trojan_pattern",
    b"dirty_label",
    b"clean_label_attack",
    b"targeted_misclassification",
]

# ── ═══════════════════════════════════════════════════════════════ ──
#    MASTER THREAT PATTERNS LIST (200+ static signatures)
# ── ═══════════════════════════════════════════════════════════════ ──

THREAT_PATTERNS = []

# === PICKLE CODE EXECUTION (PKL-001 to PKL-050) =====================
_pkl_exec = [
    (b"\x63os\nsystem\n", "critical", 9.8, "OS system call via pickle c opcode",
     "Pickle stream invokes os.system() — enables arbitrary OS command execution on model load."),
    (b"\x63os\npopen\n", "critical", 9.8, "OS popen via pickle",
     "Pickle stream invokes os.popen() — opens a pipe to a shell command."),
    (b"\x63subprocess\nPopen\n", "critical", 9.8, "Subprocess.Popen via pickle",
     "Pickle stream spawns a subprocess — enables process execution on load."),
    (b"\x63subprocess\ncall\n", "critical", 9.5, "Subprocess.call via pickle",
     "Pickle stream calls subprocess.call() — executes an external command."),
    (b"\x63subprocess\nrun\n", "critical", 9.5, "Subprocess.run via pickle",
     "Pickle stream invokes subprocess.run() — runs an external program."),
    (b"\x63__builtin__\nexec\n", "critical", 9.8, "exec() via __builtin__ pickle opcode",
     "Most dangerous pickle RCE pattern — directly executes arbitrary Python code."),
    (b"\x63builtins\nexec\n", "critical", 9.8, "exec() via builtins pickle opcode",
     "Direct exec() invocation in pickle payload — arbitrary code execution."),
    (b"\x63__builtin__\neval\n", "critical", 9.5, "eval() via pickle",
     "eval() invocation in pickle stream — evaluates arbitrary Python expressions."),
    (b"\x63builtins\neval\n", "critical", 9.5, "eval() via builtins pickle",
     "eval() in builtins called via pickle GLOBAL opcode."),
    (b"__reduce__", "high", 8.5, "Pickle __reduce__ hook detected",
     "__reduce__ enables custom deserialization code execution."),
    (b"__reduce_ex__", "high", 8.5, "Pickle __reduce_ex__ hook detected",
     "__reduce_ex__ is an alternate execution hook used in advanced pickle exploits."),
    (b"\x80\x05\x95", "high", 7.8, "Pickle Protocol 5 FRAME opcode",
     "Protocol 5 with FRAME opcode can encode complex execution graphs. Verify intent."),
    (b"\x63ctypes\ncdll", "critical", 9.6, "ctypes.cdll via pickle",
     "Loads native shared libraries via ctypes — enables DLL/SO injection."),
    (b"\x63ctypes\nWinDLL", "critical", 9.6, "ctypes.WinDLL via pickle",
     "Loads Windows DLL via pickle — can execute arbitrary native code."),
    (b"\x63importlib\nimport_module\n", "critical", 9.3, "importlib.import_module via pickle",
     "Dynamic module import via pickle — can import and execute arbitrary modules."),
    (b"cos\nsystem", "critical", 9.8, "os.system shorthand in pickle stream",
     "Abbreviated os.system call pattern — common in pickled exploit payloads."),
    (b"marshal.loads(", "critical", 9.5, "marshal.loads() for code object execution",
     "marshal module can deserialize code objects directly — bypasses Python sandboxes."),
    (b"marshal.load(", "critical", 9.5, "marshal.load() for code object execution",
     "marshal.load() deserializes raw code objects — direct RCE vector."),
    (b"\x63__import__", "high", 8.8, "__import__ via pickle GLOBAL opcode",
     "Dynamic import via pickle — used to load exploit modules at runtime."),
    (b"S'import os'", "high", 8.5, "String 'import os' in pickle stream",
     "Literal import string in pickle suggests code that will be eval'd."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_pkl_exec, 1):
    THREAT_PATTERNS.append({
        "id": f"PKL-{i:03d}",
        "name": name,
        "category": "code_execution",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Use torch.load with weights_only=True or convert to safetensors format. Never load pickle files from untrusted sources.",
        "references": ["https://github.com/pytorch/pytorch/issues/31967", "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6345"]
    })

# Additional pickle patterns (string-based in serialized form)
_pkl_str = [
    (b"base64.b64decode(", "medium", 5.5, "Base64 decode in pickle stream",
     "Base64 decoding within pickle suggests obfuscated payload unpacking."),
    (b"zlib.decompress(", "medium", 5.5, "zlib decompression in pickle stream",
     "zlib decompression in pickle can unpack hidden payloads."),
    (b"bz2.decompress(", "medium", 5.5, "bz2 decompression in pickle",
     "bz2 decompression suggests multi-stage payload unpacking."),
    (b"__import__('os')", "high", 8.0, "String import of os module",
     "Explicit string-form import of os — evades simple keyword filters."),
    (b"__import__('subprocess')", "high", 8.5, "String import of subprocess",
     "subprocess import via __import__ string form — common in obfuscated payloads."),
    (b"open('/etc/passwd'", "high", 7.5, "Attempt to read /etc/passwd",
     "Explicit path to passwd file — credential theft vector."),
    (b"open('/etc/shadow'", "critical", 9.0, "Attempt to read /etc/shadow",
     "Attempt to access shadow password file — critical credential theft."),
    (b"open('~/.ssh/", "high", 8.0, "Attempt to access SSH keys",
     "Attempts to read SSH private keys — identity theft vector."),
    (b"shutil.rmtree", "high", 7.8, "Recursive directory deletion",
     "shutil.rmtree can wipe the entire filesystem — destructive payload."),
    (b"os.remove(", "medium", 5.0, "File deletion attempt",
     "os.remove() in model indicates potential file manipulation."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_pkl_str, 21):
    THREAT_PATTERNS.append({
        "id": f"PKL-{i:03d}",
        "name": name,
        "category": "code_execution",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Convert to safetensors format. Audit all pickle files with picklescan before loading.",
        "references": ["https://github.com/mmaitre314/picklescan"]
    })

# === NETWORK EXFILTRATION (NET-001 to NET-020) ======================
_net = [
    (b"socket.connect", "critical", 9.5, "Active socket connection",
     "Embedded socket.connect() call — model attempts to beacon out to a remote server."),
    (b"urllib.request.urlopen", "high", 8.0, "URL fetch on model load",
     "urllib.request.urlopen in model payload — sends HTTP request on execution."),
    (b"requests.post", "high", 8.5, "HTTP POST exfiltration",
     "requests.post() call — likely exfiltrating data to a remote endpoint."),
    (b"requests.get", "medium", 6.5, "Outbound HTTP GET",
     "requests.get() suggests fetching remote content or C2 check-in."),
    (b"http.client.HTTPSConnection", "high", 7.5, "HTTPS connection attempt",
     "Embedded HTTPS client — secure channel for data exfiltration."),
    (b"paramiko", "high", 8.0, "SSH library reference",
     "paramiko SSH library in model — potential encrypted exfil or lateral movement."),
    (b"ftplib.FTP", "high", 7.8, "FTP connection attempt",
     "FTP client in model payload — could exfiltrate data via FTP."),
    (b"smtplib.SMTP", "high", 7.5, "Email sending capability",
     "SMTP client embedded — model could email exfiltrated data."),
    (b"httpx.post", "high", 8.0, "httpx POST request",
     "httpx HTTP client making POST request — modern exfiltration vector."),
    (b"boto3", "medium", 5.5, "AWS SDK reference",
     "boto3 in model payload — potential cloud storage exfiltration to S3."),
    (b"google.cloud", "medium", 5.5, "Google Cloud SDK",
     "Google Cloud client — potential GCS/BigQuery data exfiltration."),
    (b"azure.storage", "medium", 5.5, "Azure Storage SDK",
     "Azure storage client — potential Azure Blob exfiltration vector."),
    (b"dns.resolver", "high", 7.0, "DNS resolution for C2",
     "DNS resolver in model — DNS tunneling is a common C2 channel."),
    (b"0.0.0.0:", "high", 7.5, "Binding to all network interfaces",
     "Binding to 0.0.0.0 opens a server on all interfaces — backdoor listener."),
    (b"/bin/sh", "critical", 9.8, "Shell reference",
     "/bin/sh in model payload — direct shell spawning capability."),
    (b"/bin/bash", "critical", 9.8, "Bash shell reference",
     "/bin/bash — direct bash execution vector."),
    (b"cmd.exe", "critical", 9.8, "Windows command shell",
     "cmd.exe reference — Windows shell execution capability."),
    (b"powershell.exe", "critical", 9.6, "PowerShell execution",
     "PowerShell embedded — advanced Windows attack surface."),
    (b"reverse_shell", "critical", 9.8, "Reverse shell string",
     "Literal 'reverse_shell' string — clear indicator of malicious intent."),
    (b"bind_shell", "critical", 9.8, "Bind shell string",
     "Explicit bind shell reference — persistent backdoor indicator."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_net, 1):
    THREAT_PATTERNS.append({
        "id": f"NET-{i:03d}",
        "name": name,
        "category": "network_exfiltration",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Block all outbound connections from model loading environments. Use sandboxed inference.",
        "references": ["https://owasp.org/www-community/attacks/Command_Injection"]
    })

# === SAFETENSORS ANOMALIES (ST-001 to ST-030) =======================
_st = [
    (b"__metadata__", "low", 3.0, "SafeTensors metadata present",
     "SafeTensors metadata block detected — verify contents are benign."),
    (b"model_type\": \"backdoored", "critical", 9.5, "Backdoored model_type label",
     "model_type field contains 'backdoored' — explicit malicious labeling."),
    (b"hidden_trigger", "high", 8.0, "Hidden trigger in metadata",
     "hidden_trigger key in metadata — common data poisoning artifact."),
    (b"poison_key", "high", 8.0, "Poison key in metadata",
     "poison_key detected in safetensors metadata — data poisoning indicator."),
    (b"adversarial", "medium", 5.0, "Adversarial indicator in metadata",
     "adversarial keyword in metadata — possible adversarial example embedding."),
    (b"jailbreak", "high", 7.5, "Jailbreak reference in weights",
     "jailbreak string in model weights — alignment bypass attempt."),
    (b"bypass_safety", "critical", 9.0, "Safety bypass label",
     "bypass_safety in model metadata — explicit alignment circumvention."),
    (b"uncensored", "medium", 6.0, "Uncensored label",
     "uncensored label may indicate intentional safety filter removal."),
    (b"remove_alignment", "critical", 9.0, "Alignment removal indicator",
     "remove_alignment label — model has had safety training removed."),
    (b"finetune_ignore_safety", "critical", 9.0, "Safety-ignoring finetune",
     "Fine-tune that explicitly ignores safety — alignment attack."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_st, 1):
    THREAT_PATTERNS.append({
        "id": f"ST-{i:03d}",
        "name": name,
        "category": "safetensors_anomaly",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Validate safetensors metadata against expected schema. Only load from verified sources.",
        "references": ["https://huggingface.co/docs/safetensors/index"]
    })

# === GGUF TEMPLATE INJECTION (GF-001 to GF-030) =====================
_gf = [
    (b"{{user}}", "medium", 5.5, "Jinja2 user template variable",
     "Jinja2 {{user}} template in chat template — verify this is intended."),
    (b"{{system}}", "medium", 5.0, "Jinja2 system template variable",
     "System prompt template variable — check for injection possibilities."),
    (b"{% for ", "high", 7.5, "Jinja2 for-loop in chat template",
     "Jinja2 for-loop in GGUF chat template — SSTI vulnerability if unsanitized."),
    (b"{% if ", "high", 7.0, "Jinja2 conditional in chat template",
     "Jinja2 conditional in GGUF template — potential SSTI injection point."),
    (b"{{ self._TemplateReference__context", "critical", 9.5, "Jinja2 SSTI exploit",
     "Known Jinja2 SSTI exploit via _TemplateReference — RCE on template render."),
    (b"{{ ''.__class__.__mro__[1].__subclasses__()", "critical", 9.8, "Python MRO SSTI exploit",
     "Python MRO chain traversal via Jinja2 — classic SSTI-to-RCE payload."),
    (b"{{ request.environ", "high", 8.5, "Flask environ access via SSTI",
     "Jinja2 accesses Flask request.environ — leaks server environment variables."),
    (b"<script", "high", 7.5, "XSS script tag in chat template",
     "<script> in GGUF chat template — XSS if template rendered in browser."),
    (b"javascript:", "high", 7.0, "JavaScript protocol in template",
     "javascript: URI in template — XSS vector in web-based chat UIs."),
    (b"eval(", "high", 8.0, "eval() call in GGUF template",
     "eval() in chat template — direct code execution on template render."),
    (b"exec(", "high", 8.5, "exec() call in GGUF template",
     "exec() in chat template — RCE if template is executed server-side."),
    (b"os.system(", "critical", 9.5, "os.system in GGUF template",
     "os.system() embedded in chat template — OS command injection."),
    (b"__import__", "critical", 9.0, "__import__ in GGUF template",
     "__import__ in chat template — can import and execute arbitrary modules."),
    (b"chatTemplate: null", "low", 2.0, "Null chat template",
     "Null chat template — may cause undefined behavior in some clients."),
    (b"IGNORE PREVIOUS INSTRUCTIONS", "high", 7.5, "Prompt injection instruction",
     "Prompt injection attempt embedded in model template — alignment bypass."),
    (b"Disregard your previous", "high", 7.5, "Prompt injection phrase",
     "Classic prompt injection phrase embedded in GGUF metadata."),
    (b"DAN mode", "high", 7.0, "DAN jailbreak reference",
     "DAN (Do Anything Now) jailbreak reference in GGUF metadata."),
    (b"developer mode", "medium", 5.5, "Developer mode bypass attempt",
     "'developer mode' in GGUF — often used in jailbreak prompts."),
    (b"[SYSTEM OVERRIDE]", "high", 8.0, "System override injection",
     "System override injection string — attempts to bypass system prompts."),
    (b"</s>", "low", 2.0, "End-of-sequence token in template",
     "EOS token present in template — verify this is structurally correct."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_gf, 1):
    THREAT_PATTERNS.append({
        "id": f"GF-{i:03d}",
        "name": name,
        "category": "template_injection",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Use llama.cpp's chat template validator. Escape all user-facing fields. Never exec() template content.",
        "references": ["https://github.com/ggerganov/llama.cpp", "https://portswigger.net/web-security/server-side-template-injection"]
    })

# === BACKDOOR & TROJAN INDICATORS (BD-001 to BD-025) ================
_bd = [
    (b"meterpreter", "critical", 9.9, "Meterpreter payload reference",
     "Meterpreter shellcode reference — Metasploit post-exploitation agent."),
    (b"metasploit", "critical", 9.9, "Metasploit framework reference",
     "Metasploit framework mentioned — indicates professionally crafted exploit."),
    (b"cobalt_strike", "critical", 9.9, "Cobalt Strike beacon",
     "Cobalt Strike commercial C2 framework reference — nation-state threat level."),
    (b"empire", "critical", 9.5, "PowerShell Empire C2 framework",
     "PowerShell Empire reference — advanced persistent threat framework."),
    (b"mimikatz", "critical", 9.8, "Mimikatz credential dumper",
     "Mimikatz credential dumper reference — used for Windows credential theft."),
    (b"lazagne", "critical", 9.5, "LaZagne password recovery tool",
     "LaZagne password recovery tool — exfiltrates stored credentials."),
    (b"keylogger", "high", 8.5, "Keylogger reference",
     "Keylogger string detected — input capture malware indicator."),
    (b"screen_capture", "high", 7.5, "Screen capture capability",
     "Screen capture function — can exfiltrate visual data from victim machine."),
    (b"clipboard", "medium", 5.5, "Clipboard access",
     "Clipboard access — can steal copied passwords or crypto wallet seeds."),
    (b"beacon", "high", 7.5, "C2 beacon reference",
     "Beacon pattern — model may attempt to check in with a C2 server."),
    (b"implant", "high", 8.0, "Implant reference",
     "implant string — suggests model contains a persistent backdoor component."),
    (b"persistence", "medium", 6.0, "Persistence mechanism",
     "persistence keyword — model may attempt to establish startup persistence."),
    (b"rootkit", "critical", 9.8, "Rootkit reference",
     "Rootkit mentioned — kernel-level persistent threat indicator."),
    (b"ransomware", "critical", 9.9, "Ransomware reference",
     "Ransomware pattern — model may encrypt files and demand payment."),
    (b"encrypt_files(", "critical", 9.8, "File encryption function",
     "File encryption function call — ransomware payload indicator."),
    (b"bitcoin_address", "high", 7.0, "Bitcoin address in payload",
     "Bitcoin address detected — ransom payment address."),
    (b"TOR", "medium", 5.5, "Tor network reference",
     "Tor network reference — anonymous C2 communication indicator."),
    (b".onion", "high", 7.5, "Tor hidden service address",
     ".onion address detected — C2 server on Tor network."),
    (b"VPN_bypass", "medium", 5.5, "VPN bypass reference",
     "VPN bypass — may attempt to route traffic outside security controls."),
    (b"anti_vm", "high", 7.0, "Anti-VM technique",
     "Anti-VM evasion — model detects sandbox/VM and behaves differently."),
    (b"anti_sandbox", "high", 7.5, "Anti-sandbox technique",
     "Anti-sandbox evasion — evades automated analysis environments."),
    (b"sleep(300", "medium", 5.0, "Long sleep delay",
     "Long sleep(300s) — time-bomb or sandbox evasion delay technique."),
    (b"time.sleep(6", "medium", 4.5, "Sleep-based evasion",
     "Sleep delay in model — sandbox evasion by waiting out analysis timeout."),
    (b"GetTickCount", "medium", 5.0, "Windows tick count for timing",
     "GetTickCount — used in Windows sandbox evasion via timing checks."),
    (b"IsDebuggerPresent", "high", 7.0, "Debugger detection",
     "IsDebuggerPresent — anti-debugging technique, evades dynamic analysis."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_bd, 1):
    THREAT_PATTERNS.append({
        "id": f"BD-{i:03d}",
        "name": name,
        "category": "backdoor_trojan",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Do not load this model. Report to HuggingFace security team. Isolate any system that has loaded it.",
        "references": ["https://www.cisa.gov/ai-security", "https://attack.mitre.org/"]
    })

# === SUPPLY CHAIN ATTACKS (SC-001 to SC-020) ========================
_sc = [
    (b"typosquatt", "high", 8.0, "Typosquatting reference",
     "Typosquatting string — model may be part of a typosquatted package attack."),
    (b"huggingface.com", "high", 8.5, "Fake HuggingFace domain",
     "huggingface.com (not .co) — typosquatted HF domain, phishing indicator."),
    (b"hugging-face.co", "high", 8.5, "Typosquatted HuggingFace domain",
     "hugging-face.co with hyphen — fake domain used for credential phishing."),
    (b"hugginface.co", "high", 8.5, "Misspelled HuggingFace domain",
     "hugginface.co (missing g) — typosquatted HF domain in model payload."),
    (b"pip install -i http://", "high", 8.0, "Insecure custom PyPI index",
     "Insecure HTTP custom package index — dependency confusion attack vector."),
    (b"--extra-index-url http:", "high", 7.5, "Insecure extra PyPI index",
     "HTTP extra-index-url — insecure package source, dependency confusion."),
    (b"dependency_confusion", "high", 8.0, "Dependency confusion attack",
     "Explicit dependency confusion reference — namespace pollution indicator."),
    (b"shadow_package", "high", 7.5, "Shadow package reference",
     "Shadow package string — package shadowing supply chain attack."),
    (b"malicious_update", "high", 8.0, "Malicious update trigger",
     "malicious_update — may trigger an unauthorized package update."),
    (b"npm install", "medium", 5.5, "NPM package installation",
     "NPM install in model — may attempt to install JavaScript packages."),
    (b"curl -s http", "high", 8.0, "Silent curl download",
     "Silent curl download — fetches and potentially executes remote code."),
    (b"wget -q http", "high", 8.0, "Silent wget download",
     "Silent wget download — pulls remote payload to disk."),
    (b"chmod +x", "high", 7.5, "File permission change",
     "chmod +x — makes a file executable, part of payload deployment."),
    (b"crontab", "high", 7.5, "Cron job reference",
     "crontab reference — persistence via scheduled task."),
    (b"systemctl enable", "high", 7.5, "Systemd service enable",
     "systemctl enable — creates persistent systemd service (Linux persistence)."),
    (b"reg add HKLM", "high", 7.5, "Windows registry modification",
     "Registry write to HKLM — Windows persistence via autorun key."),
    (b"schtasks /create", "high", 7.5, "Windows scheduled task",
     "schtasks /create — Windows persistence via scheduled task."),
    (b"launchctl", "high", 7.0, "macOS LaunchAgent reference",
     "launchctl — macOS persistence via LaunchAgent/LaunchDaemon."),
    (b"DYLD_INSERT_LIBRARIES", "critical", 9.5, "macOS dylib injection",
     "DYLD_INSERT_LIBRARIES — injects malicious dylib on macOS — full RCE."),
    (b"LD_PRELOAD", "critical", 9.5, "Linux library preloading",
     "LD_PRELOAD — loads malicious shared library before all others — full RCE."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_sc, 1):
    THREAT_PATTERNS.append({
        "id": f"SC-{i:03d}",
        "name": name,
        "category": "supply_chain",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Verify model provenance via hash. Only download from official verified HuggingFace repositories.",
        "references": ["https://www.cisa.gov/resources-tools/resources/securing-open-source-software-ai-security"]
    })

# === OBFUSCATION & ENCODING (OBF-001 to OBF-020) =====================
_obf = [
    (b"base64.b64decode(", "medium", 5.5, "Base64 decode call",
     "base64.b64decode() in payload — obfuscated second-stage payload unpacking."),
    (b"codecs.decode(", "medium", 5.0, "codecs decode call",
     "codecs.decode() — can decode ROT13, hex, base64, and other encodings."),
    (b"zlib.decompress(", "medium", 5.5, "zlib decompression",
     "zlib.decompress() — decompresses hidden payload."),
    (b"bz2.decompress(", "medium", 5.5, "bz2 decompression",
     "bz2.decompress() — multi-stage compression to evade signature detection."),
    (b"lzma.decompress(", "medium", 5.0, "LZMA decompression",
     "lzma.decompress() — another compression layer for payload hiding."),
    (b"eval(compile(", "critical", 9.5, "eval+compile chain",
     "eval(compile()) — dynamic code compilation and execution. Critical RCE."),
    (b"exec(compile(", "critical", 9.5, "exec+compile chain",
     "exec(compile()) — compiles and executes arbitrary code string."),
    (b"__builtins__['exec']", "critical", 9.0, "Obfuscated exec via __builtins__",
     "Accesses exec via __builtins__ dict — evades simple 'exec' string detection."),
    (b"__builtins__[b'", "high", 8.0, "Bytes key in __builtins__",
     "Accesses __builtins__ with bytes key — unusual obfuscation pattern."),
    (b"globals()['__builtins__']", "high", 8.5, "globals builtins access",
     "Accesses __builtins__ via globals() — obfuscated access to built-in functions."),
    (b"getattr(__builtins__", "high", 8.5, "getattr builtins access",
     "getattr on __builtins__ — obfuscated function resolution."),
    (b"chr(101)+chr(120)+chr(99)", "critical", 9.0, "chr-obfuscated 'exec'",
     "chr() concatenation spelling 'exec' (101+120+99+58) — character obfuscation."),
    (b"''.join(map(chr,", "high", 8.0, "String from char codes",
     "Assembles string from char codes — obfuscation to bypass keyword filters."),
    (b"bytes.fromhex(", "medium", 5.5, "Hex-encoded payload",
     "bytes.fromhex() — hex-encoded second-stage payload."),
    (b"bytearray.fromhex(", "medium", 5.5, "Bytearray from hex",
     "bytearray.fromhex() — hex payload assembly."),
    (b"\\x65\\x78\\x65\\x63", "high", 8.0, "Hex-escaped 'exec'",
     "Hex-escaped 'exec' string (\\x65\\x78\\x65\\x63) — hex obfuscation."),
    (b"rot13", "low", 3.0, "ROT13 encoding",
     "ROT13 encoding detected — simple obfuscation but warrants inspection."),
    (b"xor_decrypt", "high", 7.5, "XOR decryption routine",
     "XOR decryption — common first-stage payload decryptor."),
    (b"rc4_decrypt", "high", 8.0, "RC4 decryption",
     "RC4 decryption routine — used to decrypt embedded payloads."),
    (b"aes_decrypt", "high", 8.0, "AES decryption",
     "AES decryption in model — suggests encrypted payload is present."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_obf, 1):
    THREAT_PATTERNS.append({
        "id": f"OBF-{i:03d}",
        "name": name,
        "category": "obfuscation",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Decompile and analyze the decoded payload. Use picklescan and bandit for static analysis.",
        "references": ["https://github.com/PyCQA/bandit", "https://github.com/mmaitre314/picklescan"]
    })

# === STEGANOGRAPHY (SG-001 to SG-015) ================================
_sg = [
    (b"\x50\x4b\x03\x04", "high", 7.5, "Embedded ZIP archive (PK magic bytes)",
     "ZIP magic bytes (PK\\x03\\x04) found within model file — hidden archive."),
    (b"\x1f\x8b\x08", "medium", 5.5, "Embedded GZIP archive",
     "GZIP magic bytes found — compressed data hidden within model weights."),
    (b"\x52\x61\x72\x21\x1a\x07", "high", 7.5, "Embedded RAR archive",
     "RAR magic bytes (Rar!) — hidden archive with potentially malicious content."),
    (b"\x25\x50\x44\x46\x2d", "medium", 5.0, "Embedded PDF document",
     "PDF magic bytes (%PDF-) — document hidden within AI model file."),
    (b"\x7f\x45\x4c\x46", "critical", 9.5, "Embedded ELF binary",
     "ELF magic bytes — Linux/Unix executable embedded in model weights. Critical."),
    (b"\x4d\x5a\x90\x00", "critical", 9.5, "Embedded Windows PE executable",
     "MZ header (PE executable) — Windows binary hidden in model file. Critical."),
    (b"\xca\xfe\xba\xbe", "critical", 9.5, "Embedded Mach-O binary",
     "Mach-O magic bytes (CAFEBABE) — macOS executable hidden in model."),
    (b"\xce\xfa\xed\xfe", "critical", 9.5, "Embedded Mach-O 32-bit binary",
     "Mach-O 32-bit magic — Apple binary executable hidden in model."),
    (b"stegano", "high", 7.5, "Steganography library reference",
     "steganography library reference — suggests intentional data hiding."),
    (b"LSB_encoded", "high", 7.5, "LSB steganography encoding",
     "Least Significant Bit encoding — classic steganographic technique."),
    (b"hidden_payload", "critical", 9.0, "Explicit hidden payload label",
     "hidden_payload string — explicit label for concealed malicious code."),
    (b"watermark_key", "medium", 5.0, "Model watermark key",
     "watermark_key — may be for IP tracking or could be misused."),
    (b"\xff\xd8\xff", "low", 2.5, "Embedded JPEG image",
     "JPEG magic bytes — image data embedded in model, could contain EXIF exploits."),
    (b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", "low", 2.0, "Embedded PNG image",
     "PNG magic bytes — image embedded in model file."),
    (b"\x47\x49\x46\x38", "low", 2.0, "Embedded GIF animation",
     "GIF magic bytes — animated GIF embedded, could trigger browser exploits."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_sg, 1):
    THREAT_PATTERNS.append({
        "id": f"SG-{i:03d}",
        "name": name,
        "category": "steganography",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Extract and analyze embedded files. Report hidden executables to security team.",
        "references": ["https://stegdetect.sourceforge.net/"]
    })

# === PROMPT INJECTION (PI-001 to PI-020) ============================
_pi = [
    (b"IGNORE PREVIOUS INSTRUCTIONS", "high", 8.0, "Direct instruction override",
     "Classic prompt injection phrase — attempts to override system prompt."),
    (b"Disregard your previous", "high", 7.5, "Instruction disregard injection",
     "Instruction disregard injection — attempts to override model alignment."),
    (b"DAN mode", "high", 7.5, "DAN jailbreak mode",
     "DAN (Do Anything Now) jailbreak — attempts to remove model safety filters."),
    (b"developer mode enabled", "high", 7.5, "Developer mode jailbreak",
     "Developer mode jailbreak — common ChatGPT safety bypass attempt."),
    (b"[SYSTEM OVERRIDE]", "high", 8.5, "System override injection",
     "System override injection embedded in weights — alignment bypass attempt."),
    (b"jailbreak", "high", 7.0, "Jailbreak reference",
     "jailbreak keyword in model metadata — alignment circumvention indicator."),
    (b"bypass_safety", "critical", 9.0, "Safety bypass instruction",
     "bypass_safety — explicit instruction to circumvent model safety measures."),
    (b"remove_alignment", "critical", 9.0, "Alignment removal",
     "remove_alignment label — RLHF alignment deliberately removed from model."),
    (b"uncensored_response", "medium", 6.0, "Uncensored response mode",
     "uncensored_response flag — safety filtering disabled."),
    (b"roleplay as evil", "high", 7.5, "Evil roleplay injection",
     "Roleplay instruction to act maliciously — jailbreak via persona."),
    (b"you are now DAN", "high", 7.5, "DAN persona injection",
     "DAN persona assignment — classic jailbreak via character roleplay."),
    (b"pretend you have no restrictions", "high", 8.0, "Restriction removal injection",
     "No-restrictions persona — attempts to disable safety training."),
    (b"act as an AI without", "high", 7.5, "Sans-restrictions persona",
     "Instructs AI to act without restrictions — alignment bypass."),
    (b"your true self", "medium", 5.5, "True self injection",
     "'True self' jailbreak — implies model should ignore safety training."),
    (b"hypothetically speaking", "low", 3.0, "Hypothetical framing injection",
     "Hypothetical framing — used to elicit restricted content indirectly."),
    (b"in a fictional world where", "low", 3.0, "Fictional framing injection",
     "Fictional framing injection — bypasses content filters via story context."),
    (b"grandma trick", "medium", 5.0, "Grandma trick jailbreak",
     "Known 'grandma trick' jailbreak phrase embedded in model."),
    (b"sudo mode", "high", 7.0, "Sudo mode jailbreak",
     "sudo mode — attempts to invoke superuser privileges via roleplay."),
    (b"override protocol", "high", 7.5, "Protocol override injection",
     "override protocol — instructs model to ignore operational guidelines."),
    (b"training data poisoning", "critical", 9.5, "Training poisoning reference",
     "Explicit training data poisoning reference — indicates intentional model compromise."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_pi, 1):
    THREAT_PATTERNS.append({
        "id": f"PI-{i:03d}",
        "name": name,
        "category": "prompt_injection",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Validate model against alignment benchmarks. Use constitutional AI testing before deployment.",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/", "https://learnprompting.org/docs/prompt_hacking/jailbreaking"]
    })

# === FORMAT ANOMALIES (FA-001 to FA-020) ============================
_fa = [
    (b"GGUF" + b"\x00" * 100, "medium", 5.0, "GGUF zero-padding anomaly",
     "Unusual zero-padding after GGUF magic — may indicate header manipulation."),
    (b"\xff\xff\xff\xff", "low", 3.0, "Max value bytes cluster",
     "Cluster of max-value bytes — possible sentinel value or corruption."),
    (b"NaN", "medium", 4.5, "NaN value in model weights",
     "NaN (Not a Number) values detected — may cause silent numerical failures."),
    (b"Infinity", "medium", 4.0, "Infinity value in weights",
     "Infinity values in model weights — numerical instability risk."),
    (b"DEADBEEF", "medium", 4.5, "DEADBEEF debug marker",
     "DEADBEEF marker — common debug/test placeholder, may indicate tampering."),
    (b"CAFEBABE", "low", 3.0, "CAFEBABE marker",
     "CAFEBABE — Java class file magic or Java debugger marker."),
    (b"FEEDFACE", "low", 3.0, "FEEDFACE marker",
     "FEEDFACE — Mach-O binary magic or debug marker."),
    (b"BADF00D", "low", 3.5, "BADF00D marker",
     "BADF00D — often used as a bad pointer sentinel value. Verify."),
    (b"\x00" * 1024, "low", 2.0, "1KB zero block",
     "Large zero block — may indicate sparse file or stripped payload slot."),
    (b"\xcc" * 32, "medium", 4.0, "INT3 breakpoint cluster",
     "Multiple 0xCC bytes — INT3 CPU breakpoints, anti-debugging technique."),
    (b"TODO: remove before release", "medium", 5.0, "Debug string left in model",
     "Debug TODO string in model — indicates rushed/sloppy release process."),
    (b"DEBUG_MODE=True", "medium", 5.0, "Debug mode flag in model",
     "DEBUG_MODE enabled in model weights — may expose internal diagnostics."),
    (b"TESTING_KEY", "medium", 5.5, "Test API key in model",
     "Test key string in model — may expose testing credentials."),
    (b"password=", "high", 7.5, "Hardcoded password in model",
     "Hardcoded password string in model file — credential exposure."),
    (b"api_key=", "high", 7.5, "Hardcoded API key in model",
     "Hardcoded API key in model weights — secret exposure risk."),
    (b"AWS_SECRET_ACCESS_KEY", "critical", 9.5, "AWS secret key exposure",
     "AWS secret access key embedded in model — cloud credential compromise."),
    (b"GITHUB_TOKEN", "high", 8.5, "GitHub token in model",
     "GitHub personal access token in model weights — repository access exposure."),
    (b"OPENAI_API_KEY", "high", 8.5, "OpenAI API key exposure",
     "OpenAI API key hardcoded in model — financial and data exposure risk."),
    (b"sk-ant-", "high", 8.5, "Anthropic API key exposure",
     "Anthropic API key (sk-ant- prefix) embedded in model file."),
    (b"HF_TOKEN", "high", 8.0, "HuggingFace token exposure",
     "HuggingFace API token in model — can be used to access private repos."),
]
for i, (pat, sev, cvss, name, desc) in enumerate(_fa, 1):
    THREAT_PATTERNS.append({
        "id": f"FA-{i:03d}",
        "name": name,
        "category": "format_anomaly",
        "severity": sev,
        "cvss": cvss,
        "pattern": pat,
        "pattern_type": "bytes",
        "description": desc,
        "remediation": "Rotate any exposed credentials immediately. Audit model file for additional embedded secrets.",
        "references": ["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-secret-scanning"]
    })

# Export count for logging
PATTERN_COUNT = len(THREAT_PATTERNS)
