from __future__ import annotations

import ast
import hashlib
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from vuln_swarm.core.config import Settings
from vuln_swarm.schemas import Evidence, Severity, Vulnerability


IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
}

TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".env",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".json",
    ".txt",
}

VULN_META: dict[str, tuple[str, str, Severity, str]] = {
    "CP-001": ("SQL Injection", "Code Pattern", Severity.critical, "CWE-89"),
    "CP-002": ("Command Injection", "Code Pattern", Severity.critical, "CWE-78"),
    "CP-003": ("Server-Side Template Injection", "Code Pattern", Severity.critical, "CWE-94"),
    "CP-004": ("Path Traversal", "Code Pattern", Severity.high, "CWE-22"),
    "CP-005": ("Cross-Site Scripting", "Code Pattern", Severity.high, "CWE-79"),
    "CP-006": ("Insecure Deserialisation", "Code Pattern", Severity.critical, "CWE-502"),
    "CP-008": ("Missing Rate Limiting", "Code Pattern", Severity.medium, "CWE-770"),
    "DEP-003": ("Unpinned Dependency Version", "Dependency", Severity.medium, "CWE-1357"),
    "DEP-004": ("Dependency Without Hash Pinning", "Dependency", Severity.medium, "CWE-494"),
    "SEC-001": ("Hardcoded API Key or Token", "Secret", Severity.critical, "CWE-798"),
    "SEC-002": ("Hardcoded Password", "Secret", Severity.critical, "CWE-259"),
    "CFG-001": ("Docker Container Running as Root", "Configuration", Severity.high, "CWE-250"),
    "CFG-002": ("Unpinned Docker Base Image", "Configuration", Severity.high, "CWE-494"),
    "CFG-003": ("CORS Wildcard Origin", "Configuration", Severity.high, "CWE-942"),
    "CFG-004": ("Debug Mode Enabled", "Configuration", Severity.high, "CWE-215"),
    "TRB-001": ("Dynamic Code Evaluation", "Trust Boundary", Severity.critical, "CWE-95"),
    "TRB-002": ("Unsafe yaml.load", "Trust Boundary", Severity.critical, "CWE-502"),
    "TRB-003": ("Unsafe pickle.loads", "Trust Boundary", Severity.critical, "CWE-502"),
    "URL-001": ("Hardcoded HTTP URL", "URL", Severity.medium, "CWE-319"),
    "URL-002": ("Internal Address Exposed", "URL", Severity.medium, "CWE-200"),
}


@dataclass(frozen=True)
class Finding:
    vuln_id: str
    file_path: str
    line: int | None
    detector: str
    confidence: float
    description: str
    excerpt: str | None = None
    remediation_hint: str | None = None


class StaticAnalyzer:
    def __init__(self, settings: Settings):
        self.settings = settings

    def scan(self, repo_path: Path) -> list[Vulnerability]:
        findings: list[Finding] = []
        files = list(self._iter_files(repo_path))
        for path in files[: self.settings.max_files_per_scan]:
            rel = path.relative_to(repo_path).as_posix()
            if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
                findings.extend(self._scan_dockerfile(path, rel))
                continue
            if path.name in {"requirements.txt", "requirements-prod.txt"}:
                findings.extend(self._scan_requirements(path, rel))
            if path.suffix == ".py":
                findings.extend(self._scan_python(path, rel))
            if path.suffix in TEXT_EXTENSIONS or path.name.startswith(".env"):
                findings.extend(self._scan_text(path, rel))

        return [self._finding_to_vulnerability(finding) for finding in self._dedupe(findings)]

    def _iter_files(self, repo_path: Path) -> Iterable[Path]:
        for path in repo_path.rglob("*"):
            if not path.is_file():
                continue
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            try:
                if path.stat().st_size > self.settings.max_file_bytes:
                    continue
            except OSError:
                continue
            if path.suffix in TEXT_EXTENSIONS or path.name in {"Dockerfile", "requirements.txt"}:
                yield path

    def _scan_python(self, path: Path, rel: str) -> list[Finding]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return []
        visitor = PythonSecurityVisitor(rel, lines)
        visitor.visit(tree)
        return visitor.findings

    def _scan_requirements(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for index, line in self._iter_requirement_entries(lines):
            if not line or line.startswith("#"):
                continue
            if "--hash=sha256:" not in line:
                findings.append(
                    Finding(
                        vuln_id="DEP-004",
                        file_path=rel,
                        line=index,
                        detector="dependency-hash",
                        confidence=0.82,
                        description="Production dependency entry lacks pip hash pinning.",
                        excerpt=line,
                        remediation_hint="Regenerate requirements with pip-compile --generate-hashes.",
                    )
                )
            if "==" not in line or any(operator in line for operator in (">=", "<=", "~=", ">")):
                findings.append(
                    Finding(
                        vuln_id="DEP-003",
                        file_path=rel,
                        line=index,
                        detector="dependency-pin",
                        confidence=0.86,
                        description="Dependency version is floating or range-based.",
                        excerpt=line,
                        remediation_hint="Pin to a reviewed version and include hashes.",
                    )
                )
        return findings

    def _iter_requirement_entries(self, lines: list[str]) -> Iterable[tuple[int, str]]:
        start_line: int | None = None
        current_parts: list[str] = []
        for index, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                if current_parts and start_line is not None:
                    yield start_line, " ".join(current_parts)
                    current_parts = []
                    start_line = None
                continue

            if not current_parts:
                if line.startswith("-"):
                    continue
                start_line = index
            current_parts.append(line.rstrip("\\").strip())
            if not raw.rstrip().endswith("\\") and start_line is not None:
                yield start_line, " ".join(current_parts)
                current_parts = []
                start_line = None

        if current_parts and start_line is not None:
            yield start_line, " ".join(current_parts)

    def _scan_dockerfile(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        from_lines = [(i, line.strip()) for i, line in enumerate(lines, start=1) if line.strip().upper().startswith("FROM ")]
        for index, line in from_lines:
            if "@sha256:" not in line:
                findings.append(
                    Finding(
                        vuln_id="CFG-002",
                        file_path=rel,
                        line=index,
                        detector="docker-base-pin",
                        confidence=0.9,
                        description="Docker base image is not pinned by digest.",
                        excerpt=line,
                        remediation_hint="Pin the base image with an immutable sha256 digest.",
                    )
                )
        user_lines = [line for line in lines if line.strip().upper().startswith("USER ")]
        if not user_lines or any(line.strip().lower() == "user root" for line in user_lines):
            findings.append(
                Finding(
                    vuln_id="CFG-001",
                    file_path=rel,
                    line=None,
                    detector="docker-user",
                    confidence=0.85,
                    description="Container runs as root by default.",
                    excerpt="No non-root USER directive found.",
                    remediation_hint="Create and switch to a non-root user in the final runtime stage.",
                )
            )
        return findings

    def _scan_text(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        for index, line in enumerate(lines, start=1):
            if self._is_test_path(rel):
                context_factor = 0.55
            else:
                context_factor = 1.0
            if re.search(r"(?i)(cors|allow_origins|origins).{0,40}['\"]\*['\"]", line):
                findings.append(
                    Finding(
                        vuln_id="CFG-003",
                        file_path=rel,
                        line=index,
                        detector="cors-wildcard",
                        confidence=0.84 * context_factor,
                        description="Wildcard CORS origin detected.",
                        excerpt=line.strip(),
                        remediation_hint="Restrict CORS origins to explicit trusted domains.",
                    )
                )
            if re.search(r"(?i)\bdebug\s*=\s*true\b|debug=True", line):
                findings.append(
                    Finding(
                        vuln_id="CFG-004",
                        file_path=rel,
                        line=index,
                        detector="debug-mode",
                        confidence=0.86 * context_factor,
                        description="Debug mode appears enabled.",
                        excerpt=line.strip(),
                        remediation_hint="Disable debug mode in production settings.",
                    )
                )
            if "http://" in line and not self._is_documentation_path(rel):
                findings.append(
                    Finding(
                        vuln_id="URL-001",
                        file_path=rel,
                        line=index,
                        detector="cleartext-url",
                        confidence=0.72 * context_factor,
                        description="Cleartext HTTP URL found in application files.",
                        excerpt=self._redact(line.strip()),
                        remediation_hint="Use HTTPS for service URLs unless this is a local-only test fixture.",
                    )
                )
            if re.search(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)\b", line) and not self._is_test_path(rel):
                findings.append(
                    Finding(
                        vuln_id="URL-002",
                        file_path=rel,
                        line=index,
                        detector="internal-address",
                        confidence=0.7,
                        description="Internal service address appears in production code.",
                        excerpt=self._redact(line.strip()),
                        remediation_hint="Move internal addresses into deployment configuration.",
                    )
                )
            secret_finding = self._detect_secret(line, rel, index, context_factor)
            if secret_finding:
                findings.append(secret_finding)
        return findings

    def _detect_secret(
        self, line: str, rel: str, index: int, context_factor: float
    ) -> Finding | None:
        if self._is_documentation_path(rel) or "placeholder" in line.lower():
            return None
        context_match = re.search(
            r"(?i)(api[_-]?key|token|secret|password|passwd|pwd|credential|auth).{0,20}[:=]\s*['\"]([^'\"]{8,})['\"]",
            line,
        )
        service_match = re.search(
            r"(sk-ant-[A-Za-z0-9_\-]{12,}|sk-proj-[A-Za-z0-9_\-]{12,}|ghp_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xoxb-[A-Za-z0-9\-]{16,}|SG\.[A-Za-z0-9_\-]{16,})",
            line,
        )
        candidate = ""
        if context_match:
            candidate = context_match.group(2)
        elif service_match:
            candidate = service_match.group(1)
        if not candidate:
            return None
        entropy = shannon_entropy(candidate)
        if service_match or entropy >= 4.2:
            vuln_id = "SEC-002" if "pass" in line.lower() or "pwd" in line.lower() else "SEC-001"
            return Finding(
                vuln_id=vuln_id,
                file_path=rel,
                line=index,
                detector="secret-fusion",
                confidence=min(0.98, (entropy / 5.2) * context_factor),
                description="Potential hardcoded credential detected using entropy and context fusion.",
                excerpt=self._redact(line.strip()),
                remediation_hint="Read the value from a secret manager or environment variable and rotate it.",
            )
        return None

    def _finding_to_vulnerability(self, finding: Finding) -> Vulnerability:
        title, category, severity, cwe = VULN_META[finding.vuln_id]
        stable = hashlib.sha256(
            f"{finding.vuln_id}:{finding.file_path}:{finding.line}:{finding.detector}".encode()
        ).hexdigest()[:12]
        return Vulnerability(
            id=f"{finding.vuln_id}-{stable}",
            vuln_id=finding.vuln_id,
            title=title,
            category=category,
            cwe=cwe,
            severity=severity,
            description=finding.description,
            affected_files=[finding.file_path],
            evidence=[
                Evidence(
                    file_path=finding.file_path,
                    line_start=finding.line,
                    line_end=finding.line,
                    code_excerpt=finding.excerpt,
                    detector=finding.detector,
                    confidence=finding.confidence,
                )
            ],
            remediation_hint=finding.remediation_hint,
        )

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, int | None, str]] = set()
        deduped: list[Finding] = []
        for finding in findings:
            key = (finding.vuln_id, finding.file_path, finding.line, finding.detector)
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        return deduped

    def _redact(self, value: str) -> str:
        return re.sub(
            r"(['\"])([^'\"]{4})[^'\"]{6,}([^'\"]{2})(['\"])",
            lambda match: f"{match.group(1)}{match.group(2)}...{match.group(3)}{match.group(4)}",
            value,
        )

    def _is_test_path(self, rel: str) -> bool:
        lowered = rel.lower()
        return "/test" in lowered or lowered.startswith("test") or ".test." in lowered or ".spec." in lowered

    def _is_documentation_path(self, rel: str) -> bool:
        lowered = rel.lower()
        return lowered.endswith((".md", ".rst")) or "/docs/" in lowered


class PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list[str]):
        self.rel = rel
        self.lines = lines
        self.query_vars: set[str] = set()
        self.user_vars: set[str] = set()
        self.findings: list[Finding] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        if is_dynamic_sql_expr(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.query_vars.add(target.id)
        if expression_references_request(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.user_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = get_call_name(node.func)
        if call_name in {"eval", "exec"} and node.args and not isinstance(node.args[0], ast.Constant):
            self.add(
                "TRB-001",
                node,
                "Dynamic code execution receives non-literal input.",
                "Replace eval/exec with a typed parser or explicit dispatch table.",
                "python-ast-eval",
                0.9,
            )
        if call_name in {"yaml.load"} and not has_safe_yaml_loader(node):
            self.add(
                "TRB-002",
                node,
                "yaml.load is called without SafeLoader.",
                "Use yaml.safe_load or yaml.load(..., Loader=yaml.SafeLoader).",
                "python-ast-yaml",
                0.94,
            )
        if call_name in {"pickle.load", "pickle.loads"}:
            self.add(
                "TRB-003",
                node,
                "Unsafe pickle deserialisation can execute code.",
                "Replace pickle with JSON or a signed, typed serialization format.",
                "python-ast-pickle",
                0.88,
            )
        if call_name in {"os.system", "os.popen"} or is_subprocess_shell(node, call_name):
            self.add(
                "CP-002",
                node,
                "User-controlled data may reach a shell command sink.",
                "Bypass the shell and pass arguments as an array to subprocess APIs.",
                "python-ast-command",
                0.86,
            )
        if is_sql_execute_call(node, call_name, self.query_vars):
            self.add(
                "CP-001",
                node,
                "SQL query appears to be built with string interpolation or concatenation.",
                "Use parameterized queries or ORM query builders.",
                "python-ast-sqli",
                0.84,
            )
        if call_name in {"open", "Path.open"} and node.args and expression_has_userish_name(node.args[0]):
            self.add(
                "CP-004",
                node,
                "File access appears to use user-controlled path data.",
                "Resolve paths with a realpath jail before opening files.",
                "python-ast-path",
                0.68,
            )
        if call_name in {"render_template_string", "jinja2.Template", "Template"}:
            self.add(
                "CP-003" if "CP-003" in VULN_META else "TRB-001",
                node,
                "Template engine receives dynamic template input.",
                "Use a sandboxed environment and pass user input as data, not as template code.",
                "python-ast-ssti",
                0.76,
            )
        self.generic_visit(node)

    def add(
        self,
        vuln_id: str,
        node: ast.AST,
        description: str,
        remediation_hint: str,
        detector: str,
        confidence: float,
    ) -> None:
        line = getattr(node, "lineno", None)
        excerpt = self.lines[line - 1].strip() if line and 0 < line <= len(self.lines) else None
        self.findings.append(
            Finding(
                vuln_id=vuln_id,
                file_path=self.rel,
                line=line,
                detector=detector,
                confidence=confidence,
                description=description,
                excerpt=excerpt,
                remediation_hint=remediation_hint,
            )
        )


def get_call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = get_call_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def is_dynamic_sql_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    if isinstance(node, ast.Call) and get_call_name(node.func).endswith(".format"):
        return True
    return False


def expression_references_request(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in {"request", "req", "input", "user_input"}:
            return True
        if isinstance(child, ast.Attribute) and child.attr in {"args", "form", "json", "GET", "POST"}:
            return True
    return False


def expression_has_userish_name(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and re.search(r"(?i)(user|input|file|path|name|request)", child.id):
            return True
        if isinstance(child, ast.Attribute) and child.attr in {"args", "form", "json", "files"}:
            return True
    return False


def is_sql_execute_call(node: ast.Call, call_name: str, query_vars: set[str]) -> bool:
    if not call_name.endswith(".execute") and call_name not in {"execute"}:
        return False
    if not node.args:
        return False
    first = node.args[0]
    return (
        is_dynamic_sql_expr(first)
        or (isinstance(first, ast.Name) and first.id in query_vars)
        or (isinstance(first, ast.Constant) and isinstance(first.value, str) and "%" in first.value)
    )


def has_safe_yaml_loader(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "Loader" and "SafeLoader" in ast.unparse(keyword.value):
            return True
    return False


def is_subprocess_shell(node: ast.Call, call_name: str) -> bool:
    if not call_name.startswith("subprocess."):
        return False
    for keyword in node.keywords:
        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
            return True
    return bool(node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
