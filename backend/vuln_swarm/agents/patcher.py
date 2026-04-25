from __future__ import annotations

import ast
import configparser
import copy
from importlib import metadata
from pathlib import Path
import re
import shutil
import tomllib
import subprocess
import sys
import tempfile

import httpx
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import Specifier
from packaging.version import InvalidVersion, Version
from pydantic import Field

from vuln_swarm.schemas import AppliedFix, PatchOperation, RagCitation, StrictModel, Vulnerability


class LlmPatchPlan(StrictModel):
    operations: list[PatchOperation] = Field(default_factory=list)
    summary: str


INTERNAL_ADDRESS_PATTERN = re.compile(
    r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)"
)
STRING_LITERAL_PATTERN = re.compile(r"(?P<quote>[\"'])(?P<value>[^\"']*)(?P=quote)")


class DeterministicPatchApplier:
    def __init__(self, *, python_executable: str | None = None):
        self.python_executable = python_executable or sys.executable
        self._requirements_cache: dict[str, tuple[list[PatchOperation], str, str | None]] = {}

    def apply(
        self,
        *,
        repo_path: Path,
        vulnerability: Vulnerability,
        citations: list[RagCitation],
    ) -> AppliedFix:
        operations: list[PatchOperation] = []
        status = "manual_required"
        strategy = "manual-review"
        notes: str | None = None

        if vulnerability.vuln_id == "TRB-002":
            operations, status = self._patch_yaml_loader(repo_path, vulnerability)
            strategy = "yaml-safe-loader"
        elif vulnerability.vuln_id == "TRB-001":
            operations, status = self._patch_eval(repo_path, vulnerability)
            strategy = "literal-eval-or-manual-dispatch"
        elif vulnerability.vuln_id == "CFG-004":
            operations, status = self._replace_line_text(repo_path, vulnerability, "debug=True", "debug=False")
            strategy = "disable-debug"
        elif vulnerability.vuln_id == "CFG-003":
            operations, status = self._replace_line_text(
                repo_path,
                vulnerability,
                "['*']",
                "['http://localhost:5173']",
                alternate_original='"*"',
                alternate_replacement='"http://localhost:5173"',
            )
            strategy = "restrict-cors-origin"
        elif vulnerability.vuln_id == "URL-002":
            operations, status, notes = self._patch_internal_address_exposure(repo_path, vulnerability)
            strategy = "externalize-internal-address"
        elif vulnerability.vuln_id in {"DEP-003", "DEP-004"}:
            operations, status, notes = self._patch_requirements_lockfile(repo_path, vulnerability)
            strategy = "piptools-compile-hashes"
        else:
            operations.append(
                PatchOperation(
                    file_path=vulnerability.affected_files[0] if vulnerability.affected_files else "",
                    operation="manual_required",
                    rationale=(
                        "No deterministic patcher is registered for this vulnerability class. "
                        "The Gemini patch planner can produce exact replacements when configured."
                    ),
                )
            )
            notes = vulnerability.remediation_hint

        return AppliedFix(
            vulnerability_id=vulnerability.id,
            file_path=vulnerability.affected_files[0] if vulnerability.affected_files else "",
            strategy=strategy,
            operations=operations,
            rag_citations=citations[:3],
            status=status,  # type: ignore[arg-type]
            notes=notes,
        )

    def apply_llm_operations(self, *, repo_path: Path, operations: list[PatchOperation]) -> list[PatchOperation]:
        applied: list[PatchOperation] = []
        for operation in operations:
            safe_path = self._safe_path(repo_path, operation.file_path)
            if operation.operation == "manual_required" or not operation.replacement:
                applied.append(operation)
                continue
            if operation.operation == "append":
                existing = safe_path.read_text(encoding="utf-8", errors="ignore") if safe_path.exists() else ""
                safe_path.parent.mkdir(parents=True, exist_ok=True)
                safe_path.write_text(existing.rstrip() + "\n" + operation.replacement.rstrip() + "\n", encoding="utf-8")
                applied.append(operation.model_copy(update={"applied": True}))
                continue
            if not safe_path.exists() or operation.original is None:
                applied.append(operation)
                continue
            text = safe_path.read_text(encoding="utf-8", errors="ignore")
            if operation.operation == "replace" and operation.original in text:
                safe_path.write_text(text.replace(operation.original, operation.replacement, 1), encoding="utf-8")
                applied.append(operation.model_copy(update={"applied": True}))
            elif operation.operation == "insert_after" and operation.original in text:
                replacement = operation.original + operation.replacement
                safe_path.write_text(text.replace(operation.original, replacement, 1), encoding="utf-8")
                applied.append(operation.model_copy(update={"applied": True}))
            else:
                applied.append(operation)
        return applied

    def _patch_yaml_loader(self, repo_path: Path, vulnerability: Vulnerability) -> tuple[list[PatchOperation], str]:
        file_path = vulnerability.affected_files[0] if vulnerability.affected_files else ""
        safe_path = self._safe_path(repo_path, file_path)
        text = safe_path.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return [self._manual(file_path, "Python parse failed; manual YAML remediation required.")], "manual_required"
        lines = text.splitlines()
        operations: list[PatchOperation] = []
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if ast.unparse(node.func) != "yaml.load" or any(keyword.arg == "Loader" for keyword in node.keywords):
                continue
            line_no = getattr(node, "lineno", None)
            if not line_no:
                continue
            original = lines[line_no - 1]
            replacement = original.replace("yaml.load(", "yaml.safe_load(", 1)
            lines[line_no - 1] = replacement
            changed = True
            operations.append(
                PatchOperation(
                    file_path=file_path,
                    operation="replace",
                    original=original,
                    replacement=replacement,
                    rationale="Replace unsafe yaml.load with yaml.safe_load.",
                    applied=True,
                )
            )
        if changed:
            safe_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return operations, "applied"
        return [self._manual(file_path, "No unsafe yaml.load call found at patch time.")], "manual_required"

    def _patch_eval(self, repo_path: Path, vulnerability: Vulnerability) -> tuple[list[PatchOperation], str]:
        file_path = vulnerability.affected_files[0] if vulnerability.affected_files else ""
        safe_path = self._safe_path(repo_path, file_path)
        text = safe_path.read_text(encoding="utf-8", errors="ignore")
        if "eval(" not in text:
            return [self._manual(file_path, "No eval call found at patch time.")], "manual_required"
        replacement_text = text.replace("eval(", "ast.literal_eval(", 1)
        if "import ast" not in replacement_text:
            replacement_text = "import ast\n" + replacement_text
        safe_path.write_text(replacement_text, encoding="utf-8")
        return [
            PatchOperation(
                file_path=file_path,
                operation="replace",
                original="eval(",
                replacement="ast.literal_eval(",
                rationale="Replace dynamic eval with literal parsing for data-only payloads.",
                applied=True,
            )
        ], "applied"

    def _replace_line_text(
        self,
        repo_path: Path,
        vulnerability: Vulnerability,
        original: str,
        replacement: str,
        *,
        alternate_original: str | None = None,
        alternate_replacement: str | None = None,
    ) -> tuple[list[PatchOperation], str]:
        file_path = vulnerability.affected_files[0] if vulnerability.affected_files else ""
        safe_path = self._safe_path(repo_path, file_path)
        text = safe_path.read_text(encoding="utf-8", errors="ignore")
        target = original if original in text else alternate_original
        replace_with = replacement if original in text else alternate_replacement
        if target and replace_with and target in text:
            safe_path.write_text(text.replace(target, replace_with, 1), encoding="utf-8")
            return [
                PatchOperation(
                    file_path=file_path,
                    operation="replace",
                    original=target,
                    replacement=replace_with,
                    rationale="Apply deterministic configuration hardening.",
                    applied=True,
                )
            ], "applied"
        return [self._manual(file_path, "Pattern was not found for deterministic replacement.")], "manual_required"

    def _patch_internal_address_exposure(
        self,
        repo_path: Path,
        vulnerability: Vulnerability,
    ) -> tuple[list[PatchOperation], str, str | None]:
        file_path = vulnerability.affected_files[0] if vulnerability.affected_files else ""
        safe_path = self._safe_path(repo_path, file_path)
        text = safe_path.read_text(encoding="utf-8", errors="ignore")
        target_line = self._find_internal_address_line(text, vulnerability)
        if target_line is None:
            return [self._manual(file_path, "No internal address literal found at patch time.")], "manual_required", vulnerability.remediation_hint

        suffix = safe_path.suffix.lower()
        if suffix in {".js", ".jsx", ".ts", ".tsx"}:
            replacement_line, env_var = self._rewrite_internal_address_for_javascript(target_line)
            updated_text = text.replace(target_line, replacement_line, 1)
        elif suffix == ".py":
            replacement_line, env_var = self._rewrite_internal_address_for_python(target_line)
            updated_text = text.replace(target_line, replacement_line, 1)
            updated_text = self._ensure_python_import(updated_text, "import os")
        else:
            return [self._manual(file_path, "Internal address auto-remediation currently supports JS/TS and Python files.")], "manual_required", vulnerability.remediation_hint

        if replacement_line == target_line:
            return [self._manual(file_path, "Could not derive a safe environment-backed replacement for the internal address literal.")], "manual_required", vulnerability.remediation_hint

        safe_path.write_text(updated_text, encoding="utf-8")
        notes = f"Removed internal address literal; configure {env_var} in deployment if a custom target is required."
        return [
            PatchOperation(
                file_path=file_path,
                operation="replace",
                original=target_line,
                replacement=replacement_line,
                rationale="Move internal network defaults into deployment configuration and keep only public-safe fallback values in source.",
                applied=True,
            )
        ], "applied", notes

    def _find_internal_address_line(self, text: str, vulnerability: Vulnerability) -> str | None:
        for evidence in vulnerability.evidence:
            if evidence.code_excerpt and evidence.code_excerpt in text:
                return evidence.code_excerpt
        for line in text.splitlines():
            if INTERNAL_ADDRESS_PATTERN.search(line):
                return line
        return None

    def _rewrite_internal_address_for_javascript(self, line: str) -> tuple[str, str]:
        return self._rewrite_internal_address_line(
            line,
            assignment_pattern=r"^\s*(?:(?:const|let|var)\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*=",
            env_builder=lambda env_var, fallback: f'process.env.{env_var} || "{fallback}"',
        )

    def _rewrite_internal_address_for_python(self, line: str) -> tuple[str, str]:
        return self._rewrite_internal_address_line(
            line,
            assignment_pattern=r"^\s*(?P<name>[A-Za-z_]\w*)\s*=",
            env_builder=lambda env_var, fallback: f'os.getenv("{env_var}", "{fallback}")',
        )

    def _rewrite_internal_address_line(
        self,
        line: str,
        *,
        assignment_pattern: str,
        env_builder,
    ) -> tuple[str, str]:
        assignment = re.search(assignment_pattern, line)
        variable_name = assignment.group("name") if assignment else "service"
        literal = None
        literal_value = None
        for match in STRING_LITERAL_PATTERN.finditer(line):
            value = match.group("value")
            if INTERNAL_ADDRESS_PATTERN.search(value):
                literal = match.group(0)
                literal_value = value
                break
        if literal is None or literal_value is None:
            return line, self._env_var_name(variable_name, is_url=False)

        is_url = "://" in literal_value or "/" in literal_value
        env_var = self._env_var_name(variable_name, is_url=is_url)
        fallback = "https://example.com" if is_url else "example.com"
        replacement_expr = env_builder(env_var, fallback)
        return line.replace(literal, replacement_expr, 1), env_var

    def _env_var_name(self, variable_name: str, *, is_url: bool) -> str:
        normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", variable_name)
        normalized = re.sub(r"[^A-Za-z0-9]+", "_", normalized).strip("_").upper() or "SERVICE"
        if is_url:
            suffix = "URL"
        else:
            suffix = "HOST"
        if not normalized.endswith(suffix):
            normalized = f"{normalized}_{suffix}"
        return f"DEFAULT_{normalized}"

    def _ensure_python_import(self, text: str, statement: str) -> str:
        if statement in text:
            return text

        lines = text.splitlines()
        insert_at = 0
        if lines and lines[0].startswith("#!"):
            insert_at = 1
        while insert_at < len(lines) and lines[insert_at].startswith(("from __future__ import ", "#")):
            insert_at += 1
        lines.insert(insert_at, statement)
        return "\n".join(lines) + ("\n" if text.endswith("\n") else "")

    def _patch_requirements_lockfile(
        self,
        repo_path: Path,
        vulnerability: Vulnerability,
    ) -> tuple[list[PatchOperation], str, str | None]:
        file_path = vulnerability.affected_files[0] if vulnerability.affected_files else ""
        if not file_path.endswith(".txt"):
            return [self._manual(file_path, "Dependency auto-remediation only supports .txt requirement files.")], "manual_required", vulnerability.remediation_hint

        cached = self._requirements_cache.get(file_path)
        if cached is not None:
            operations, status, notes = cached
            return [operation.model_copy(deep=True) for operation in operations], status, notes

        safe_path = self._safe_path(repo_path, file_path)
        if not safe_path.exists():
            result = ([self._manual(file_path, "Requirement file not found at patch time.")], "manual_required", vulnerability.remediation_hint)
            self._requirements_cache[file_path] = result
            return copy.deepcopy(result)

        original_text = safe_path.read_text(encoding="utf-8", errors="ignore")
        cache_root = tempfile.TemporaryDirectory(prefix="vuln-swarm-pip-tools-")
        cache_dir = Path(cache_root.name)

        source_path, cleanup_dir = self._resolve_requirements_source(repo_path, safe_path)
        try:
            completed = self._compile_requirements(repo_path=repo_path, source_path=source_path, output_path=safe_path, cache_dir=cache_dir)
            if completed is not None and completed.returncode == 0:
                regenerated_text = safe_path.read_text(encoding="utf-8", errors="ignore")
                operations = [
                    PatchOperation(
                        file_path=file_path,
                        operation="replace",
                        original=safe_path.name,
                        replacement=f"{safe_path.name} regenerated from {source_path.name} with pinned, hashed dependencies.",
                        rationale="Compile a fully pinned dependency lockfile with pip-tools and SHA-256 hashes.",
                        applied=regenerated_text != original_text or bool(regenerated_text.strip()),
                    )
                ]
                notes = f"Regenerated from {source_path.name} using pip-tools."
                result = (operations, "applied", notes)
                self._requirements_cache[file_path] = result
                return [operation.model_copy(deep=True) for operation in operations], "applied", notes

            fallback = self._synthesise_requirements_lockfile(
                source_path=source_path,
                output_path=safe_path,
                original_text=original_text,
            )
            if fallback is not None:
                operations, notes = fallback
                result = (operations, "applied", notes)
                self._requirements_cache[file_path] = result
                return [operation.model_copy(deep=True) for operation in operations], "applied", notes

            stderr = (completed.stderr or completed.stdout or "").strip() if completed is not None else ""
            truncated = stderr[-600:] if stderr else "pip-tools failed and fallback locking could not infer secure versions."
            return (
                [self._manual(file_path, f"Dependency auto-remediation could not build a hashed lockfile: {truncated}")],
                "manual_required",
                vulnerability.remediation_hint,
            )
        finally:
            cache_root.cleanup()
            if cleanup_dir is not None:
                cleanup_dir.cleanup()

    def _compile_requirements(
        self,
        *,
        repo_path: Path,
        source_path: Path,
        output_path: Path,
        cache_dir: Path,
    ) -> subprocess.CompletedProcess[str] | None:
        commands: list[list[str]] = [
            [
                self.python_executable,
                "-m",
                "piptools",
                "compile",
                "--cache-dir",
                str(cache_dir),
                "--generate-hashes",
                "--allow-unsafe",
                "--output-file",
                str(output_path),
                str(source_path),
            ]
        ]
        pip_compile = shutil.which("pip-compile")
        if pip_compile:
            commands.append(
                [
                    pip_compile,
                    "--cache-dir",
                    str(cache_dir),
                    "--generate-hashes",
                    "--allow-unsafe",
                    "--output-file",
                    str(output_path),
                    str(source_path),
                ]
            )

        last_result: subprocess.CompletedProcess[str] | None = None
        for command in commands:
            try:
                completed = subprocess.run(
                    command,
                    cwd=repo_path,
                    check=False,
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError:
                continue
            last_result = completed
            if completed.returncode == 0:
                return completed
        return last_result

    def _synthesise_requirements_lockfile(
        self,
        *,
        source_path: Path,
        output_path: Path,
        original_text: str,
    ) -> tuple[list[PatchOperation], str] | None:
        dependencies = self._load_dependencies_from_source(source_path)
        if not dependencies:
            return None

        locked_entries: list[str] = []
        resolved_from: list[str] = []
        for dependency in dependencies:
            locked_entry, source_label = self._lock_dependency_entry(dependency)
            if locked_entry is None:
                return None
            locked_entries.append(locked_entry)
            resolved_from.append(source_label)

        lockfile = (
            "# Generated by Vuln-Swarm fallback dependency locker.\n"
            "# Prefer pip-compile --generate-hashes when the toolchain is available.\n\n"
            + "\n".join(locked_entries)
            + "\n"
        )
        output_path.write_text(lockfile, encoding="utf-8")
        operations = [
            PatchOperation(
                file_path=output_path.name,
                operation="replace",
                original=output_path.name,
                replacement=f"{output_path.name} synthesized from {source_path.name} with pinned versions and SHA-256 hashes.",
                rationale="Fall back to deterministic PyPI metadata locking when pip-tools is unavailable.",
                applied=lockfile != original_text,
            )
        ]
        unique_sources = ", ".join(sorted(set(resolved_from)))
        return operations, f"Synthesized from {source_path.name} using package metadata resolved via {unique_sources}."

    def _load_dependencies_from_source(self, source_path: Path) -> list[str]:
        if source_path.suffix == ".toml" and source_path.name == "pyproject.toml":
            data = tomllib.loads(source_path.read_text(encoding="utf-8", errors="ignore"))
            project = data.get("project", {})
            dependencies = project.get("dependencies", [])
            if isinstance(dependencies, list):
                return [str(item).strip() for item in dependencies if str(item).strip()]
            return []
        if source_path.suffix in {".txt", ".in"}:
            entries: list[str] = []
            for raw_line in source_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                entries.append(line)
            return entries
        if source_path.suffix == ".cfg":
            parser = configparser.ConfigParser()
            parser.read(source_path, encoding="utf-8")
            install_requires = parser.get("options", "install_requires", fallback="")
            return [line.strip() for line in install_requires.splitlines() if line.strip()]
        return []

    def _lock_dependency_entry(self, raw_requirement: str) -> tuple[str | None, str]:
        try:
            requirement = Requirement(raw_requirement)
        except InvalidRequirement:
            return None, "manual-review"
        if requirement.url:
            return None, "manual-review"

        pinned_version = self._extract_exact_pin(requirement)
        version_source = "declared pin"
        if pinned_version is None:
            pinned_version = self._resolve_installed_version(requirement)
            version_source = "installed metadata"
        hashes: list[str] = []
        if pinned_version is not None:
            hashes = self._fetch_release_hashes(requirement.name, pinned_version)
        if pinned_version is None or not hashes:
            resolved = self._resolve_from_pypi(requirement)
            if resolved is None:
                return None, version_source
            pinned_version, hashes = resolved
            version_source = "PyPI release metadata"

        marker = f"; {requirement.marker}" if requirement.marker else ""
        line = f"{requirement.name}{self._format_extras(requirement)}=={pinned_version}{marker} \\"
        hash_lines = [f"    --hash=sha256:{digest}" for digest in hashes]
        return "\n".join([line, *hash_lines]), version_source

    def _extract_exact_pin(self, requirement: Requirement) -> str | None:
        for specifier in requirement.specifier:
            if specifier.operator in {"==", "==="} and "*" not in specifier.version:
                return specifier.version
        return None

    def _resolve_installed_version(self, requirement: Requirement) -> str | None:
        normalized_name = requirement.name.replace("-", "_")
        try:
            version = metadata.version(normalized_name)
        except metadata.PackageNotFoundError:
            return None
        return version if self._specifier_allows(requirement.specifier, version) else None

    def _resolve_from_pypi(self, requirement: Requirement) -> tuple[str, list[str]] | None:
        package_name = requirement.name
        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            response = httpx.get(url, follow_redirects=True, timeout=10.0)
            response.raise_for_status()
        except httpx.HTTPError:
            return None

        payload = response.json()
        releases = payload.get("releases", {})
        candidates: list[Version] = []
        for raw_version, files in releases.items():
            if not files:
                continue
            try:
                parsed = Version(raw_version)
            except InvalidVersion:
                continue
            if parsed.is_prerelease:
                continue
            if self._specifier_allows(requirement.specifier, raw_version):
                candidates.append(parsed)
        if not candidates:
            return None

        selected = str(max(candidates))
        hashes = self._hashes_from_release_files(releases.get(selected, []))
        if not hashes:
            return None
        return selected, hashes

    def _fetch_release_hashes(self, package_name: str, version: str) -> list[str]:
        url = f"https://pypi.org/pypi/{package_name}/{version}/json"
        try:
            response = httpx.get(url, follow_redirects=True, timeout=10.0)
            response.raise_for_status()
        except httpx.HTTPError:
            return []
        payload = response.json()
        urls = payload.get("urls", [])
        return self._hashes_from_release_files(urls)

    def _hashes_from_release_files(self, files: list[dict]) -> list[str]:
        hashes = [
            file_info.get("digests", {}).get("sha256")
            for file_info in files
            if isinstance(file_info, dict)
        ]
        return sorted({digest for digest in hashes if digest})[:8]

    def _specifier_allows(self, specifiers, version: str) -> bool:
        if not specifiers:
            return True
        try:
            parsed = Version(version)
        except InvalidVersion:
            return False
        for specifier in specifiers:
            if not isinstance(specifier, Specifier):
                continue
            if not specifier.contains(parsed, prereleases=False):
                return False
        return True

    def _format_extras(self, requirement: Requirement) -> str:
        if not requirement.extras:
            return ""
        return "[" + ",".join(sorted(requirement.extras)) + "]"

    def _resolve_requirements_source(
        self,
        repo_path: Path,
        requirements_path: Path,
    ) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
        sibling_in = requirements_path.with_suffix(".in")
        if sibling_in.exists():
            return sibling_in, None
        pyproject = repo_path / "pyproject.toml"
        if pyproject.exists():
            return pyproject, None
        setup_cfg = repo_path / "setup.cfg"
        if setup_cfg.exists():
            return setup_cfg, None
        setup_py = repo_path / "setup.py"
        if setup_py.exists():
            return setup_py, None

        temp_dir = tempfile.TemporaryDirectory(dir=repo_path)
        temp_source = Path(temp_dir.name) / "requirements.in"
        temp_source.write_text(requirements_path.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
        return temp_source, temp_dir

    def _manual(self, file_path: str, rationale: str) -> PatchOperation:
        return PatchOperation(file_path=file_path, operation="manual_required", rationale=rationale)

    def _safe_path(self, repo_path: Path, file_path: str) -> Path:
        candidate = (repo_path / file_path).resolve()
        root = repo_path.resolve()
        if root not in candidate.parents and candidate != root:
            raise ValueError(f"Unsafe patch path outside repository: {file_path}")
        return candidate
