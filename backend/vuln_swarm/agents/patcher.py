from __future__ import annotations

import ast
import copy
from pathlib import Path
import subprocess
import sys
import tempfile

from pydantic import Field

from vuln_swarm.schemas import AppliedFix, PatchOperation, RagCitation, StrictModel, Vulnerability


class LlmPatchPlan(StrictModel):
    operations: list[PatchOperation] = Field(default_factory=list)
    summary: str


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
                        "The Groq patch planner can produce exact replacements when configured."
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
        cache_dir = repo_path / ".vuln-swarm-cache" / "pip-tools"
        cache_dir.mkdir(parents=True, exist_ok=True)

        source_path, cleanup_dir = self._resolve_requirements_source(repo_path, safe_path)
        command = [
            self.python_executable,
            "-m",
            "piptools",
            "compile",
            "--cache-dir",
            str(cache_dir),
            "--generate-hashes",
            "--allow-unsafe",
            "--output-file",
            str(safe_path),
            str(source_path),
        ]

        try:
            completed = subprocess.run(
                command,
                cwd=repo_path,
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            if cleanup_dir is not None:
                cleanup_dir.cleanup()

        if completed.returncode != 0:
            stderr = (completed.stderr or completed.stdout or "").strip()
            truncated = stderr[-600:] if stderr else "pip-tools failed without stderr output."
            result = (
                [self._manual(file_path, f"pip-tools failed to compile hashed requirements: {truncated}")],
                "manual_required",
                vulnerability.remediation_hint,
            )
            self._requirements_cache[file_path] = result
            return copy.deepcopy(result)

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
