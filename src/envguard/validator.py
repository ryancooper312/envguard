"""执行 .env 结构同步校验、类型约束验证与模板明文密钥防泄漏扫描。"""

from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlparse

from envguard.parser import EnvEntry, EnvRule

BOOL_VALUES = {"true", "false", "1", "0", "yes", "no", "on", "off"}

# 常见真实凭据前缀模式，用于阻止误将有效密钥提交至 .env.example
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI / Anthropic Style Key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b")),
    ("Stripe Live Key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
    ("GitHub Classic Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("GitHub Fine-Grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack Bot/User Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Private Key Header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


@dataclass(frozen=True)
class ValidationFinding:
    """记录单条校验错误或潜在泄漏告警。"""

    code: str
    key: str
    message: str
    line_no: int | None = None

    def to_dict(self) -> dict[str, object]:
        """转换为可 JSON 序列化的字典结构。"""
        return {
            "code": self.code,
            "key": self.key,
            "message": self.message,
            "line": self.line_no,
        }


@dataclass(frozen=True)
class ValidationReport:
    """汇总全部校验结果。"""

    findings: tuple[ValidationFinding, ...]
    checked_keys: int

    @property
    def ok(self) -> bool:
        """无任何错误发现时返回 True。"""
        return len(self.findings) == 0

    def to_dict(self) -> dict[str, object]:
        """转换为标准 JSON 输出结构。"""
        return {
            "ok": self.ok,
            "checked_keys": self.checked_keys,
            "error_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _validate_typed_value(key: str, value: str, rule: EnvRule, line_no: int) -> str | None:
    """按声明的 @type 规则验证值合法性，合法返回 None，否则返回错误信息。"""
    vtype = rule.value_type
    if not vtype:
        return None
    if not value.strip():
        # 空值仅在 @required 时报错，避免对可选字段误报类型错误
        return None

    if vtype == "nonempty":
        return None if value.strip() else f"{key} must not be empty"

    if vtype == "int":
        try:
            int(value.strip())
            return None
        except ValueError:
            return f"{key} expected integer, got {value!r} (line {line_no})"

    if vtype == "float":
        try:
            float(value.strip())
            return None
        except ValueError:
            return f"{key} expected float, got {value!r} (line {line_no})"

    if vtype == "port":
        try:
            port = int(value.strip())
        except ValueError:
            return f"{key} expected port integer 1-65535, got {value!r} (line {line_no})"
        if not (1 <= port <= 65535):
            return f"{key} port out of range (1-65535): {port} (line {line_no})"
        return None

    if vtype == "bool":
        if value.strip().lower() not in BOOL_VALUES:
            return f"{key} expected boolean (true/false/1/0/yes/no), got {value!r} (line {line_no})"
        return None

    if vtype == "url":
        parsed = urlparse(value.strip())
        if not parsed.scheme or not parsed.netloc:
            return f"{key} expected valid URL with scheme and host, got {value!r} (line {line_no})"
        return None

    if vtype == "enum":
        if value.strip() not in rule.enum_choices:
            allowed = ", ".join(rule.enum_choices)
            return f"{key} must be one of [{allowed}], got {value!r} (line {line_no})"
        return None

    return f"{key} declares unsupported @type={vtype!r}"


def scan_example_secrets(example_entries: dict[str, EnvEntry]) -> list[ValidationFinding]:
    """扫描模板文件 .env.example 中是否误填高危真实格式密钥。"""
    findings: list[ValidationFinding] = []
    for entry in example_entries.values():
        if not entry.value:
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(entry.value):
                findings.append(
                    ValidationFinding(
                        code="SECRET_LEAK_IN_EXAMPLE",
                        key=entry.key,
                        message=f"Potential {label} detected in example template at line {entry.line_no}",
                        line_no=entry.line_no,
                    )
                )
                break
    return findings


def validate_env(
    env_entries: dict[str, EnvEntry],
    example_entries: dict[str, EnvEntry],
    *,
    allow_extra: bool = False,
    scan_secrets: bool = True,
) -> ValidationReport:
    """比对实际环境配置与模板声明，输出结构化校验报告。"""
    findings: list[ValidationFinding] = []

    for key, ex_entry in example_entries.items():
        actual = env_entries.get(key)
        if actual is None:
            findings.append(
                ValidationFinding(
                    code="MISSING_KEY",
                    key=key,
                    message=f"Missing key {key} declared in example file (line {ex_entry.line_no})",
                    line_no=ex_entry.line_no,
                )
            )
            continue

        if ex_entry.rule.required and not actual.value.strip():
            findings.append(
                ValidationFinding(
                    code="EMPTY_REQUIRED_KEY",
                    key=key,
                    message=f"Required key {key} is empty (line {actual.line_no})",
                    line_no=actual.line_no,
                )
            )
            continue

        type_err = _validate_typed_value(key, actual.value, ex_entry.rule, actual.line_no)
        if type_err:
            findings.append(
                ValidationFinding(
                    code="INVALID_TYPE",
                    key=key,
                    message=type_err,
                    line_no=actual.line_no,
                )
            )

    if not allow_extra:
        for key, actual in env_entries.items():
            if key not in example_entries:
                findings.append(
                    ValidationFinding(
                        code="UNDECLARED_EXTRA_KEY",
                        key=key,
                        message=f"Undocumented key {key} present in env file (line {actual.line_no})",
                        line_no=actual.line_no,
                    )
                )

    if scan_secrets:
        findings.extend(scan_example_secrets(example_entries))

    return ValidationReport(findings=tuple(findings), checked_keys=len(example_entries))
