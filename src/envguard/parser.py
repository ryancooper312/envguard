"""解析 .env 与 .env.example 文件及注释中的类型约束指令。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

DIRECTIVE_TYPE_RE = re.compile(r"@type=([a-zA-Z0-9_(),.-]+)")
KEY_VALUE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


@dataclass(frozen=True)
class EnvRule:
    """描述单个环境变量的校验规则。"""

    required: bool = False
    value_type: str | None = None
    enum_choices: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class EnvEntry:
    """表示从配置文件解析出的单个键值条目及其行号和规则。"""

    key: str
    value: str
    line_no: int
    rule: EnvRule = field(default_factory=EnvRule)


def _parse_directives(comment_text: str) -> EnvRule:
    """从注释文本中提取 @required 与 @type 规则。"""
    required = "@required" in comment_text
    value_type: str | None = None
    enum_choices: tuple[str, ...] = ()

    type_match = DIRECTIVE_TYPE_RE.search(comment_text)
    if type_match:
        raw_type = type_match.group(1).strip()
        if raw_type.startswith("enum(") and raw_type.endswith(")"):
            value_type = "enum"
            inner = raw_type[5:-1]
            enum_choices = tuple(c.strip() for c in inner.split(",") if c.strip())
        else:
            value_type = raw_type.lower()

    return EnvRule(required=required, value_type=value_type, enum_choices=enum_choices)


def _split_value_and_comment(raw_rhs: str) -> tuple[str, str]:
    """拆分赋值右侧的真实字符串值与行内注释，正确处理单双引号。"""
    text = raw_rhs.strip()
    if not text:
        return "", ""

    quote = text[0]
    if quote in ('"', "'"):
        buf: list[str] = []
        escaped = False
        idx = 1
        while idx < len(text):
            ch = text[idx]
            if escaped:
                buf.append(ch)
                escaped = False
            elif ch == "\\" and quote == '"':
                escaped = True
            elif ch == quote:
                remainder = text[idx + 1 :].strip()
                comment = remainder[1:].strip() if remainder.startswith("#") else ""
                return "".join(buf), comment
            else:
                buf.append(ch)
            idx += 1
        return "".join(buf), ""

    # 无引号值遇到空白后的 # 视为行内注释起点
    for idx, ch in enumerate(text):
        if ch == "#" and (idx == 0 or text[idx - 1].isspace()):
            return text[:idx].strip(), text[idx + 1 :].strip()

    return text, ""


def _merge_rules(above: EnvRule | None, inline: EnvRule) -> EnvRule:
    """合并前一行注释规则与行内注释规则，行内声明优先级更高。"""
    if not above:
        return inline
    return EnvRule(
        required=above.required or inline.required,
        value_type=inline.value_type or above.value_type,
        enum_choices=inline.enum_choices or above.enum_choices,
    )


def parse_env_text(content: str) -> dict[str, EnvEntry]:
    """将 dotenv 文本解析为键名到 EnvEntry 的有序映射。"""
    entries: dict[str, EnvEntry] = {}
    pending_rule: EnvRule | None = None

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            pending_rule = None
            continue
        if stripped.startswith("#"):
            comment_body = stripped[1:].strip()
            if "@" in comment_body:
                pending_rule = _parse_directives(comment_body)
            else:
                pending_rule = None
            continue

        kv_match = KEY_VALUE_RE.match(stripped)
        if not kv_match:
            pending_rule = None
            continue

        key = kv_match.group(1)
        val, inline_comment = _split_value_and_comment(kv_match.group(2))
        inline_rule = _parse_directives(inline_comment) if inline_comment else EnvRule()
        merged_rule = _merge_rules(pending_rule, inline_rule)
        pending_rule = None
        entries[key] = EnvEntry(key=key, value=val, line_no=line_no, rule=merged_rule)

    return entries


def parse_env_file(path: str | Path) -> dict[str, EnvEntry]:
    """从磁盘读取并解析指定的 dotenv 文件。"""
    file_path = Path(path)
    return parse_env_text(file_path.read_text(encoding="utf-8"))
