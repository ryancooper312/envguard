"""envguard：零依赖 .env 结构校验与泄漏扫描工具。"""

from envguard.parser import EnvEntry, EnvRule, parse_env_file
from envguard.validator import ValidationFinding, ValidationReport, validate_env

__all__ = [
    "EnvEntry",
    "EnvRule",
    "ValidationFinding",
    "ValidationReport",
    "parse_env_file",
    "validate_env",
]
__version__ = "0.1.0"
