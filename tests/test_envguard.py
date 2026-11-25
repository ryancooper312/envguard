"""envguard 完整单元测试套件，覆盖解析、类型规则、密钥泄漏扫描与 CLI 行为。"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from envguard.cli import main as cli_main
from envguard.parser import parse_env_text
from envguard.validator import validate_env


class TestEnvParser(unittest.TestCase):
    """验证 dotenv 解析与注释规则指令提取。"""

    def test_parses_quotes_export_and_inline_directives(self):
        content = (
            "# @required @type=url\n"
            "export API_URL='https://api.example.com'\n"
            'APP_NAME="My # App" # @required @type=nonempty\n'
            "PORT=8080 # @type=port\n"
        )
        entries = parse_env_text(content)
        self.assertEqual(entries["API_URL"].value, "https://api.example.com")
        self.assertTrue(entries["API_URL"].rule.required)
        self.assertEqual(entries["API_URL"].rule.value_type, "url")
        self.assertEqual(entries["APP_NAME"].value, "My # App")
        self.assertEqual(entries["PORT"].rule.value_type, "port")


class TestEnvValidator(unittest.TestCase):
    """验证同步检查、所有内置类型约束与防泄漏扫描。"""

    def test_valid_configuration_passes(self):
        example = parse_env_text(
            "PORT=3000 # @required @type=port\n"
            "DEBUG=false # @type=bool\n"
            "WORKERS=4 # @type=int\n"
            "RATIO=0.75 # @type=float\n"
            "ENV=prod # @type=enum(dev,staging,prod)\n"
            "API_URL=https://example.com # @required @type=url\n"
        )
        env = parse_env_text(
            "PORT=8080\n"
            "DEBUG=true\n"
            "WORKERS=8\n"
            "RATIO=1.25\n"
            "ENV=staging\n"
            "API_URL=https://service.example.com/v1\n"
        )
        report = validate_env(env, example)
        self.assertTrue(report.ok)
        self.assertEqual(report.checked_keys, 6)

    def test_missing_and_empty_required_keys_detected(self):
        example = parse_env_text(
            "DB_URL= # @required @type=nonempty\n"
            "REDIS_URL= # @required\n"
        )
        env = parse_env_text("DB_URL=   \n")
        report = validate_env(env, example)
        codes = {f.key: f.code for f in report.findings}
        self.assertFalse(report.ok)
        self.assertEqual(codes["DB_URL"], "EMPTY_REQUIRED_KEY")
        self.assertEqual(codes["REDIS_URL"], "MISSING_KEY")

    def test_undeclared_extra_key_strict_vs_allow_extra(self):
        example = parse_env_text("APP_NAME=demo\n")
        env = parse_env_text("APP_NAME=demo\nEXTRA_FLAG=1\n")
        strict_report = validate_env(env, example, allow_extra=False)
        self.assertEqual([f.code for f in strict_report.findings], ["UNDECLARED_EXTRA_KEY"])

        relaxed_report = validate_env(env, example, allow_extra=True)
        self.assertTrue(relaxed_report.ok)

    def test_invalid_port_and_integer_rejected(self):
        example = parse_env_text(
            "PORT=8000 # @type=port\n"
            "RETRIES=3 # @type=int\n"
        )
        env = parse_env_text("PORT=70000\nRETRIES=abc\n")
        report = validate_env(env, example)
        self.assertEqual(len(report.findings), 2)
        self.assertTrue(all(f.code == "INVALID_TYPE" for f in report.findings))

    def test_invalid_bool_url_and_enum_rejected(self):
        example = parse_env_text(
            "DEBUG=false # @type=bool\n"
            "WEBHOOK=https://example.com # @type=url\n"
            "MODE=fast # @type=enum(fast,safe)\n"
        )
        env = parse_env_text("DEBUG=maybe\nWEBHOOK=/relative/path\nMODE=turbo\n")
        report = validate_env(env, example)
        self.assertEqual(len(report.findings), 3)
        self.assertTrue(all(f.code == "INVALID_TYPE" for f in report.findings))

    def test_optional_empty_typed_value_allowed(self):
        example = parse_env_text("OPTIONAL_PORT= # @type=port\n")
        env = parse_env_text("OPTIONAL_PORT=\n")
        report = validate_env(env, example)
        self.assertTrue(report.ok)

    def test_secret_leak_in_example_detected(self):
        fake_ghp = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
        example = parse_env_text(f"GITHUB_TOKEN={fake_ghp}\n")
        env = parse_env_text(f"GITHUB_TOKEN={fake_ghp}\n")
        report = validate_env(env, example)
        self.assertFalse(report.ok)
        self.assertEqual(report.findings[0].code, "SECRET_LEAK_IN_EXAMPLE")

        no_scan_report = validate_env(env, example, scan_secrets=False)
        self.assertTrue(no_scan_report.ok)


class TestEnvGuardCLI(unittest.TestCase):
    """验证 CLI 进程退出码与 JSON 输出格式。"""

    def test_cli_json_success_and_failure_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            ex_file = tmp_dir / ".env.example"
            env_file = tmp_dir / ".env"

            ex_file.write_text("PORT=8080 # @required @type=port\n", encoding="utf-8")
            env_file.write_text("PORT=8080\n", encoding="utf-8")

            proc_ok = subprocess.run(
                [sys.executable, "-m", "envguard", "--env", str(env_file), "--example", str(ex_file), "--json"],
                cwd=str(Path(__file__).resolve().parent.parent),
                env={"PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src")},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc_ok.returncode, 0)
            payload = json.loads(proc_ok.stdout)
            self.assertTrue(payload["ok"])

            env_file.write_text("PORT=invalid\n", encoding="utf-8")
            code_fail = cli_main(["--env", str(env_file), "--example", str(ex_file), "--json"])
            self.assertEqual(code_fail, 1)

    def test_cli_missing_file_returns_exit_code_2(self):
        code = cli_main(["--env", "/nonexistent/.env", "--example", "/nonexistent/.env.example"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
