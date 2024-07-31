import os
import sys

from typing import List, Optional

import main

from qc_ositrace import constants
from qc_baselib import Configuration, Result, IssueSeverity

CONFIG_FILE_PATH = "bundle_config.xml"
REPORT_FILE_PATH = "osi_bundle_report.xqar"


def create_test_config(
    target_file_path: str,
    target_file_type: str,
    target_file_version: Optional[str] = None,
):
    test_config = Configuration()
    test_config.set_config_param(name="osiFile", value=target_file_path)
    test_config.set_config_param(name="osiType", value=target_file_type)
    if target_file_version is not None:
        test_config.set_config_param(name="osiVersion", value=target_file_version)
    test_config.register_checker_bundle(checker_bundle_name=constants.BUNDLE_NAME)
    test_config.set_checker_bundle_param(
        checker_bundle_name=constants.BUNDLE_NAME,
        name="resultFile",
        value=REPORT_FILE_PATH,
    )

    test_config.write_to_file(CONFIG_FILE_PATH)


def check_issues(rule_uid: str, issue_count: int, severity: IssueSeverity):
    result = Result()
    result.load_from_file(REPORT_FILE_PATH)

    issues = result.get_issues_by_rule_uid(rule_uid)

    assert len(issues) == issue_count

    for issue in issues:
        assert issue.level == severity


def launch_main(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "-c",
            CONFIG_FILE_PATH,
        ],
    )
    main.main()


def cleanup_files():
    os.remove(REPORT_FILE_PATH)
    os.remove(CONFIG_FILE_PATH)
