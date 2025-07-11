import os
import sys
import pytest

from typing import List

from qc_baselib import IssueSeverity

from test_setup import *


@pytest.mark.parametrize(
    "target_file,target_type,issue_count",
    [
        ("invalid", "SensorView", 547),
        ("valid", "SensorView", 0),
    ],
)
def test_osirules_version_is_set_examples(
    target_file: str,
    target_type: str,
    issue_count: int,
    monkeypatch,
) -> None:
    base_path = "tests/data/deserialization_version_is_set/"
    target_file_name = f"deserialization_version_is_set_{target_file}.osi"
    rule_uid = "asam.net:osi:3.0.0:osirules.version_is_set"
    issue_severity = IssueSeverity.ERROR

    target_file_path = os.path.join(base_path, target_file_name)
    create_test_config(target_file_path, target_type)
    launch_main(monkeypatch)
    check_issues(rule_uid, issue_count, issue_severity)
    cleanup_files()


@pytest.mark.parametrize(
    "target_file,target_type,target_version,issue_count",
    [
        ("360", "SensorView", "3.5.0", 547),
        ("360", "SensorView", "3.6.0", 0),
    ],
)
def test_osirules_expected_version(
    target_file: str,
    target_type: str,
    target_version: str,
    issue_count: int,
    monkeypatch,
) -> None:
    base_path = "tests/data/deserialization_expected_version/"
    target_file_name = f"deserialization_expected_version_{target_file}.osi"
    rule_uid = "asam.net:osi:3.0.0:osirules.expected_version"
    issue_severity = IssueSeverity.ERROR

    target_file_path = os.path.join(base_path, target_file_name)
    create_test_config(target_file_path, target_type, target_version)
    launch_main(monkeypatch)
    check_issues(rule_uid, issue_count, issue_severity)
    cleanup_files()


@pytest.mark.parametrize(
    "target_file,target_type,target_version,rule_name,issue_count",
    [
        (
            "deserialization_version_is_set/deserialization_version_is_set_invalid.osi",
            "SensorView",
            "3.6.0",
            "sensorview.version.is_set",
            0,
        ),
        (
            "deserialization_version_is_set/deserialization_version_is_set_invalid.osi",
            "SensorView",
            "3.7.0",
            "sensorview.version.is_set",
            547,
        ),
        (
            "deserialization_expected_version/deserialization_expected_version_360.osi",
            "SensorView",
            "3.6.0",
            "sensorview.mounting_position.is_set",
            0,
        ),
        (
            "deserialization_expected_version/deserialization_expected_version_360.osi",
            "SensorView",
            "3.7.0",
            "sensorview.mounting_position.is_set",
            547,
        ),
    ],
)
def test_osirules_automatic_rules(
    target_file: str,
    target_type: str,
    target_version: str,
    rule_name: str,
    issue_count: int,
    monkeypatch,
) -> None:
    base_path = "tests/data/"
    rule_uid = f"asam.net:osi:{target_version}:osirules.{rule_name}"
    issue_severity = IssueSeverity.ERROR

    target_file_path = os.path.join(base_path, target_file)
    create_test_config(target_file_path, target_type, target_version)
    launch_main(monkeypatch)
    check_issues(rule_uid, issue_count, issue_severity)
    cleanup_files()


@pytest.mark.parametrize(
    "target_file,target_type,target_version,rule_name,issue_count",
    [
        (
            "deserialization_version_is_set/deserialization_version_is_set_invalid.osi",
            "SensorView",
            "3.6.0",
            "sensorview.version.is_set",
            0,
        ),
        (
            "deserialization_expected_version/deserialization_expected_version_360.osi",
            "SensorView",
            "3.6.0",
            "groundtruth.country_code.is_set",
            547,
        ),
        (
            "deserialization_expected_version/deserialization_expected_version_360.osi",
            "SensorView",
            "3.6.0",
            "groundtruth.proj_string.is_set",
            547,
        ),
        (
            "deserialization_expected_version/deserialization_expected_version_360.osi",
            "SensorView",
            "3.6.0",
            "groundtruth.map_reference.is_set",
            547,
        ),
    ],
)
def test_osirules_custom_rules(
    target_file: str,
    target_type: str,
    target_version: str,
    rule_name: str,
    issue_count: int,
    monkeypatch,
) -> None:
    base_path = "tests/data/"
    rule_uid = f"asam.net:osi:{target_version}:osirules.{rule_name}"
    issue_severity = IssueSeverity.ERROR

    target_file_path = os.path.join(base_path, target_file)
    create_test_config(
        target_file_path,
        target_type,
        target_version,
        "tests/data/customrules/customrules.yml",
    )
    launch_main(monkeypatch)
    check_issues(rule_uid, issue_count, issue_severity)
    cleanup_files()
