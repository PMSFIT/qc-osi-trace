import logging

from lxml import etree

from qc_baselib import Configuration, Result, StatusType, IssueSeverity

from qc_ositrace import constants

from qc_ositrace.checks.osirules import (
    osirules_constants,
)

from osi3trace.osi_trace import OSITrace

from importlib import resources as impresources
from . import rulesyml

import yaml


def run_checks(config: Configuration, result: Result) -> None:
    logging.info("Executing osirules checks")

    expected_version = (
        tuple([int(s) for s in config.get_config_param("osiVersion").split(".")])
        if config.get_config_param("osiVersion")
        else None
    )
    fallback_version = tuple(
        [int(s) for s in osirules_constants.OSI_FALLBACK_VERSION.split(".")]
    )
    expected_type_name = config.get_config_param("osiType") or "SensorView"
    expected_type = OSITrace.map_message_type(expected_type_name)

    trace = OSITrace(
        config.get_config_param("InputFile"), config.get_config_param("osiType")
    )

    result.register_checker(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=osirules_constants.CHECKER_ID,
        description="Evaluates messages in the trace file against the OSI Rules of the given OSI version to guarantee they are in conformance with the standard OSI rules.",
        summary=f"Checker validating OSI Rules compliance of messages in a trace file",
    )

    if expected_version is None:
        logging.info(
            f"No expected version, falling back to {'.'.join([str(s) for s in fallback_version])} rules"
        )
    rules_file = (
        impresources.files(rulesyml)
        / f"osi_{'_'.join(map(str,expected_version or fallback_version))}.yml"
    )
    try:
        with rules_file.open("rt") as file:
            rules = yaml.safe_load(file)
        logging.info(
            f"Read rules file for version {'.'.join([str(s) for s in (expected_version or fallback_version)])}"
        )

    except FileNotFoundError:
        logging.info(
            f"No rules file for expected version {'.'.join([str(s) for s in expected_version])}, falling back to {'.'.join([str(s) for s in fallback_version])} rules"
        )
        fallback_rules_file = (
            impresources.files(rulesyml)
            / f"osi_{'_'.join(map(str,fallback_version))}.yml"
        )
        with fallback_rules_file.open("rt") as file:
            rules = yaml.safe_load(file)
            logging.info(
                f"Read rules file for version {'.'.join([str(s) for s in fallback_version])}"
            )

    version_rule_uid = result.register_rule(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=osirules_constants.CHECKER_ID,
        emanating_entity="asam.net",
        standard="osi",
        definition_setting="3.0.0",
        rule_full_name="osirules.version_is_set",
    )

    exp_version_rule_uid = result.register_rule(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=osirules_constants.CHECKER_ID,
        emanating_entity="asam.net",
        standard="osi",
        definition_setting="3.0.0",
        rule_full_name="osirules.expected_version",
    )

    # TODO: Register rules from rules yml

    logging.info("Executing osirules.version_is_set check")
    logging.info("Executing osirules.expected_version check")

    for message in trace:
        if not message.HasField("version"):
            issue_id = result.register_issue(
                checker_bundle_name=constants.BUNDLE_NAME,
                checker_id=osirules_constants.CHECKER_ID,
                description=f"Version field is not set in top-level message.",
                level=IssueSeverity.ERROR,
                rule_uid=version_rule_uid,
            )
        elif (
            expected_version is not None
            and (
                int(message.version.version_major),
                int(message.version.version_minor),
                int(message.version.version_patch),
            )
            != expected_version
        ):
            issue_id = result.register_issue(
                checker_bundle_name=constants.BUNDLE_NAME,
                checker_id=osirules_constants.CHECKER_ID,
                description=f"Version field value {message.version.version_major}.{message.version.version_minor}.{message.version.version_patch} is not the expected version {'.'.join([str(s) for s in expected_version])}.",
                level=IssueSeverity.ERROR,
                rule_uid=exp_version_rule_uid,
            )
        # TODO: Check rules from rulesyml

    logging.info(
        f"Issues found - {result.get_checker_issue_count(checker_bundle_name=constants.BUNDLE_NAME, checker_id=osirules_constants.CHECKER_ID)}"
    )

    # TODO: Add logic to deal with error or to skip it
    result.set_checker_status(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=osirules_constants.CHECKER_ID,
        status=StatusType.COMPLETED,
    )
