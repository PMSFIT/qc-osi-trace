import logging

from lxml import etree

from qc_baselib import Configuration, Result, StatusType, IssueSeverity

from qc_ositrace import constants

from qc_ositrace.checks.deserialization import (
    deserialization_constants,
)

from osi3trace.osi_trace import OSITrace


def run_checks(config: Configuration, result: Result) -> None:
    logging.info("Executing deserialization checks")

    expected_version = (
        tuple([int(s) for s in config.get_config_param("osiVersion").split(".")])
        if config.get_config_param("osiVersion")
        else None
    )
    expected_type_name = config.get_config_param("osiType") or "SensorView"
    expected_type = OSITrace.map_message_type(expected_type_name)

    trace = OSITrace(
        config.get_config_param("InputFile"), config.get_config_param("osiType")
    )

    result.register_checker(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=deserialization_constants.CHECKER_ID,
        description="Evaluates messages in the trace file with the OSI deserialization to guarantee they are in conformance with the basic standard trace file rules.",
        summary=f"Checker validating basic deserializability of messages in a trace file",
    )

    deser_rule_uid = result.register_rule(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=deserialization_constants.CHECKER_ID,
        emanating_entity="asam.net",
        standard="osi",
        definition_setting="3.0.0",
        rule_full_name="deserialization.possible",
    )

    type_rule_uid = result.register_rule(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=deserialization_constants.CHECKER_ID,
        emanating_entity="asam.net",
        standard="osi",
        definition_setting="3.0.0",
        rule_full_name="deserialization.expected_type",
    )

    version_rule_uid = result.register_rule(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=deserialization_constants.CHECKER_ID,
        emanating_entity="asam.net",
        standard="osi",
        definition_setting="3.0.0",
        rule_full_name="deserialization.version_is_set",
    )

    exp_version_rule_uid = result.register_rule(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=deserialization_constants.CHECKER_ID,
        emanating_entity="asam.net",
        standard="osi",
        definition_setting="3.0.0",
        rule_full_name="deserialization.expected_version",
    )

    logging.info("Executing deserialization.expected_type check")
    logging.info("Executing deserialization.version_is_set check")
    logging.info("Executing deserialization.expected_version check")

    for message in trace:
        if not type(message) is expected_type:
            issue_id = result.register_issue(
                checker_bundle_name=constants.BUNDLE_NAME,
                checker_id=deserialization_constants.CHECKER_ID,
                description=f"Deserialized message is not of expected type {expected_type}.",
                level=IssueSeverity.ERROR,
                rule_uid=type_rule_uid,
            )
        if not message.HasField("version"):
            issue_id = result.register_issue(
                checker_bundle_name=constants.BUNDLE_NAME,
                checker_id=deserialization_constants.CHECKER_ID,
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
                checker_id=deserialization_constants.CHECKER_ID,
                description=f"Version field value {message.version.version_major}.{message.version.version_minor}.{message.version.version_patch} is not the expected version {'.'.join([str(s) for s in expected_version])}.",
                level=IssueSeverity.ERROR,
                rule_uid=exp_version_rule_uid,
            )

    logging.info(
        f"Issues found - {result.get_checker_issue_count(checker_bundle_name=constants.BUNDLE_NAME, checker_id=deserialization_constants.CHECKER_ID)}"
    )

    # TODO: Add logic to deal with error or to skip it
    result.set_checker_status(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=deserialization_constants.CHECKER_ID,
        status=StatusType.COMPLETED,
    )
