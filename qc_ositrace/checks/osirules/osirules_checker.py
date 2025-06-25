import logging
from pathlib import Path

from qc_baselib import Configuration, Result, StatusType, IssueSeverity

from qc_ositrace import constants

from qc_ositrace.checks.osirules import (
    osirules_constants,
)

from osi3trace.osi_trace import OSITrace
import google.protobuf.message

from importlib import resources as impresources
from . import rulesyml

import yaml


def rule_name_from_rule(rule: dict) -> str:
    def flatten_rule(r):
        items = []
        for k, v in r.items():
            items.append(k.lower())
            if v is None:
                continue
            if isinstance(v, dict):
                items.extend(flatten_rule(v))
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        items.extend(flatten_rule(item))
                    elif isinstance(item, list):
                        items.extend(item)
                    else:
                        items.append(item)
            else:
                items.append(
                    v.replace(".", "_").lower()
                    if isinstance(v, str)
                    else str(v).replace(".", "_")
                )
        return items

    return "_".join(flatten_rule(rule))


def register_automatic_rule(
    rule_map: dict, result: Result, keys: list, items, rules_version
) -> None:
    if items is not None:
        if isinstance(items, dict):
            for subkey, subitems in items.items():
                register_automatic_rule(
                    rule_map, result, keys + [subkey], subitems, rules_version
                )
        else:
            for rule in items:
                rulename = rule_name_from_rule(rule)
                rule_uid = result.register_rule(
                    checker_bundle_name=constants.BUNDLE_NAME,
                    checker_id=osirules_constants.CHECKER_ID,
                    emanating_entity="asam.net",
                    standard="osi",
                    definition_setting=".".join([str(s) for s in rules_version]),
                    rule_full_name=f"osirules.{'.'.join(x.lower() for x in keys)}.{rulename}",
                )
                rule_osi3_type = f"osi3.{'.'.join(keys[:-1])}"
                rule_map.setdefault(rule_osi3_type, {})
                rule_map[rule_osi3_type].setdefault(keys[-1], [])
                rule_map[rule_osi3_type][keys[-1]].append((rule_uid, rule))


def register_automatic_rules(result: Result, rules: dict, rules_version) -> dict:
    logging.info("Registering Automatic Rules")
    rule_map = {}
    for key, items in rules.items():
        register_automatic_rule(rule_map, result, [key], items, rules_version)
    logging.info("Regsitered Automatic Rules")
    return rule_map


def check_message_against_rules(
    message: google.protobuf.message.Message, rule_map: dict, result: Result
) -> None:
    field_rules = rule_map.get(message.DESCRIPTOR.full_name, {})

    # Check if required fields are set
    for field_name, rules in field_rules.items():
        has_field = message.HasField(field_name)
        for rule_uid, rule in rules:
            if "is_set" in rule and not has_field:
                result.register_issue(
                    checker_bundle_name=constants.BUNDLE_NAME,
                    checker_id=osirules_constants.CHECKER_ID,
                    description=f"Field '{field_name}' is not set in message '{message.DESCRIPTOR.full_name}'.",
                    level=IssueSeverity.ERROR,
                    rule_uid=rule_uid,
                )

    # Process other rules for each set field
    for field, value in message.ListFields():
        for rule_uid, rule in field_rules.get(field.name, []):
            if "is_greater_than" in rule and not value > rule["is_greater_than"]:
                result.register_issue(
                    checker_bundle_name=constants.BUNDLE_NAME,
                    checker_id=osirules_constants.CHECKER_ID,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not greater than {rule['is_greater_than']}.",
                    level=IssueSeverity.ERROR,
                    rule_uid=rule_uid,
                )
            if (
                "is_greater_than_or_equal_to" in rule
                and not value >= rule["is_greater_than_or_equal_to"]
            ):
                result.register_issue(
                    checker_bundle_name=constants.BUNDLE_NAME,
                    checker_id=osirules_constants.CHECKER_ID,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not greater or equal to {rule['is_greater_than_or_equal_to']}.",
                    level=IssueSeverity.ERROR,
                    rule_uid=rule_uid,
                )
            if "is_less_than" in rule and not value < rule["is_less_than"]:
                result.register_issue(
                    checker_bundle_name=constants.BUNDLE_NAME,
                    checker_id=osirules_constants.CHECKER_ID,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not less than {rule['is_less_than']}.",
                    level=IssueSeverity.ERROR,
                    rule_uid=rule_uid,
                )
            if (
                "is_less_than_or_equal_to" in rule
                and not value <= rule["is_less_than_or_equal_to"]
            ):
                result.register_issue(
                    checker_bundle_name=constants.BUNDLE_NAME,
                    checker_id=osirules_constants.CHECKER_ID,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not less or equal to {rule['is_less_than_or_equal_to']}.",
                    level=IssueSeverity.ERROR,
                    rule_uid=rule_uid,
                )
            if "is_equal_to" in rule and not value == rule["is_equal_to"]:
                result.register_issue(
                    checker_bundle_name=constants.BUNDLE_NAME,
                    checker_id=osirules_constants.CHECKER_ID,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not equal to {rule['is_equal_to']}.",
                    level=IssueSeverity.ERROR,
                    rule_uid=rule_uid,
                )
            if "is_different_to" in rule and not value != rule["is_different_to"]:
                result.register_issue(
                    checker_bundle_name=constants.BUNDLE_NAME,
                    checker_id=osirules_constants.CHECKER_ID,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not different from {rule['is_different_to']}.",
                    level=IssueSeverity.ERROR,
                    rule_uid=rule_uid,
                )
            # TODO: Add remaining rule checks

        # Recursively check nested messages
        if field.message_type is not None:
            if isinstance(value, google.protobuf.message.Message):
                check_message_against_rules(value, rule_map, result)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, google.protobuf.message.Message):
                        check_message_against_rules(item, rule_map, result)


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

    custom_rules_file = (
        Path(config.get_config_param("osiRulesFile"))
        if config.get_config_param("osiRulesFile")
        else None
    )
    rules_file = custom_rules_file or (
        impresources.files(rulesyml)
        / f"osi_{'_'.join(map(str,expected_version or fallback_version))}.yml"
    )
    try:
        with rules_file.open("rt") as file:
            rules = yaml.safe_load(file)
        rules_version = expected_version or fallback_version
        logging.info(
            f"Read {'custom' if custom_rules_file else 'standard'} rules file for version {'.'.join([str(s) for s in rules_version])}"
        )

    except FileNotFoundError:
        logging.info(
            f"No {'custom' if custom_rules_file else 'standard'} rules file for expected version {'.'.join([str(s) for s in expected_version])}, falling back to standard {'.'.join([str(s) for s in fallback_version])} rules"
        )
        fallback_rules_file = (
            impresources.files(rulesyml)
            / f"osi_{'_'.join(map(str,fallback_version))}.yml"
        )
        with fallback_rules_file.open("rt") as file:
            rules = yaml.safe_load(file)
        rules_version = fallback_version
        logging.info(
            f"Read standard rules file for version {'.'.join([str(s) for s in rules_version])}"
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

    # Register rules from rules yml
    rule_uid_map = register_automatic_rules(result, rules, rules_version)

    logging.info("Executing osirules.version_is_set check")
    logging.info("Executing osirules.expected_version check")
    logging.info("Executing osirules automatic checks")

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
        check_message_against_rules(message, rule_uid_map, result)

    logging.info(
        f"Issues found - {result.get_checker_issue_count(checker_bundle_name=constants.BUNDLE_NAME, checker_id=osirules_constants.CHECKER_ID)}"
    )

    # TODO: Add logic to deal with error or to skip it
    result.set_checker_status(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=osirules_constants.CHECKER_ID,
        status=StatusType.COMPLETED,
    )
