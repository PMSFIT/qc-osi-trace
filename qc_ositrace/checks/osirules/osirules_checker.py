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

import iso3166


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


def record_message_ids(
    message: google.protobuf.message.Message, id_message_map: dict
) -> None:
    if hasattr(message, "id") and message.HasField("id"):
        id_message_map[message.id.value] = message
    for field, value in message.ListFields():
        if field.message_type is not None:
            if isinstance(value, google.protobuf.message.Message):
                record_message_ids(value, id_message_map)
            else:
                for item in value:
                    if isinstance(item, google.protobuf.message.Message):
                        record_message_ids(item, id_message_map)


def register_issue(
    result: Result,
    message: google.protobuf.message.Message,
    index: int,
    time: float | None,
    rule_uid: str,
    level: IssueSeverity,
    description: str,
) -> None:
    time_str = f"{time}" if time is not None else "unknown"
    issue_id = result.register_issue(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=osirules_constants.CHECKER_ID,
        description=f"Message {index} at {time_str}: {description}",
        level=level,
        rule_uid=rule_uid,
    )
    result.add_file_location(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=osirules_constants.CHECKER_ID,
        issue_id=issue_id,
        row=index,
        column=0,
        description=f"Message {index} at {time_str}: {description}",
    )


def evaluate_rule_condition(
    message: google.protobuf.message.Message, field_name: str, rule: dict
) -> bool:
    if not message.HasField(field_name):
        return False
    value = getattr(message, field_name)
    if "is_set" in rule:
        return True
    if "is_greater_than" in rule and value > rule["is_greater_than"]:
        return True
    if (
        "is_greater_than_or_equal_to" in rule
        and value >= rule["is_greater_than_or_equal_to"]
    ):
        return True
    if "is_less_than" in rule and value < rule["is_less_than"]:
        return True
    if "is_less_than_or_equal_to" in rule and value <= rule["is_less_than_or_equal_to"]:
        return True
    if "is_equal_to" in rule and value == rule["is_equal_to"]:
        return True
    if "is_different_to" in rule and value != rule["is_different_to"]:
        return True
    if "is_iso_country_code" in rule and value >= 0 and value <= 999:
        return True
    if "is_globally_unique" in rule or "refers_to" in rule or "check_if" in rule:
        # Not supported within check_if, so we return False
        return False
    return False


def check_message_against_rules(
    message: google.protobuf.message.Message,
    rule_map: dict,
    id_message_map: dict,
    index: int,
    time: float | None,
    result: Result,
) -> None:
    field_rules = rule_map.get(message.DESCRIPTOR.full_name, {})

    # Check if required fields are set
    for field_name, rules in field_rules.items():
        has_field = message.HasField(field_name)
        for rule_uid, rule in rules:
            if "is_set" in rule and not has_field:
                register_issue(
                    result,
                    message,
                    index,
                    time,
                    rule_uid,
                    IssueSeverity.ERROR,
                    description=f"Field '{field_name}' is not set in message '{message.DESCRIPTOR.full_name}' but should be set.",
                )
            if (
                "check_if" in rule
                and "do_check" in rule
                and "is_set" in rule["do_check"][0]
            ):
                (target, target_field_name) = rule["check_if"][0]["target"].split(".")
                if target != "this":
                    logging.warning(
                        f"Message {index} at {time}: 'check_if' rule for field '{field_name}' in message '{message.DESCRIPTOR.full_name}' has a target that is not 'this': {target}. Ignoring rule."
                    )
                else:
                    if (
                        evaluate_rule_condition(
                            message, target_field_name, rule["check_if"][0]
                        )
                        and not has_field
                    ):
                        register_issue(
                            result,
                            message,
                            index,
                            time,
                            rule_uid,
                            IssueSeverity.ERROR,
                            description=f"Field '{field_name}' is not set in message '{message.DESCRIPTOR.full_name}' but should be set according to 'check_if' rule.",
                        )

    # Process other rules for each set field
    for field, value in message.ListFields():
        for rule_uid, rule in field_rules.get(field.name, []):
            if "is_greater_than" in rule and not value > rule["is_greater_than"]:
                register_issue(
                    result,
                    message,
                    index,
                    time,
                    rule_uid,
                    IssueSeverity.ERROR,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not greater than {rule['is_greater_than']}.",
                )
            if (
                "is_greater_than_or_equal_to" in rule
                and not value >= rule["is_greater_than_or_equal_to"]
            ):
                register_issue(
                    result,
                    message,
                    index,
                    time,
                    rule_uid,
                    IssueSeverity.ERROR,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not greater or equal to {rule['is_greater_than_or_equal_to']}.",
                )
            if "is_less_than" in rule and not value < rule["is_less_than"]:
                register_issue(
                    result,
                    message,
                    index,
                    time,
                    rule_uid,
                    IssueSeverity.ERROR,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not less than {rule['is_less_than']}.",
                )
            if (
                "is_less_than_or_equal_to" in rule
                and not value <= rule["is_less_than_or_equal_to"]
            ):
                register_issue(
                    result,
                    message,
                    index,
                    time,
                    rule_uid,
                    IssueSeverity.ERROR,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not less or equal to {rule['is_less_than_or_equal_to']}.",
                )
            if "is_equal_to" in rule and not value == rule["is_equal_to"]:
                register_issue(
                    result,
                    message,
                    index,
                    time,
                    rule_uid,
                    IssueSeverity.ERROR,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not equal to {rule['is_equal_to']}.",
                )
            if "is_different_to" in rule and not value != rule["is_different_to"]:
                register_issue(
                    result,
                    message,
                    index,
                    time,
                    rule_uid,
                    IssueSeverity.ERROR,
                    description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not different from {rule['is_different_to']}.",
                )
            if "is_iso_country_code" in rule:
                if value > 999 or value < 0:
                    register_issue(
                        result,
                        message,
                        index,
                        time,
                        rule_uid,
                        IssueSeverity.ERROR,
                        description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not a valid numeric ISO country code (must be between 000 and 999).",
                    )
                if iso3166.countries.get(value, None) is None:
                    register_issue(
                        result,
                        message,
                        index,
                        time,
                        rule_uid,
                        IssueSeverity.ERROR,
                        description=f"Field '{field.name}' value {value} in message '{message.DESCRIPTOR.full_name}' is not a valid numeric ISO country code (not found in ISO 3166).",
                    )
            if "is_globally_unique" in rule:
                if value.value in id_message_map:
                    existing_message = id_message_map[value.value]
                    if existing_message != message:
                        register_issue(
                            result,
                            message,
                            index,
                            time,
                            rule_uid,
                            IssueSeverity.ERROR,
                            description=f"Field '{field.name}' value {value.value} in message '{message.DESCRIPTOR.full_name}' is not globally unique, already used by different message '{existing_message.DESCRIPTOR.full_name}'.",
                        )
            if "refers_to" in rule:
                referred_message = id_message_map.get(value.value, None)
                if referred_message is None:
                    register_issue(
                        result,
                        message,
                        index,
                        time,
                        rule_uid,
                        IssueSeverity.ERROR,
                        description=f"Field '{field.name}' value {value.value} in message '{message.DESCRIPTOR.full_name}' does not refer to any existing message.",
                    )
                else:
                    # Check if referred message matches the expected type
                    expected_type = f"""osi3.{rule['refers_to'].strip("'")}"""
                    if referred_message.DESCRIPTOR.full_name != expected_type:
                        register_issue(
                            result,
                            message,
                            index,
                            time,
                            rule_uid,
                            IssueSeverity.ERROR,
                            description=f"Field '{field.name}' value {value.value} in message '{message.DESCRIPTOR.full_name}' refers to message '{referred_message.DESCRIPTOR.full_name}', which does not match the expected type '{expected_type}'.",
                        )

        # Recursively check nested messages
        if field.message_type is not None:
            if isinstance(value, google.protobuf.message.Message):
                check_message_against_rules(
                    value, rule_map, id_message_map, index, time, result
                )
            else:
                for item in value:
                    if isinstance(item, google.protobuf.message.Message):
                        check_message_against_rules(
                            item, rule_map, id_message_map, index, time, result
                        )


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

    trace = OSITrace(config.get_config_param("InputFile"), expected_type_name)

    result.register_checker(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=osirules_constants.CHECKER_ID,
        description="Evaluates messages in the trace file against the OSI Rules of the given OSI version to guarantee they are in conformance with the standard OSI rules.",
        summary="Checker validating OSI Rules compliance of messages in a trace file",
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

    for index, message in enumerate(trace):
        time = (
            message.timestamp.seconds + message.timestamp.nanos * 1e-9
            if hasattr(message, "timestamp") and message.HasField("timestamp")
            else None
        )
        if not message.HasField("version"):
            register_issue(
                result,
                message,
                index,
                time,
                version_rule_uid,
                IssueSeverity.ERROR,
                description="Version field is not set in top-level message.",
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
            register_issue(
                result,
                message,
                index,
                time,
                exp_version_rule_uid,
                IssueSeverity.ERROR,
                description=f"Version field value {message.version.version_major}.{message.version.version_minor}.{message.version.version_patch} is not the expected version {'.'.join([str(s) for s in expected_version])}.",
            )

        id_message_map = {}
        record_message_ids(message, id_message_map)
        check_message_against_rules(
            message, rule_uid_map, id_message_map, index, time, result
        )

    logging.info(
        f"Issues found - {result.get_checker_issue_count(checker_bundle_name=constants.BUNDLE_NAME, checker_id=osirules_constants.CHECKER_ID)}"
    )

    # TODO: Add logic to deal with error or to skip it
    result.set_checker_status(
        checker_bundle_name=constants.BUNDLE_NAME,
        checker_id=osirules_constants.CHECKER_ID,
        status=StatusType.COMPLETED,
    )
