import argparse
import logging
import pathlib

from qc_baselib import Configuration, Result
from qc_baselib.models.common import ParamType

from qc_ositrace import constants
from qc_ositrace.checks.deserialization import deserialization_checker
from qc_ositrace.checks.osirules import osirules_checker

logging.basicConfig(format="%(asctime)s - %(message)s", level=logging.INFO)


def args_entrypoint() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="QC OSI Trace Checker",
        description="This is a collection of scripts for checking validity of OSI Trace (.osi) files.",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--default_config", action="store_true")
    group.add_argument("-c", "--config_path")

    parser.add_argument(
        "-i",
        "--input_file",
        type=pathlib.Path,
        help="Path to the input OSI Trace file.",
    )
    parser.add_argument(
        "--osiType",
        type=str,
        help="Type of the OSI Trace file (e.g., 'SensorView', 'SensorData').",
    )
    parser.add_argument(
        "--osiVersion",
        type=str,
        help="Expected version of the OSI Trace file (e.g., '3.7.0').",
    )
    parser.add_argument(
        "--osiRulesFile", type=pathlib.Path, help="Path to a custom OSI rules file."
    )

    parser.add_argument(
        "-r",
        "--result_file",
        type=pathlib.Path,
        help="Path to the output result file.",
    )

    parser.add_argument(
        "--output_config",
        type=pathlib.Path,
        help="Path to save the configuration after running the checks.",
    )

    return parser.parse_args()


def run_checker_bundle(config: Configuration) -> Result:
    """
    Run the OSI Trace checker bundle with the provided configuration and result objects.
    This function is a wrapper to allow for easier testing and modularity.
    """

    result = Result()
    result.register_checker_bundle(
        name=constants.BUNDLE_NAME,
        build_date="2024-06-05",
        description="OSI Trace checker bundle",
        version=constants.BUNDLE_VERSION,
        summary="",
    )
    result.set_result_version(version=constants.BUNDLE_VERSION)

    input_file_path = config.get_config_param("InputFile")
    input_param = ParamType(name="InputFile", value=input_file_path)
    result.get_checker_bundle_result(constants.BUNDLE_NAME).params.append(input_param)

    deserialization_checker.run_checks(config=config, result=result)
    osirules_checker.run_checks(config=config, result=result)

    return result


def main():
    args = args_entrypoint()

    logging.info("Initializing checks")

    config = Configuration()
    if args.default_config:
        logging.info("Using default configuration")
        config.register_checker_bundle(checker_bundle_name=constants.BUNDLE_NAME)
    else:
        config.load_from_file(xml_file_path=args.config_path)
        logging.info("Configuration loaded from %s", args.config_path)

    if args.input_file:
        logging.info("Setting input file: %s", args.input_file)
        config.set_config_param("InputFile", str(args.input_file))

    if args.osiType:
        logging.info("Setting OSI Type: %s", args.osiType)
        config.set_config_param("osiType", args.osiType)
    if args.osiVersion:
        logging.info("Setting OSI Version: %s", args.osiVersion)
        config.set_config_param("osiVersion", args.osiVersion)

    if args.osiRulesFile:
        logging.info("Setting OSI Rules File: %s", args.osiRulesFile)
        config.set_config_param("osiRulesFile", str(args.osiRulesFile))

    if args.result_file:
        logging.info("Setting result file: %s", args.result_file)
        config.register_checker_bundle(checker_bundle_name=constants.BUNDLE_NAME)
        config.set_checker_bundle_param(
            checker_bundle_name=constants.BUNDLE_NAME,
            name="resultFile",
            value=str(args.result_file),
        )

    logging.info("Running OSI Trace checker bundle")

    result = run_checker_bundle(config=config)

    if config.get_checker_bundle_param(
        checker_bundle_name=constants.BUNDLE_NAME, param_name="resultFile"
    ):
        logging.info("Writing results to file")

        result.write_to_file(
            config.get_checker_bundle_param(
                checker_bundle_name=constants.BUNDLE_NAME, param_name="resultFile"
            )
        )
    else:
        logging.info("No result file specified, results will not be written to file")

    if args.output_config:
        logging.info("Writing configuration to file: %s", args.output_config)
        config.write_to_file(args.output_config)

    logging.info("Done")


if __name__ == "__main__":
    main()
