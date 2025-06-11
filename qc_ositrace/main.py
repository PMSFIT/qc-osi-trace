import argparse
import logging

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

    return parser.parse_args()


def main():
    args = args_entrypoint()

    logging.info("Initializing checks")

    if args.default_config:
        raise RuntimeError("Not implemented.")
    else:
        config = Configuration()
        config.load_from_file(xml_file_path=args.config_path)

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
        result.get_checker_bundle_result(constants.BUNDLE_NAME).params.append(
            input_param
        )

        deserialization_checker.run_checks(config=config, result=result)
        osirules_checker.run_checks(config=config, result=result)

        result.write_to_file(
            config.get_checker_bundle_param(
                checker_bundle_name=constants.BUNDLE_NAME, param_name="resultFile"
            )
        )

    logging.info("Done")


if __name__ == "__main__":
    main()
