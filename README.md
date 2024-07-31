# qc-osi-trace

This project implements the OSI Trace Checker for the ASAM Quality Checker project.

## Installation

To install the project, run:

```
pip install -r requirements.txt
```

This will install the needed dependencies to your local Python.

## Usage

The checker can be used as a Python script:

```
python main.py --help

usage: QC OSI Trace Checker [-h] (-d | -c CONFIG_PATH)

This is a collection of scripts for checking validity of OSI Trace (.osi)
files.

options:
  -h, --help            show this help message and exit
  -d, --default_config
  -c CONFIG_PATH, --config_path CONFIG_PATH

```

### Example

- No issues found

```
$ python main.py \
    -c example_config/config.xml
2024-07-31 16:09:01,186 - Initializing checks
2024-07-31 16:09:01,187 - Executing deserialization checks
2024-07-31 16:09:01,188 - Executing deserialization.expected_type check
2024-07-31 16:09:01,188 - Executing deserialization.version_is_set check
2024-07-31 16:09:01,188 - Executing deserialization.expected_version check
2024-07-31 16:09:01,191 - Issues found - 0
2024-07-31 16:09:01,192 - Done
```

- Issues found on file

```
$ python main.py \
    -c example_config/config-errors.xml
2024-07-31 16:15:05,779 - Initializing checks
2024-07-31 16:15:05,780 - Executing deserialization checks
2024-07-31 16:15:05,781 - Executing deserialization.expected_type check
2024-07-31 16:15:05,781 - Executing deserialization.version_is_set check
2024-07-31 16:15:05,781 - Executing deserialization.expected_version check
2024-07-31 16:15:05,796 - Issues found - 547
2024-07-31 16:15:05,806 - Done
```

## Tests

To run the tests, you need to have installed the main dependencies mentioned
at [Instalation](#installation).

Install Python tests and development dependencies:

```
pip install -r requirements-tests.txt
```

Execute tests:

```
python -m pytest -vv
```

They should output something similar to:

```
============================= test session starts =============================
platform win32 -- Python 3.10.4, pytest-8.2.2, pluggy-1.5.0 -- C:\Users\pmai\src\ASAM\qc-osi-trace\.venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\pmai\src\ASAM\qc-osi-trace
collecting ... collected 4 items

tests/test_deserialization_checks.py::test_deserialization_version_is_set_examples[invalid-SensorView-547] PASSED [ 25%]
tests/test_deserialization_checks.py::test_deserialization_version_is_set_examples[valid-SensorView-0] PASSED [ 50%]
tests/test_deserialization_checks.py::test_deserialization_expected_version[360-SensorView-3.5.0-547] PASSED [ 75%]
tests/test_deserialization_checks.py::test_deserialization_expected_version[360-SensorView-3.6.0-0] PASSED [100%]

============================== 4 passed in 0.39s ==============================
```

You can check more options for pytest at its [own documentation](https://docs.pytest.org/).

## Contributing

For contributing, you need to install the development requirements besides the
test and installation requirements, for that run:

```
pip install -r requirements-dev.txt
```

You need to have pre-commit installed and install the hooks:

```
pre-commit install
```
