# qc-osi-trace

This project implements the OSI Trace Checker for the ASAM Quality Checker project.

- [qc-osi-trace](#qc-osi-trace)
  - [Installation and usage](#installation-and-usage)
    - [Installation using pip](#installation-using-pip)
      - [To use as a library](#to-use-as-a-library)
      - [To use as an application](#to-use-as-an-application)
    - [Installation from source](#installation-from-source)
    - [Example output](#example-output)
  - [Tests](#tests)
    - [Execute tests](#execute-tests)
  - [Contributing](#contributing)

## Installation and usage

qc-osi-trace can be installed using pip or from source.

### Installation using pip

qc-osi-trace can be installed using pip, so that it can be used as a library or as an application.

```bash
pip install qc-osi-trace@git+https://github.com/PMSFIT/qc-osi-trace@main
```

**Note**: To install from different sources, you can replace `@main` with
your desired target. For example, `develop` branch as `@develop`.

#### To use as a library

After installation, the usage is similar to the one expressed in the
[`main.py`](./qc_ositrace/main.py) script:

```Python3
from qc_ositrace.checks.deserialization import deserialization_checker
```

#### To use as an application

```
qc_ositrace --help

usage: QC OSI Trace Checker [-h] (-d | -c CONFIG_PATH)

This is a collection of scripts for checking validity of OSI Trace (.osi)
files.

options:
  -h, --help            show this help message and exit
  -d, --default_config
  -c CONFIG_PATH, --config_path CONFIG_PATH
```

### Installation from source

The project can be installed from source using [Poetry](https://python-poetry.org/).

```bash
poetry install
```

After installing from source, the usage is the same as shown above.

It is also possible to execute the qc_ositrace application using Poetry.

```bash
poetry run qc_ositrace --help

usage: QC OSI Trace Checker [-h] (-d | -c CONFIG_PATH)

This is a collection of scripts for checking validity of OSI Trace (.osi)
files.

options:
  -h, --help            show this help message and exit
  -d, --default_config
  -c CONFIG_PATH, --config_path CONFIG_PATH
```

### Example output

- No issues found

```bash
$ qc_ositrace -c example_config/config.xml
2024-07-31 16:09:01,186 - Initializing checks
2024-07-31 16:09:01,187 - Executing deserialization checks
2024-07-31 16:09:01,188 - Executing deserialization.expected_type check
2024-07-31 16:09:01,188 - Executing deserialization.version_is_set check
2024-07-31 16:09:01,188 - Executing deserialization.expected_version check
2024-07-31 16:09:01,191 - Issues found - 0
2024-07-31 16:09:01,192 - Done
```

- Issues found

```bash
$ qc_ositrace -c example_config/config-errors.xml
2024-07-31 16:15:05,779 - Initializing checks
2024-07-31 16:15:05,780 - Executing deserialization checks
2024-07-31 16:15:05,781 - Executing deserialization.expected_type check
2024-07-31 16:15:05,781 - Executing deserialization.version_is_set check
2024-07-31 16:15:05,781 - Executing deserialization.expected_version check
2024-07-31 16:15:05,796 - Issues found - 547
2024-07-31 16:15:05,806 - Done
```

## Tests

To run the tests, you need to install the extra test dependency.

```bash
poetry install --with dev
```

### Execute tests

```bash
poetry run pytest -vv
```

They should output something similar to:

```bash
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

For contributing, you need to install the development requirements.
For that run:

```bash
poetry install --with dev
```

You need to have pre-commit installed and install the hooks:

```
pre-commit install
```
