# Mercury Library Tests

## Generating Coverage Report
The `test-coverage` and `test-coverage-fuzz` targets are used to generate a comprehensive code coverage report for the Mercury library. It compiles the code with coverage instrumentation, runs multiple tests, and collects coverage data. The collected data is then processed to create a detailed HTML report that shows which parts of the code were executed during the tests. This helps in identifying untested code paths and improving the overall test coverage.

There are two targets for generating coverage reports:

- **`test-coverage`**: Runs all tests **except fuzz tests** and creates the coverage report.
- **`test-coverage-fuzz`**: First calls `test-coverage` and then generates a coverage report **including coverage from fuzz tests** as well.

> **Note:**  
> The `test-coverage-fuzz` target will **not work on RHEL-based Linux distributions** due to toolchain compatibility issues with coverage instrumentation. It is supported and will work correctly **only on Debian-based Linux distributions**.

### Requirements
1. Install `lcov`, `clang` and `llvm` if not already installed:
    ```bash
    sudo apt-get install lcov clang llvm
    ```
2. Download the resource file and copy it into the folder `unit_tests/xtra/resources/`.

### Steps to Generate the Report
1. In the root directory, run:
    ```bash
    ./configure
    make test-coverage
    ```

The generated report can be found in the `coverage_html_report` directory.

### Viewing the Report
To view the report, you can take the `coverage_html_report` folder to a web server and open that in a web browser.