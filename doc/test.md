# Mercury Library Tests

## Generating Coverage Report
The `test-coverage` target is used to generate a comprehensive code coverage report for the Mercury library. It compiles the code with coverage instrumentation, runs multiple tests, and collects coverage data. The collected data is then processed to create a detailed HTML report that shows which parts of the code were executed during the tests. This helps in identifying untested code paths and improving the overall test coverage.

### Requirements
1. Install `lcov` if it is not already installed:
    ```bash
    sudo apt-get install lcov
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