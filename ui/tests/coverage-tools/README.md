# Globe browser coverage

Install the pinned test dependencies and Chromium, then run from the repository root:

```sh
npm ci --prefix ui/tests/coverage-tools --ignore-scripts
node ui/tests/coverage-tools/node_modules/playwright/cli.js install --with-deps chromium
node --test ui/tests/globe-coverage.test.cjs
node ui/tests/globe-browser.cjs --coverage coverage
```

The browser serves the production globe bundle, sidebar CSS, and world texture over a local HTTP listener. It checks WebGL output, peer geometry, mouse and touch input, scoped keyboard zoom, theme changes, resizing, pause/resume, and resource disposal. It does not start a node or access user data.

Chromium measures the shipped bundle with Playwright's precise JavaScript coverage. The mapper requires that the bundle contain the editable `globe.js` source exactly once. It clips and rebases V8 function and block offsets to that exact source span while retaining zero-hit ranges. The standard `v8-to-istanbul` converter and Istanbul reporters then produce line, function, and branch data. No source exclusions or coverage ignore comments are added.

The Sonar job imports `coverage/globe-lcov.info`. The JSON reports preserve raw browser coverage, converted coverage, test results, and overall summaries for inspection. Sonar determines new-code coverage against the pull request baseline; the local whole-file summary is not that gate result.
