'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'epix-ble-tests-'));
const java = process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin', 'java') : 'java';
const source = path.resolve(__dirname, '../app/src/main/java/zone/epix/app');
const output = path.join(temporary, 'ble-tests.jar');
const stubs = path.join(__dirname, 'ble-stubs');
const args = [path.join(source, 'NearbyTransport.kt'), path.join(source, 'BleMeshTransport.kt'),
  path.join(__dirname, 'BleMeshTests.kt'), ...fs.readdirSync(stubs).filter(name => name.endsWith('.kt')).sort().map(name => path.join(stubs, name)),
  '-jvm-target', '17', '-include-runtime', '-d', output];

function run(command, commandArgs) {
  const result = spawnSync(command, commandArgs, { cwd: __dirname, stdio: 'inherit', timeout: 120000 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited with ${result.status ?? result.signal}`);
}

try {
  if (process.env.KOTLIN_COMPILER_CLASSPATH && process.env.KOTLIN_HOME) {
    run(java, ['-Xmx512m', '-cp', process.env.KOTLIN_COMPILER_CLASSPATH,
      'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-kotlin-home', process.env.KOTLIN_HOME, ...args]);
  } else {
    run(process.env.KOTLINC || 'kotlinc', args);
  }
  run(java, ['-jar', output]);
} finally {
  fs.rmSync(temporary, { recursive: true });
}
