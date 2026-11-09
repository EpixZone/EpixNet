'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const coroutines = process.env.COROUTINES_JAR;
if (!coroutines || !fs.existsSync(coroutines)) throw new Error('Set COROUTINES_JAR to the existing Kotlin coroutines library.');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'epix-nearby-pump-'));
const java = process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin', 'java') : 'java';
const source = path.resolve(__dirname, '../app/src/main/java/zone/epix/app');
const output = path.join(temporary, 'pump-tests.jar');
const args = ['NearbyTransport.kt', 'NearbyPump.kt', 'NearbyPermissions.kt'].map(name => path.join(source, name));
args.push(path.join(__dirname, 'NearbyPumpTests.kt'), '-classpath', coroutines,
  '-jvm-target', '17', '-include-runtime', '-d', output);

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
  run(java, ['-cp', [output, coroutines].join(path.delimiter), 'zone.epix.app.NearbyPumpTestsKt']);
} finally {
  fs.rmSync(temporary, { recursive: true });
}
