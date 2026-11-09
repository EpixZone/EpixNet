'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const tests = __dirname;
const production = path.resolve(tests, '../app/src/main/java/zone/epix/app');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'epix-aware-tests-'));
const jar = path.join(temporary, 'aware-tests.jar');
const sources = ['NearbyTransport.kt', 'AwareControl.kt', 'WifiAwareMeshTransport.kt'].map(name => path.join(production, name));
sources.push(path.join(tests, 'WifiAwareTransportTests.kt'));
sources.push(...fs.readdirSync(path.join(tests, 'aware-stubs')).filter(name => name.endsWith('.kt'))
  .map(name => path.join(tests, 'aware-stubs', name)));
function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit', timeout: 120000 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited with ${result.status ?? result.signal}`);
}
try {
  run(process.env.KOTLINC || 'kotlinc', [...sources, '-jvm-target', '17', '-include-runtime', '-d', jar]);
  run(process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin/java') : 'java', ['-jar', jar]);
} finally {
  fs.rmSync(temporary, { recursive: true });
}
