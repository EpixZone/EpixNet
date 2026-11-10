// npm ci --prefix ui/tests/coverage-tools --ignore-scripts
// node ui/tests/globe-browser.cjs --coverage /path/to/coverage
// Exercises the shipped WebGL bundle and CSS, without a backend or mocked renderer.
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const assert = require('node:assert/strict');
const {chromium} = require('./coverage-tools/node_modules/playwright');
const v8toIstanbul = require('./coverage-tools/node_modules/v8-to-istanbul');
const {createCoverageMap} = require('./coverage-tools/node_modules/istanbul-lib-coverage');
const {createContext} = require('./coverage-tools/node_modules/istanbul-lib-report');
const reports = require('./coverage-tools/node_modules/istanbul-reports');
const {sourceCoverage} = require('./helpers/globe-coverage.cjs');
const repo = path.resolve(__dirname, '../..');
const sourcePath = 'crates/epix-plugins/media/sidebar/globe/globe.js';
const source = fs.readFileSync(path.join(repo, sourcePath), 'utf8');
const media = path.join(repo, 'crates/epix-plugins/media/sidebar');
const output = path.resolve(process.argv[process.argv.indexOf('--coverage') + 1] || 'coverage');
assert.ok(process.argv.includes('--coverage'), 'provide --coverage output directory');
fs.mkdirSync(output, {recursive: true});
const errors = [], cases = [];
let browser;

const html = `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/sidebar.css">
<style>body{margin:0}.sidebar{right:0;width:min(420px,100%)}.sidebar .content{width:100%;padding-top:20px}</style>
<div class="sidebar-container loaded"><div class="sidebar"><div class="content sidebar-properties">
<section class="sidebar-peer-map"><div id="map-panel"><div class="globe"></div></div></section>
<input id="outside" aria-label="Outside the map" value="Draft value">
</div></div></div><script src="/globe/all.js"></script>`;
const assets = new Map([
  ['/', ['text/html', Buffer.from(html)]],
  ['/sidebar.css', ['text/css', fs.readFileSync(path.join(media, 'all.css'))]],
  ['/globe/all.js', ['application/javascript', fs.readFileSync(path.join(media, 'globe/all.js'))]],
  ['/globe/world.jpg', ['image/jpeg', fs.readFileSync(path.join(media, 'globe/world.jpg'))]]
]);
const server = http.createServer((request, response) => {
  const asset = assets.get(new URL(request.url, 'http://localhost').pathname);
  if (!asset) { response.writeHead(404); response.end(); return; }
  response.writeHead(200, {'Content-Type': asset[0]}); response.end(asset[1]);
});

async function position(page) {
  return page.evaluate(() => globeObservation.position);
}
async function distance(page) {
  return Math.hypot(...await position(page));
}
async function changedPosition(page, before) {
  await page.waitForFunction(before => Math.hypot(...globeObservation.position.map((n, i) => n - before[i])) > 10, before);
}
async function assertSquare(page, width) {
  await page.waitForFunction(() => {
    const element = document.querySelector('.globe'), canvas = element.querySelector('canvas');
    return canvas.width === element.clientWidth && canvas.height === element.clientHeight;
  });
  const sizes = await page.locator('.globe').evaluate(element => {
    const canvas = element.querySelector('canvas'), box = canvas.getBoundingClientRect();
    return {width: element.clientWidth, height: element.clientHeight, canvasWidth: box.width, canvasHeight: box.height,
      inlineWidth: canvas.style.width, inlinePosition: canvas.style.position};
  });
  assert.equal(sizes.width, width); assert.equal(sizes.height, width);
  assert.equal(sizes.canvasWidth, width); assert.equal(sizes.canvasHeight, width);
  assert.equal(sizes.inlineWidth, ''); assert.equal(sizes.inlinePosition, '');
}

async function collectCoverage(page) {
  const measured = await page.coverage.stopJSCoverage();
  const bundle = measured.find(entry => entry.url === new URL('/globe/all.js', page.url()).href);
  assert.ok(bundle, 'Chromium measured the production bundle');
  assert.equal(bundle.source, assets.get('/globe/all.js')[1].toString(), 'measured bundle is the file served from the repository');
  const converter = v8toIstanbul(path.join(repo, sourcePath), 0, {source});
  await converter.load();
  converter.applyCoverage(sourceCoverage(bundle, source));
  const coverageMap = createCoverageMap(converter.toIstanbul());
  const context = createContext({dir: output, coverageMap});
  reports.create('lcovonly', {file: 'globe-lcov.info', projectRoot: repo}).execute(context);
  reports.create('json', {file: 'globe-istanbul.json'}).execute(context);
  fs.writeFileSync(path.join(output, 'globe-v8.json'), JSON.stringify(bundle));
  const summary = coverageMap.getCoverageSummary().toJSON();
  assert.ok(summary.lines.covered > 0 && summary.branches.total > 0, 'line and branch hits are reported');
  fs.writeFileSync(path.join(output, 'globe-results.json'), JSON.stringify({cases, errors, summary}, null, 2));
  console.log(JSON.stringify({cases, summary, output}));
}

(async () => {
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    browser = await chromium.launch({headless: true});
    const page = await browser.newPage({viewport: {width: 1024, height: 800}, hasTouch: true});
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => {
      if (message.type() === 'error' && /shader|webgl|gl_invalid/i.test(message.text())) errors.push(message.text());
    });
    await page.coverage.startJSCoverage();
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.evaluate(() => {
      const request = window.requestAnimationFrame, cancel = window.cancelAnimationFrame;
      window.pendingGlobeFrames = new Set();
      window.requestAnimationFrame = callback => {
        const id = request(time => { pendingGlobeFrames.delete(id); callback(time); });
        pendingGlobeFrames.add(id); return id;
      };
      window.cancelAnimationFrame = id => { pendingGlobeFrames.delete(id); cancel(id); };
      window.globe = new DAT.Globe(document.querySelector('.globe'), {imgDir: '/globe/', controls: document.querySelector('.sidebar-peer-map')});
      window.globeObservation = {renders: 0, position: null, disposed: 0, textureDisposed: 0};
      const render = globe.renderer.render;
      globe.renderer.render = function(scene, camera) {
        globeObservation.renders++;
        globeObservation.position = [camera.position.x, camera.position.y, camera.position.z];
        const result = render.call(this, scene, camera);
        const context = this.getContext(), pixel = new Uint8Array(4);
        context.readPixels(Math.floor(this.domElement.width / 2), Math.floor(this.domElement.height / 2), 1, 1, context.RGBA, context.UNSIGNED_BYTE, pixel);
        globeObservation.pixel = [...pixel];
        return result;
      };
      globe.addData([37.422, -122.085, 0.08, -33.8688, 151.209, -0.135], {format: 'magnitude'});
      globe.createPoints(); globe.animate(); globe.resume();
    });
    await page.waitForFunction(() => globe.scene.children.some(child => child.material?.uniforms?.texture?.value.image?.complete));
    await page.waitForFunction(() => globeObservation.pixel?.[3] > 0 && globeObservation.pixel.slice(0, 3).some(n => n > 0));
    assert.equal(await page.evaluate(() => pendingGlobeFrames.size), 1, 'repeated resume keeps one render loop');
    assert.ok(await page.evaluate(() => globe.points.geometry.vertices.length > 0), 'peer geometry reaches the rendered scene');
    await assertSquare(page, 280);
    cases.push('real texture, shader, peer geometry and single render loop');

    for (const theme of ['dark', 'light']) {
      await page.evaluate(theme => { document.body.className = 'theme-' + theme; }, theme);
      await page.waitForFunction(expected => globe.scene.children.find(child => child.material?.uniforms?.landColor).material.uniforms.landColor.value.getHexString() === expected,
        theme === 'dark' ? '14181d' : '59636e');
    }
    await page.evaluate(() => { document.body.className = ''; });
    for (const scheme of ['dark', 'light']) {
      await page.emulateMedia({colorScheme: scheme});
      await page.waitForFunction(expected => globe.scene.children.find(child => child.material?.uniforms?.landColor).material.uniforms.landColor.value.getHexString() === expected,
        scheme === 'dark' ? '14181d' : '59636e');
    }
    cases.push('explicit light/dark and live operating-system theme events');

    const canvas = page.locator('.globe');
    await canvas.click();
    const beforeKey = await distance(page);
    await canvas.press('ArrowUp');
    await page.waitForFunction(before => Math.hypot(...globeObservation.position) < before - 50, beforeKey);
    const near = await distance(page);
    await canvas.press('ArrowDown');
    await page.waitForFunction(before => Math.hypot(...globeObservation.position) > before + 30, near);
    await page.evaluate(() => globe.reset());
    await page.waitForFunction(() => Math.hypot(...globeObservation.position) > 854);
    await page.locator('#outside').focus(); await page.keyboard.press('ArrowUp');
    await page.waitForTimeout(100);
    assert.ok(await distance(page) > 854, 'keyboard controls do not capture unrelated fields');
    await canvas.hover();
    const beforeWheel = await distance(page);
    await page.mouse.wheel(0, -120);
    await page.waitForFunction(before => Math.hypot(...globeObservation.position) < before - 50, beforeWheel);
    const box = await canvas.boundingBox(), beforeDrag = await position(page);
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down(); await page.mouse.move(box.x + box.width / 2 + 60, box.y + box.height / 2 + 30, {steps: 8}); await page.mouse.up();
    await changedPosition(page, beforeDrag);
    cases.push('scoped keyboard zoom, wheel zoom and mouse rotation');

    await page.setViewportSize({width: 390, height: 844});
    await page.evaluate(() => document.body.classList.add('controls-narrow'));
    await assertSquare(page, 250);
    const mobile = await canvas.boundingBox(), x = mobile.x + mobile.width / 2, y = mobile.y + mobile.height / 2;
    const session = await page.context().newCDPSession(page);
    const touch = (type, points) => session.send('Input.dispatchTouchEvent', {type, touchPoints: points.map(([id, x, y]) => ({id, x, y, radiusX: 4, radiusY: 4, force: 1}))});
    const beforeTouch = await position(page);
    await touch('touchStart', [[1, x, y]]); await touch('touchMove', [[1, x + 40, y + 20]]); await touch('touchEnd', []);
    await changedPosition(page, beforeTouch);
    const beforePinch = await distance(page);
    await touch('touchStart', [[1, x - 35, y], [2, x + 35, y]]);
    await touch('touchMove', [[1, x - 65, y], [2, x + 65, y]]);
    await page.waitForFunction(before => Math.hypot(...globeObservation.position) < before - 50, beforePinch);
    // Lifting one finger transitions smoothly from pinch back to rotation.
    await touch('touchEnd', [[1, x - 65, y]]); await touch('touchMove', [[1, x - 35, y + 20]]); await touch('touchEnd', []);
    await session.detach();
    await page.evaluate(() => { document.querySelector('.sidebar').style.width = '200px'; });
    await assertSquare(page, 168); // Narrow controls use 16px padding on each side.
    await page.evaluate(() => { document.querySelector('.sidebar').style.width = ''; });
    await page.setViewportSize({width: 320, height: 700}); await assertSquare(page, 250);
    cases.push('mobile touch rotation, pinch continuation and observed square resizing');

    await page.evaluate(() => { globe.pause(); globe.pause(); document.querySelector('#map-panel').hidden = true; globe.resize(); });
    const stopped = await page.evaluate(() => globeObservation.renders);
    await page.waitForTimeout(150);
    assert.equal(await page.evaluate(() => globeObservation.renders), stopped);
    assert.equal(await page.evaluate(() => pendingGlobeFrames.size), 0);
    await page.evaluate(() => { document.querySelector('#map-panel').hidden = false; globe.resume(); globe.resume(); });
    await page.waitForFunction(stopped => globeObservation.renders > stopped, stopped);
    assert.equal(await page.evaluate(() => pendingGlobeFrames.size), 1);
    await assertSquare(page, 250);
    cases.push('hidden pause, reopen resize and idempotent resume');

    await page.evaluate(() => {
      globe.scene.traverse(object => {
        object.geometry?.addEventListener('dispose', () => globeObservation.disposed++);
        object.material?.addEventListener('dispose', () => globeObservation.disposed++);
        object.material?.uniforms?.texture?.value.addEventListener('dispose', () => globeObservation.textureDisposed++);
      });
      globe.unload();
      globeObservation.finalRenders = globeObservation.renders;
      globeObservation.finalLand = globe.scene.children.find(child => child.material?.uniforms?.landColor).material.uniforms.landColor.value.getHexString();
      document.body.classList.add('theme-dark');
    });
    await page.emulateMedia({colorScheme: 'dark'});
    await page.setViewportSize({width: 1024, height: 800});
    await page.keyboard.press('ArrowUp'); await page.mouse.wheel(0, -100);
    await page.waitForTimeout(150);
    assert.deepEqual(await page.evaluate(() => ({canvas: document.querySelector('.globe canvas') !== null,
      frames: pendingGlobeFrames.size, renders: globeObservation.renders === globeObservation.finalRenders,
      theme: globe.scene.children.find(child => child.material?.uniforms?.landColor).material.uniforms.landColor.value.getHexString() === globeObservation.finalLand,
      disposed: globeObservation.disposed > 0, textureDisposed: globeObservation.textureDisposed > 0})),
    {canvas: false, frames: 0, renders: true, theme: true, disposed: true, textureDisposed: true});
    cases.push('unload releases GPU resources, canvas, animation and theme listeners');
    assert.deepEqual(errors, [], 'no browser or WebGL errors');
    await collectCoverage(page);
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
