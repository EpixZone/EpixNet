import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installPackagedTheme, THEME_ID, THEME_VERSION, THEME_BASE } from '../theme.sys.mjs';

const DEFAULT = 'default-theme@mozilla.org';
const ALTERNATE = 'firefox-compact-dark@mozilla.org';
function fixture({ selected = DEFAULT, initialized = false, previous, failure, installedPatch = {} } = {}) {
  const calls = [];
  const prefs = new Map([['extensions.activeThemeID', selected], ['epix.theme.initialized', initialized]]);
  const themes = new Map();
  let builtIn;
  const makeTheme = id => ({ id, type: 'theme', isActive: id === selected, userDisabled: id !== selected,
    async enable() { for (const theme of themes.values()) theme.isActive = false; this.isActive = true; this.userDisabled = false; calls.push(['enable', id]); prefs.set('extensions.activeThemeID', id); },
  });
  for (const id of [DEFAULT, ALTERNATE]) themes.set(id, makeTheme(id));
  if (previous) themes.set(THEME_ID, {
    ...makeTheme(THEME_ID), isBuiltin: false, scope: 1,
    async disable() { calls.push(['disable', THEME_ID]); this.isActive = false; this.userDisabled = true; themes.get(DEFAULT).isActive = true; prefs.set('extensions.activeThemeID', DEFAULT); },
    async uninstall() { calls.push(['uninstall', THEME_ID]); themes.set(THEME_ID, builtIn); builtIn.isActive = !builtIn.userDisabled; if (prefs.get('extensions.activeThemeID') === THEME_ID) prefs.set('extensions.activeThemeID', DEFAULT); },
    ...previous,
  });
  function register() {
    if (failure) throw new Error('engine install failed');
    builtIn = { ...makeTheme(THEME_ID), isActive: false, isBuiltin: true, version: THEME_VERSION, getResourceURI: () => ({ spec: THEME_BASE }),
      async disable() { calls.push(['disable-built-in', THEME_ID]); this.userDisabled = true; this.isActive = false; }, ...installedPatch };
    if (!themes.has(THEME_ID) || themes.get(THEME_ID).isBuiltin) themes.set(THEME_ID, builtIn);
    return builtIn;
  }
  const manager = {
    SCOPE_PROFILE: 1, readyPromise: Promise.resolve(),
    async getAddonByID(id) { return themes.get(id) || null; },
    async maybeInstallBuiltinAddon(...args) {
      calls.push(['install', ...args]);
      if (!themes.get(THEME_ID)?.isBuiltin) return register();
    },
    async installBuiltinAddon(base) { calls.push(['register', base]); return register(); },
  };
  const preferences = {
    getStringPref: (key, fallback) => prefs.get(key) ?? fallback,
    getBoolPref: (key, fallback) => prefs.get(key) ?? fallback,
    setBoolPref: (key, value) => prefs.set(key, value),
  };
  return { manager, preferences, calls, prefs, themes, run: legacy => installPackagedTheme(manager, preferences, legacy) };
}

test('fresh profile registers only the fixed packaged theme and selects it', async () => {
  const f = fixture(); await f.run(false);
  assert.deepEqual(f.calls, [['install', THEME_ID, THEME_VERSION, THEME_BASE], ['enable', THEME_ID]]);
  assert.equal(f.prefs.get('epix.theme.initialized'), true);
});

test('active legacy theme migrates through uninstall and built-in registration', async () => {
  const f = fixture({ selected: THEME_ID, previous: {} }); await f.run(true);
  assert.deepEqual(f.calls, [['register', THEME_BASE], ['disable-built-in', THEME_ID], ['disable', THEME_ID], ['uninstall', THEME_ID], ['enable', THEME_ID]]);
  assert.equal(f.prefs.get('extensions.activeThemeID'), THEME_ID);
  assert.deepEqual([...f.themes.values()].filter(theme => theme.isActive).map(theme => theme.id), [THEME_ID]);
});

test('migration waits for the active theme transition before uninstall or activation', async () => {
  let finish;
  const transition = new Promise(resolve => { finish = resolve; });
  const f = fixture({ selected: THEME_ID, previous: { async disable() { await transition; this.isActive = false; } } });
  const pending = f.run(true);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(f.calls, [['register', THEME_BASE], ['disable-built-in', THEME_ID]]);
  finish(); await pending;
  assert.deepEqual(f.calls, [['register', THEME_BASE], ['disable-built-in', THEME_ID], ['uninstall', THEME_ID], ['enable', THEME_ID]]);
});

test('legacy marker and subsequent launches preserve an intentionally selected System theme', async () => {
  for (const options of [{ previous: {} }, { initialized: true }]) {
    const f = fixture(options); await f.run(!!options.previous);
    assert.equal(f.prefs.get('extensions.activeThemeID'), DEFAULT);
    assert.ok(!f.calls.some(call => call[0] === 'enable'));
  }
});

test('an alternate selected theme survives legacy migration and initial installation', async () => {
  for (const previous of [{}, undefined]) {
    const f = fixture({ selected: ALTERNATE, previous }); await f.run(false);
    assert.equal(f.prefs.get('extensions.activeThemeID'), ALTERNATE);
    assert.ok(!f.calls.some(call => call[0] === 'enable'));
  }
});

test('restart keeps the same built-in theme and does not uninstall it', async () => {
  const f = fixture(); await f.run(false); f.calls.length = 0; await f.run(false);
  assert.deepEqual(f.calls, [['install', THEME_ID, THEME_VERSION, THEME_BASE]]);
  assert.equal(f.prefs.get('extensions.activeThemeID'), THEME_ID);
});

test('registration failure remains retryable and does not mark setup complete', async () => {
  const f = fixture({ failure: true }); await assert.rejects(f.run(false), /engine install failed/);
  assert.equal(f.prefs.get('epix.theme.initialized'), false);
  assert.ok(!f.calls.some(call => call[0] === 'enable'));
});

test('failed migration preserves the legacy theme and selected preference', async () => {
  const f = fixture({ selected: THEME_ID, previous: {}, failure: true });
  const previous = f.themes.get(THEME_ID);
  await assert.rejects(f.run(true), /engine install failed/);
  assert.deepEqual(f.calls, [['register', THEME_BASE]]);
  assert.equal(f.themes.get(THEME_ID), previous);
  assert.equal(f.prefs.get('extensions.activeThemeID'), THEME_ID);
  assert.equal(f.prefs.get('epix.theme.initialized'), false);
});

test('unexpected existing add-on or engine registration is rejected', async () => {
  for (const previous of [{ type: 'extension' }, { scope: 4 }]) {
    const f = fixture({ previous }); await assert.rejects(f.run(false), /not a profile theme/);
    assert.deepEqual(f.calls, []);
  }
  for (const installedPatch of [{ id: 'unexpected@example.invalid' }, { isBuiltin: false }, { type: 'extension' }, { version: 'other' }, { getResourceURI: () => ({ spec: 'resource://elsewhere/' }) }]) {
    const f = fixture({ installedPatch }); await assert.rejects(f.run(false), /did not register/);
    assert.equal(f.prefs.get('epix.theme.initialized'), false);
    const legacy = fixture({ selected: THEME_ID, previous: {}, installedPatch });
    await assert.rejects(legacy.run(true), /did not register/);
    assert.deepEqual(legacy.calls, [['register', THEME_BASE]]);
    assert.equal(legacy.prefs.get('extensions.activeThemeID'), THEME_ID);
  }
});

test('registration waits for Firefox and leaves signature requirements unchanged', async () => {
  const f = fixture(); let ready;
  f.prefs.set('xpinstall.signatures.required', true);
  f.manager.readyPromise = new Promise(resolve => { ready = resolve; });
  const pending = f.run(false); await Promise.resolve();
  assert.deepEqual(f.calls, []);
  ready(); await pending;
  assert.equal(f.prefs.get('xpinstall.signatures.required'), true);
});

test('packaged theme is static, unprivileged source with matching identity and version', () => {
  const manifest = JSON.parse(readFileSync(new URL('../../../shells/epix-theme/manifest.json', import.meta.url)));
  assert.equal(manifest.applications.gecko.id, THEME_ID);
  assert.equal(manifest.version, THEME_VERSION);
  assert.deepEqual(Object.keys(manifest).sort(), ['manifest_version', 'name', 'version', 'description', 'applications', 'theme', 'dark_theme'].sort());
  assert.deepEqual(Object.keys(manifest.theme), ['colors']);
  assert.deepEqual(Object.keys(manifest.dark_theme), ['colors']);
});
