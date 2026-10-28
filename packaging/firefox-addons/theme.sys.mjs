// Only this static application resource can be registered as a built-in theme.
// The launcher checks both this module and its manifest against embedded bytes.
export const THEME_ID = 'theme@epix.zone';
export const THEME_VERSION = '1.0.1';
export const THEME_BASE = 'resource://epix-addon-installer/theme/';
const SELECTED_THEME = 'extensions.activeThemeID';
const ACTIVATED = 'epix.theme.initialized';
const DEFAULT_THEME = 'default-theme@mozilla.org';

function requirePackagedTheme(theme) {
  if (!theme || theme.id !== THEME_ID || theme.type !== 'theme' || theme.isBuiltin !== true ||
      theme.version !== THEME_VERSION || theme.getResourceURI('').spec !== THEME_BASE) {
    throw new Error('Firefox did not register the packaged Epix theme.');
  }
}

async function migrateProfileTheme(manager, previous) {
  if (previous.type !== 'theme' || previous.scope !== manager.SCOPE_PROFILE) {
    throw new Error('The previous Epix theme is not a profile theme.');
  }
  // The profile add-on retains precedence until its replacement is ready.
  // A registration failure must leave the working legacy theme in place.
  const packaged = await manager.installBuiltinAddon(THEME_BASE);
  requirePackagedTheme(packaged);
  // Firefox can mark the hidden replacement enabled from the selected ID.
  // Keep it disabled until promotion, so enable() performs the full switch.
  await packaged.disable();
  // Disabling awaits Firefox's theme transition. Uninstalling an active
  // theme starts an unawaited fallback that can disable the replacement.
  if (previous.isActive) await previous.disable();
  await previous.uninstall();
}

/** Migrate the old profile XPI using Firefox's lifecycle, preserving theme choice. */
export async function installPackagedTheme(manager, prefs, legacyActivated = false) {
  await manager.readyPromise;
  const selected = prefs.getStringPref(SELECTED_THEME, DEFAULT_THEME);
  const initialized = legacyActivated || prefs.getBoolPref(ACTIVATED, false);
  const previous = await manager.getAddonByID(THEME_ID);
  if (previous && !previous.isBuiltin) {
    await migrateProfileTheme(manager, previous);
  } else {
    await manager.maybeInstallBuiltinAddon(THEME_ID, THEME_VERSION, THEME_BASE);
  }
  const theme = await manager.getAddonByID(THEME_ID);
  requirePackagedTheme(theme);
  // Only choose Epix on initial setup or restore it when it was already selected.
  // Later selections, including the default System theme, belong to the user.
  if (selected === THEME_ID || (!initialized && selected === DEFAULT_THEME)) {
    if (!theme.isActive) await theme.enable();
  } else if (prefs.getStringPref(SELECTED_THEME, DEFAULT_THEME) !== selected) {
    const chosen = await manager.getAddonByID(selected);
    if (chosen?.type === 'theme') await chosen.enable();
  }
  prefs.setBoolPref(ACTIVATED, true);
}
