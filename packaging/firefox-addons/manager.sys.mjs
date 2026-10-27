import { LIMITS, validateCandidate, parseMirror, validateClient, signatureAccepted, macInput, InstallGuard } from './policy.sys.mjs';
import { installPackagedTheme } from './theme.sys.mjs';
const { AddonManager } = ChromeUtils.importESModule('resource://gre/modules/AddonManager.sys.mjs');
const { setTimeout, clearTimeout } = ChromeUtils.importESModule('resource://gre/modules/Timer.sys.mjs');
const { CustomizableUI } = ChromeUtils.importESModule('moz-src:///browser/components/customizableui/CustomizableUI.sys.mjs');
const RESOURCE = 'resource://epix-addon-installer/';
const HEX = /^[0-9a-f]{64}$/;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let initialized = false, profile, profileId, client, credential, guard, session, connection, operation, themeReady, unavailable = null;
const views = new Set(), renders = new WeakMap(), browserWindows = new WeakMap();
const api = {
  signed: AddonManager.SIGNEDSTATE_SIGNED, downloaded: AddonManager.STATE_DOWNLOADED,
  notBlocked: Ci.nsIBlocklistService.STATE_NOT_BLOCKED,
  modern: [Ci.nsIAppSignatureInfo.PKCS7_WITH_SHA256, Ci.nsIAppSignatureInfo.COSE_WITH_SHA256],
  known: [Ci.nsIAppSignatureInfo.PKCS7_WITH_SHA1, Ci.nsIAppSignatureInfo.PKCS7_WITH_SHA256, Ci.nsIAppSignatureInfo.COSE_WITH_SHA256]
};
function file(path) { const value = Cc['@mozilla.org/file/local;1'].createInstance(Ci.nsIFile); value.initWithPath(path); return value; }
function child(parent, ...parts) { const value = parent.clone(); for (const part of parts) value.append(part); return value; }
function regular(value, maximum) {
  if (!value.exists() || value.isSymlink() || !value.isFile() || value.fileSize < 1 || value.fileSize > maximum) throw new Error('Extension file is missing, changed, or too large.');
}
function readText(value, maximum) {
  regular(value, maximum);
  const stream = Cc['@mozilla.org/network/file-input-stream;1'].createInstance(Ci.nsIFileInputStream);
  stream.init(value, 0x01, 0, 0);
  const binary = Cc['@mozilla.org/binaryinputstream;1'].createInstance(Ci.nsIBinaryInputStream); binary.setInputStream(stream);
  try { return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(binary.readByteArray(value.fileSize))); }
  finally { binary.close(); }
}
function digest(value) {
  regular(value, LIMITS.archive); const bytes = value.fileSize;
  const stream = Cc['@mozilla.org/network/file-input-stream;1'].createInstance(Ci.nsIFileInputStream);
  stream.init(value, 0x01, 0, 0);
  try {
    const hash = Cc['@mozilla.org/security/hash;1'].createInstance(Ci.nsICryptoHash); hash.init(hash.SHA256); hash.updateFromStream(stream, bytes);
    return { bytes, sha256: Array.from(hash.finish(false), char => char.charCodeAt(0).toString(16).padStart(2, '0')).join('') };
  } finally { stream.close(); }
}
function mirror() { return parseMirror(readText(child(profile, 'epix-addons', 'mirror.json'), LIMITS.mirror), profileId); }
function refreshGuard() { guard.refresh(mirror()); }
function consent(candidate) {
  const path = child(profile, 'epix-addons', 'native-consent.json');
  if (!path.exists()) return false;
  const value = JSON.parse(readText(path, 8192));
  return value.protocol === 1 && value.profile_id === profileId && value.operation_id === candidate.operation_id && value.addon_id === candidate.addon_id && value.version === candidate.version && value.archive_sha256 === candidate.archive_sha256;
}
async function recordConsent(op) {
  current(op);
  const candidate = op.candidate;
  if (candidate.expires_at_ms <= Date.now()) throw new Error('The extension review expired.');
  await checkClean(candidate, op.action); current(op);
  if (digest(op.install.file).sha256 !== candidate.archive_sha256) throw new Error('The approved archive changed.');
  // The native broker uses its protected directory for atomic, synced consent.
  // Firefox cannot proceed to execution or staging until this acknowledgement.
  op.consentWrite = (async () => {
    const saved = await request({ command: 'consent', operation_id: candidate.operation_id, archive_sha256: candidate.archive_sha256 });
    if (saved?.protocol !== 1 || saved.profile_id !== profileId || ['operation_id', 'addon_id', 'version', 'archive_sha256'].some(field => saved[field] !== candidate[field])) throw new Error('The native extension consent does not match this review.');
    current(op);
    if (candidate.expires_at_ms <= Date.now() || digest(op.install.file).sha256 !== candidate.archive_sha256 || !consent(candidate)) throw new Error('The extension review expired or changed while saving consent.');
    guard.authorize(op.install);
  })();
  return op.consentWrite;
}
function engineAccepted(install, candidate) {
  return !Services.prefs.getBoolPref('xpinstall.signatures.dev-root', false) && signatureAccepted(install, candidate, api) &&
    install.addon.isSystem !== true && install.addon.scope === AddonManager.SCOPE_PROFILE;
}
function hex(bytes) { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
function decodeHex(value) { if (!HEX.test(value)) throw new Error('Invalid authenticated response.'); return Uint8Array.from(value.match(/../g), part => parseInt(part, 16)); }
async function request(value) {
  const window = Services.wm.getMostRecentWindow('navigator:browser');
  if (!window || window.closed) throw new Error('Open an EpixNet browser window before managing extensions.');
  const crypto = window.crypto;
  const body = new TextEncoder().encode(JSON.stringify(value));
  if (body.byteLength > LIMITS.request) throw new Error('Extension request exceeds its limit.');
  const nonce = hex(crypto.getRandomValues(new Uint8Array(32))), timestamp = String(Date.now());
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(credential), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  const mac = hex(new Uint8Array(await crypto.subtle.sign('HMAC', key, macInput('EpixNet addon broker request v1\0', [client.client_id, nonce, timestamp, body]))));
  const controller = new window.AbortController();
  const timeout = setTimeout(() => controller.abort(), ['prepare', 'stage'].includes(value.command) ? 150000 : 30000);
  let reply;
  try {
    const response = await window.fetch(client.endpoint, {
      method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer', signal: controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-Epix-Addon-Client': client.client_id, 'X-Epix-Addon-Nonce': nonce, 'X-Epix-Addon-Time': timestamp, 'X-Epix-Addon-Mac': mac }, body
    });
    const declared = response.headers.get('Content-Length');
    if (declared !== null && (!/^[0-9]+$/.test(declared) || Number(declared) > LIMITS.mirror)) throw new Error('Extension response exceeds its limit.');
    if (!response.body) throw new Error('The local extension response is empty.');
    const reader = response.body.getReader(), chunks = []; let length = 0;
    try {
      while (true) {
        const next = await reader.read(); if (next.done) break;
        length += next.value.byteLength;
        if (length > LIMITS.mirror) throw new Error('Extension response exceeds its limit.');
        chunks.push(next.value);
      }
    } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    reply = { status: response.status, bytes, mac: response.headers.get('X-Epix-Addon-Mac') };
  } catch (error) {
    throw new Error(controller.signal.aborted ? 'The local extension request timed out. Refresh status before trying again.' : error.message);
  } finally { clearTimeout(timeout); controller.abort(); }
  if (reply.bytes.length > LIMITS.mirror || !await crypto.subtle.verify('HMAC', key, decodeHex(reply.mac), macInput('EpixNet addon broker response v1\0', [client.client_id, nonce, timestamp, reply.bytes], reply.status))) throw new Error('The local extension response could not be authenticated. Close this browser and reopen it from EpixNet.');
  const decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(reply.bytes));
  if (decoded.ok !== true) throw new Error(typeof decoded.error?.message === 'string' ? decoded.error.message : 'The extension request was rejected.');
  return decoded.result;
}
function managedDigest(addon) {
  if (addon.scope !== AddonManager.SCOPE_PROFILE || addon.isSystem || !addon.isWebExtension) throw new Error('Managed extension location changed.');
  const uri = addon.getResourceURI('').QueryInterface(Ci.nsIJARURI).JARFile.QueryInterface(Ci.nsIFileURL);
  const expected = child(profile, 'extensions', `${addon.id}.xpi`);
  if (!uri.file.equals(expected)) throw new Error('Managed extension archive is outside the profile.');
  return digest(uri.file).sha256;
}
async function inventory() {
  const snapshot = mirror(), ids = new Set(snapshot.managed.map(owner => owner.addon_id));
  if (snapshot.pending?.candidate && consent(snapshot.pending.candidate)) ids.add(snapshot.pending.candidate.addon_id);
  const addons = await AddonManager.getAllAddons();
  return { addons: addons.map(addon => {
    const owned = ids.has(addon.id);
    // Firefox lists unavailable GMP plugins with a null version. Keep their
    // IDs occupied without inventing an installed version or archive proof.
    let version = addon.version;
    if (version == null && !owned) version = '';
    if (typeof version !== 'string' || (owned && !version)) throw new Error('Firefox could not identify a managed extension version.');
    return { addon_id: addon.id, version, archive_sha256: owned ? managedDigest(addon) : null, enabled: addon.isActive === true };
  }), has_pending_installs: (await AddonManager.getAllInstalls()).some(install => ![AddonManager.STATE_CANCELLED, AddonManager.STATE_INSTALLED, AddonManager.STATE_DOWNLOAD_FAILED, AddonManager.STATE_INSTALL_FAILED].includes(install.state)) };
}
async function connect() {
  if (connection) return connection;
  connection = (async () => {
    await AddonManager.readyPromise;
    await themeReady;
    session = await request({ command: 'open' });
    // Bundled wallet/theme startup work must settle before clean enrollment.
    let state;
    for (let attempt = 0; attempt < 20; attempt++) { state = await inventory(); if (!state.has_pending_installs) break; await sleep(250); }
    session = await request({ command: 'reconcile', inventory: state }); refreshGuard(); unavailable = null;
    if (session.needs_reconciliation) throw new Error('An extension operation needs reconciliation. Finish or cancel pending Firefox installs, then refresh status.');
    return session;
  })().catch(error => { unavailable = error.message; throw error; }).finally(() => { connection = null; renderAll(); });
  return connection;
}
async function checkClean(candidate, action) {
  const addons = await AddonManager.getAllAddons();
  const existing = addons.find(addon => addon.id === candidate.addon_id);
  const pending = (await AddonManager.getAllInstalls()).filter(install => install !== operation?.install && (install.addon?.id === candidate.addon_id || install.existingAddon?.id === candidate.addon_id));
  if (pending.length) throw new Error('Firefox already has a pending install for this extension. Cancel it before continuing.');
  if (action === 'Install') { if (existing) throw new Error('This ID is already installed outside this manager. It cannot be adopted.'); }
  else {
    const owner = mirror().managed.find(owner => owner.addon_id === candidate.addon_id);
    if (!owner || !existing || existing.version !== owner.version || managedDigest(existing) !== owner.archive_sha256 || owner.publisher !== candidate.publisher || owner.inner_path !== candidate.inner_path) throw new Error('The installed extension or its publisher changed. Refresh status before continuing.');
  }
}
function current(op) { if (operation !== op || op.cancelled || op.view.closed || op.browserWindow.closed || op.browserWindow.gBrowser.selectedBrowser !== op.browser || op.browser.currentURI.spec !== op.uri) throw new Error('The extension review was closed or its browser tab changed.'); }
async function prepare(view, source, action = 'Install') {
  if (operation) throw new Error('Finish the current extension review first.');
  if (!session || session.needs_reconciliation) await connect();
  const browserWindow = browserWindows.get(view);
  if (view.closed || !browserWindow?.gBrowser || browserWindow.closed) throw new Error('Open this manager from an EpixNet browser window.');
  const browser = browserWindow.gBrowser.selectedBrowser;
  const op = { view, action, browserWindow, browser, uri: browser.currentURI.spec, cancelled: false, candidate: null, install: null };
  const changed = () => { if (!op.finished) cancelOperation(op, 'The browser tab changed. Review the extension again.').catch(() => {}); };
  const progress = { onStateChange(currentBrowser, webProgress, _request, flags) { if (currentBrowser === browser && webProgress.isTopLevel && (flags & Ci.nsIWebProgressListener.STATE_START)) changed(); } };
  browserWindow.gBrowser.tabContainer.addEventListener('TabSelect', changed);
  browserWindow.gBrowser.addTabsProgressListener(progress);
  browserWindow.addEventListener('unload', changed, { once: true });
  op.cleanup = () => { if (op.cleaned) return; op.cleaned = true; clearTimeout(op.expiryTimeout); for (const remove of [() => browserWindow.gBrowser?.tabContainer.removeEventListener('TabSelect', changed), () => browserWindow.gBrowser?.removeTabsProgressListener(progress), () => browserWindow.removeEventListener('unload', changed), () => op.removeNativeListener?.()]) { try { remove(); } catch { /* A closed window may already have removed its listeners. */ } } };
  operation = op; renderAll();
  try {
    const candidate = validateCandidate(await request({ command: 'prepare', source_url: source, action })); op.candidate = candidate; current(op);
    op.expiryTimeout = setTimeout(() => cancelOperation(op, 'This package review expired. Review it again before installing.').catch(() => {}), Math.max(0, candidate.expires_at_ms - Date.now()));
    // Early ID reservation only denies other installs. It does not authorize any object.
    guard.ids.add(candidate.addon_id); await checkClean(candidate, action); current(op);
    const staged = await request({ command: 'stage', operation_id: candidate.operation_id, archive_sha256: candidate.archive_sha256 }); current(op);
    if (JSON.stringify(validateCandidate(staged.candidate)) !== JSON.stringify(candidate)) throw new Error('The prepared receipt changed.');
    refreshGuard(); const stagedFile = file(staged.path); guard.prepare(candidate, stagedFile);
    let install;
    try { install = await AddonManager.getInstallForFile(stagedFile); } finally { guard.clearTicket(); }
    if (op.cancelled || operation !== op) { try { install.cancel(); } finally { guard.revoke(install); } current(op); }
    op.install = install; current(op);
    if (guard.receipt(install) !== candidate || !engineAccepted(install, candidate)) throw new Error('Firefox did not verify an ordinary Mozilla-signed extension with a modern signature.');
    await checkClean(candidate, action); current(op);
    renderAll();
  } catch (error) { await cancelOperation(op, error.message); throw error; }
}
async function cancelOperation(op, message = 'Extension review cancelled.') {
  if (!op || op.cancelled || op.finished) return;
  op.cancelled = true; guard.clearTicket(); op.cleanup?.();
  try { op.install?.cancel(); } catch { /* The following reconciliation preserves uncertain outcomes. */ }
  if (op.install) guard.revoke(op.install);
  if (op.consentWrite) await op.consentWrite.catch(() => {});
  try {
    await request({ command: 'cancel', operation_id: op.candidate?.operation_id || null });
    session = await request({ command: 'reconcile', inventory: await inventory() }); refreshGuard();
  } catch (error) { unavailable = `${message} ${error.message}`; }
  if (operation === op) operation = null;
  op.cleanup?.();
  status(op.view, unavailable || message); renderAll();
}
async function finish(op, outcome) {
  if (op.finished || op.cancelled) return; op.finished = true;
  try {
    await request({ command: 'report', operation_id: op.candidate.operation_id, outcome }); refreshGuard();
    session = await request({ command: 'status' });
    status(op.view, typeof outcome === 'object' && 'Staged' in outcome ? 'Update approved and staged. Restart Firefox to activate it.' : typeof outcome === 'object' && 'Installed' in outcome ? 'Extension installed.' : 'Extension was not installed. Refresh status before another attempt.');
  } catch (error) { unavailable = error.message; status(op.view, error.message); }
  finally { guard.revoke(op.install); if (operation === op) operation = null; op.cleanup?.(); renderAll(); }
}
async function approve(view) {
  const op = operation; if (!op || op.view !== view || !op.install || op.approving) return;
  current(op); await checkClean(op.candidate, op.action); current(op);
  if (op.candidate.expires_at_ms <= Date.now() || !engineAccepted(op.install, op.candidate) || digest(op.install.file).sha256 !== op.candidate.archive_sha256) throw new Error('The package review expired or its verified bytes changed. Cancel and review it again.');
  op.approving = true; renderAll();
  const identity = { addon_id: op.candidate.addon_id, version: op.candidate.version, archive_sha256: op.candidate.archive_sha256 };
  const listener = {
    onInstallEnded: async (_install, addon) => { try { if (addon.id !== identity.addon_id || addon.version !== identity.version || managedDigest(addon) !== identity.archive_sha256) throw new Error('Installed archive does not match the approved receipt.'); addon.applyBackgroundUpdates = AddonManager.AUTOUPDATE_DISABLE; await finish(op, { Installed: identity }); } catch (error) { await finish(op, { Unknown: { reason: error.message } }); } },
    onInstallPostponed: async () => { try { if (!consent(op.candidate) || op.candidate.expires_at_ms <= Date.now()) { await cancelOperation(op, 'The extension review expired before staging.'); return; } if (digest(child(profile, 'extensions', 'staged', `${identity.addon_id}.xpi`)).sha256 !== identity.archive_sha256) throw new Error('Staged archive does not match the approved receipt.'); await finish(op, { Staged: identity }); } catch (error) { await finish(op, { Unknown: { reason: error.message } }); } },
    onInstallCancelled: () => finish(op, 'Cancelled'), onDownloadCancelled: () => finish(op, 'Cancelled'),
    onInstallFailed: () => finish(op, { Failed: { reason: 'Firefox could not install this extension.' } }),
    onDownloadFailed: () => finish(op, { Failed: { reason: 'Firefox could not read this extension.' } })
  };
  op.install.addListener(listener);
  const promptObserver = { observe(subject) {
    const info = subject.wrappedJSObject;
    if (info?.browser !== op.browser || info.installs?.length !== 1 || info.installs[0] !== op.install) return;
    try {
      current(op);
      const nativePrompt = op.install.promptHandler;
      if (typeof nativePrompt !== 'function' || op.promptWrapped) throw new Error('Firefox native confirmation is unavailable.');
      op.install.promptHandler = async promptInfo => {
        if (promptInfo.install !== op.install) throw new Error('Firefox confirmation belongs to another package.');
        current(op); await nativePrompt(promptInfo); current(op);
        await recordConsent(op);
      };
      op.promptWrapped = true;
    } catch { op.install.cancel(); }
  } };
  Services.obs.addObserver(promptObserver, 'addon-install-started');
  op.removeNativeListener = () => { op.install.removeListener(listener); Services.obs.removeObserver(promptObserver, 'addon-install-started'); };
  op.browserWindow.focus();
  try {
    AddonManager.installAddonFromAOM(op.browser, Services.io.newURI(op.candidate.source_url), op.install);
    if (!op.promptWrapped) throw new Error('Firefox did not provide the required native confirmation boundary.');
  } catch (error) { op.approving = false; await cancelOperation(op, 'Firefox could not open the extension confirmation.'); throw error; }

}
function status(view, message) { if (!view.closed) view.document.getElementById('status').textContent = message; }
function button(document, label, action) { const result = document.createElementNS('http://www.w3.org/1999/xhtml', 'button'); result.type = 'button'; result.textContent = label; result.disabled = !!operation; result.addEventListener('click', () => action().catch(error => { status(document.defaultView, error.message); })); return result; }
async function manage(owner, action) {
  if (operation) throw new Error('Finish the current extension review first.');
  const addon = await AddonManager.getAddonByID(owner.addon_id);
  if (!addon || managedDigest(addon) !== owner.archive_sha256) throw new Error('The managed extension changed. Refresh status.');
  if (action === 'toggle') { if (addon.userDisabled) await addon.enable(); else await addon.disable(); }
  else {
    const snapshot = await request({ command: 'begin_uninstall', addon_id: owner.addon_id }); refreshGuard();
    try { await addon.uninstall(); if (await AddonManager.getAddonByID(owner.addon_id)) throw new Error('Firefox has not completed the uninstall.'); await request({ command: 'report', operation_id: snapshot.operation_id, outcome: { Uninstalled: { addon_id: owner.addon_id } } }); refreshGuard(); }
    catch (error) { await request({ command: 'report', operation_id: snapshot.operation_id, outcome: { Unknown: { reason: error.message } } }); throw error; }
  }
  session = await request({ command: 'status' }); renderAll();
}
async function render(view) {
  if (view.closed) return;
  const generation = (renders.get(view) || 0) + 1; renders.set(view, generation);
  const doc = view.document, op = operation?.view === view ? operation : null;
  doc.getElementById('review').disabled = !!operation || !session || !!session.needs_reconciliation;
  doc.getElementById('source').disabled = !!operation;
  doc.getElementById('refresh').disabled = !!operation;
  doc.getElementById('candidate').hidden = !op?.install;
  if (op?.install) {
    const c = op.candidate; doc.getElementById('candidate-name').textContent = c.name;
    const details = doc.getElementById('details'); details.replaceChildren();
    for (const [key, value] of [['Publisher', c.publisher], ['Package', c.inner_path], ['Extension ID', c.addon_id], ['Version', c.version], ['Signature', 'Mozilla signed, modern signature verified'], ['SHA-256', c.archive_sha256]]) { const dt = doc.createElementNS('http://www.w3.org/1999/xhtml', 'dt'), dd = doc.createElementNS('http://www.w3.org/1999/xhtml', 'dd'); dt.textContent = key; dd.textContent = value; details.append(dt, dd); }
    doc.getElementById('permissions').textContent = 'Required permissions and sites:\n' + [...c.required_permissions, ...c.host_permissions].join('\n') + '\n\nOptional permissions and sites:\n' + [...c.optional_permissions, ...c.optional_host_permissions].join('\n');
    doc.getElementById('approve').disabled = op.approving;
    doc.getElementById('cancel').disabled = op.approving;
  }
  const list = doc.getElementById('managed'); list.replaceChildren();
  for (const owner of session?.managed || []) {
    const addon = await AddonManager.getAddonByID(owner.addon_id); if (view.closed || renders.get(view) !== generation) return;
    const card = doc.createElementNS('http://www.w3.org/1999/xhtml', 'div'); card.className = 'extension';
    const heading = doc.createElementNS('http://www.w3.org/1999/xhtml', 'h3'); heading.textContent = addon?.name || owner.addon_id;
    const detail = doc.createElementNS('http://www.w3.org/1999/xhtml', 'p'); detail.textContent = `${owner.version} · ${addon?.isActive ? 'Enabled' : 'Disabled'}\n${owner.source_url}`;
    card.append(heading, detail, button(doc, addon?.userDisabled ? 'Enable' : 'Disable', () => manage(owner, 'toggle')), button(doc, 'Review update', () => prepare(view, owner.source_url, { Update: { addon_id: owner.addon_id } })), button(doc, 'Uninstall', async () => { if (Services.prompt.confirm(view, 'Uninstall extension', `Remove ${addon?.name || owner.addon_id}?`)) await manage(owner, 'uninstall'); })); list.append(card);
  }
  if (!session?.managed?.length) list.textContent = 'No extensions have been installed through this manager.';
}
function renderAll() { for (const view of views) render(view).catch(error => status(view, error.message)); }
function browserWindowForCommand(event) {
  const window = event?.target?.ownerDocument?.defaultView;
  if (!event?.isTrusted || !window || window.closed || !window.gBrowser || !window.document.nodePrincipal.isSystemPrincipal || window.document.documentElement.getAttribute('windowtype') !== 'navigator:browser') return null;
  return window;
}
function openManager(browserWindow) {
  const view = Services.ww.openWindow(browserWindow, 'chrome://epix-addon-installer/content/manager.xhtml', '_blank', 'chrome,dialog=no,resizable,centerscreen,width=840,height=780', null);
  browserWindows.set(view, browserWindow);
  view.addEventListener('load', async () => {
    if (!view.document.nodePrincipal.isSystemPrincipal) { view.close(); return; }
    views.add(view);
    const run = task => task().catch(error => status(view, error.message));
    view.document.getElementById('source-form').addEventListener('submit', event => { event.preventDefault(); run(() => prepare(view, view.document.getElementById('source').value)); });
    view.document.getElementById('approve').addEventListener('click', () => run(() => approve(view)));
    view.document.getElementById('cancel').addEventListener('click', () => run(() => cancelOperation(operation)));
    view.document.getElementById('refresh').addEventListener('click', () => run(async () => { await connect(); status(view, 'Ready. Review a package URL or choose a managed extension.'); }));
    view.addEventListener('unload', () => { views.delete(view); browserWindows.delete(view); if (operation?.view === view) cancelOperation(operation).catch(() => {}); }, { once: true });
    renderAll(); await run(async () => { if (!session) await connect(); status(view, unavailable || 'Ready. Review a package URL or choose a managed extension.'); });
  }, { once: true });
}
export function initialize() {
  if (initialized) throw new Error('Extension manager already initialized.');
  const version = Services.appinfo.version.split('.').map(Number);
  if (version[0] !== 153 || version[1] < 4 || typeof AddonManager.getInstallForFile !== 'function' || typeof AddonManager.installAddonFromAOM !== 'function' || typeof AddonManager.getAllInstalls !== 'function' || typeof AddonManager.maybeInstallBuiltinAddon !== 'function' || typeof AddonManager.installBuiltinAddon !== 'function' || api.known.some(value => !Number.isInteger(value))) throw new Error('Unsupported Firefox extension engine.');
  profile = Services.dirsvc.get('ProfD', Ci.nsIFile);
  const identity = JSON.parse(readText(child(profile, 'epix-addons', 'profile.json'), 4096));
  if (identity.protocol !== 1 || !HEX.test(identity.profile_id)) throw new Error('Invalid extension profile identity.'); profileId = identity.profile_id;
  client = validateClient(JSON.parse(readText(child(profile, 'epix-addons', 'client.json'), 4096)), profileId);
  credential = Services.env.get('EPIX_ADDON_BROKER_SECRET');
  if (!HEX.test(credential) || Services.env.get('EPIX_ADDON_BROKER_CLIENT') !== client.client_id) throw new Error('Extension launcher credentials are unavailable.');
  guard = new InstallGuard({ mirror: mirror(), inspectFile: digest, sameFile: (a, b) => !!a && a.equals(b), signature: engineAccepted, onUnavailable: () => { unavailable = 'The extension guard failed. Close this browser and reopen it from EpixNet.'; } });
  AddonManager.addInstallListener(guard); initialized = true;
  themeReady = installPackagedTheme(AddonManager, Services.prefs, child(profile, '.epix-theme-activated').exists());
  themeReady.catch(error => Components.utils.reportError(`Packaged Epix theme unavailable: ${error.message}`));
  CustomizableUI.createWidget({ id: 'epix-xite-extensions', label: 'EpixNet Extensions', tooltiptext: 'Manage extensions from verified xites', defaultArea: CustomizableUI.AREA_NAVBAR, removable: false, onCreated: node => node.setAttribute('image', 'chrome://mozapps/skin/extensions/extension.svg'), onCommand: event => { const window = browserWindowForCommand(event); if (window) openManager(window); } });
  // Keep the pre-stage guard alive even if the local node is temporarily absent.
  Services.obs.addObserver(function started() {
    Services.obs.removeObserver(started, 'browser-delayed-startup-finished');
    // Headless CA warm-up can mark the widget seen without placing it. Ensure
    // the visible browser always has the dedicated manager's entry point.
    if (!CustomizableUI.getPlacementOfWidget('epix-xite-extensions')) CustomizableUI.addWidgetToArea('epix-xite-extensions', CustomizableUI.AREA_NAVBAR);
    connect().catch(() => {});
  }, 'browser-delayed-startup-finished');
}
