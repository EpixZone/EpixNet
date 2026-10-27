// Pure validation shared by the packaged privileged adapter and its tests.
export const LIMITS = Object.freeze({ archive: 32 * 1024 * 1024, request: 6 * 1024 * 1024, mirror: 2 * 1024 * 1024, managed: 256, permissionBytes: 65536 });
const HEX = /^[0-9a-f]{64}$/;
const ADDON_ID = /^[A-Za-z0-9@._{}-]{1,255}$/;
const PHASES = new Set(["Preparing", "Ready", "HandedOff", "Staged", "Installed", "Cancelled", "Failed", "NeedsReconciliation", "Uninstalling", "Uninstalled"]);
const FORBIDDEN = new Set(["management", "nativemessaging", "nativemessagingfromcontent", "nativemessagingfromaddon", "geckoviewaddons", "experiments", "experiment_apis"]);
const bytes = value => new TextEncoder().encode(value).length;

function requireThat(ok, message) { if (!ok) throw new Error(message); }
function object(value, label) { requireThat(value && typeof value === "object" && !Array.isArray(value), `Invalid ${label}.`); return value; }
function text(value, max, label, empty = false) {
  requireThat(typeof value === "string" && (empty || value.length > 0) && bytes(value) <= max && !/[\u0000-\u001f\u007f]/.test(value), `Invalid ${label}.`);
  return value;
}
function hex(value, label) { requireThat(typeof value === "string" && HEX.test(value), `Invalid ${label}.`); return value; }
export function reservedId(id) { return typeof id === "string" && (id.toLowerCase().endsWith("@epix.zone") || id.toLowerCase() === "zone.epix.nmh"); }
export function addonId(value) { requireThat(typeof value === "string" && ADDON_ID.test(value) && !reservedId(value), "This extension ID is reserved or unsupported."); return value; }

export function validateCandidate(value) {
  object(value, "extension receipt");
  hex(value.operation_id, "operation"); addonId(value.addon_id);
  text(value.version, 128, "extension version"); text(value.name, 256, "extension name");
  text(value.publisher, 128, "publisher"); text(value.inner_path, 1024, "archive path");
  text(value.governing_manifest, 1024, "governing manifest"); text(value.source_url, 4096, "source URL");
  hex(value.archive_sha256, "archive digest");
  requireThat(Number.isSafeInteger(value.byte_length) && value.byte_length > 0 && value.byte_length <= LIMITS.archive, "Unsupported archive size.");
  requireThat(Number.isSafeInteger(value.expires_at_ms) && value.expires_at_ms > 0, "Invalid receipt expiry.");
  requireThat(value.engine === "Gecko" && [2, 3].includes(value.manifest_version), "Unsupported extension engine or manifest.");
  let total = 0;
  for (const name of ["required_permissions", "optional_permissions", "host_permissions", "optional_host_permissions"]) {
    requireThat(Array.isArray(value[name]) && value[name].length <= 256, "Invalid permission list.");
    for (const permission of value[name]) {
      text(permission, 2048, "permission"); total += bytes(permission);
      requireThat(!FORBIDDEN.has(permission.toLowerCase()), "Native and experimental extension privileges are unavailable.");
    }
  }
  requireThat(total <= LIMITS.permissionBytes, "Extension permissions exceed the review limit.");
  return value;
}

export function validateOwnership(value) {
  object(value, "extension ownership"); addonId(value.addon_id);
  text(value.version, 128, "extension version"); hex(value.archive_sha256, "archive digest");
  text(value.publisher, 128, "publisher"); text(value.inner_path, 1024, "archive path");
  text(value.source_url, 4096, "source URL"); requireThat(value.engine === "Gecko", "Unsupported ownership engine.");
  return value;
}

export function parseMirror(raw, profileId) {
  requireThat(typeof raw === "string" && bytes(raw) <= LIMITS.mirror, "Extension ownership state exceeds its limit.");
  const value = object(JSON.parse(raw), "extension ownership state");
  requireThat(value.protocol === 1 && hex(value.profile_id, "profile") === profileId, "Extension ownership belongs to another profile.");
  requireThat(Array.isArray(value.managed) && value.managed.length <= LIMITS.managed, "Invalid managed extension list.");
  const ids = new Set();
  for (const owner of value.managed) {
    validateOwnership(owner); requireThat(!ids.has(owner.addon_id), "Duplicate extension ownership."); ids.add(owner.addon_id);
  }
  if (value.pending !== null) {
    const pending = object(value.pending, "pending extension operation");
    hex(pending.operation_id, "operation"); requireThat(PHASES.has(pending.phase), "Unknown extension operation state.");
    if (pending.candidate !== null) {
      validateCandidate(pending.candidate);
      requireThat(pending.operation_id === pending.candidate.operation_id, "Pending receipt does not match its operation.");
    }
    if (pending.uninstall_id != null) addonId(pending.uninstall_id);
    if (pending.message != null) text(pending.message, 4096, "operation message", true);
  }
  return value;
}

export function protectedIds(mirror) {
  const ids = new Set(mirror.managed.map(owner => owner.addon_id));
  if (mirror.pending?.candidate && !["Cancelled", "Failed", "Uninstalled"].includes(mirror.pending.phase)) ids.add(mirror.pending.candidate.addon_id);
  if (mirror.pending?.uninstall_id) ids.add(mirror.pending.uninstall_id);
  return ids;
}

export function validateClient(value, profileId) {
  object(value, "extension broker configuration");
  requireThat(value.protocol === 1 && hex(value.profile_id, "profile") === profileId, "Extension broker belongs to another profile.");
  hex(value.client_id, "client");
  requireThat(!Object.hasOwn(value, "secret"), "Broker credentials must not be stored in the profile.");
  const match = typeof value.endpoint === "string" && /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/EpixNet-Internal\/AddonBroker$/.exec(value.endpoint);
  requireThat(match && Number(match[1]) <= 65535, "Extension broker must use its fixed local endpoint.");
  return value;
}

export function signatureAccepted(install, candidate, api) {
  if (!api || !Number.isInteger(api.signed) || !Number.isInteger(api.downloaded) || !Number.isInteger(api.notBlocked) || !Array.isArray(api.modern) || !api.modern.length || !api.modern.every(Number.isInteger) || !Array.isArray(api.known) || !api.known.every(Number.isInteger)) return false;
  const addon = install?.addon;
  return install?.error === 0 && install.state === api.downloaded && addon?.id === candidate.addon_id && addon.version === candidate.version &&
    addon.type === "extension" && addon.isWebExtension === true && addon.isCompatible === true && addon.appDisabled === false &&
    addon.blocklistState === api.notBlocked && addon.signedState === api.signed &&
    Array.isArray(addon.signedTypes) && addon.signedTypes.every(type => Number.isInteger(type) && api.known.includes(type)) && addon.signedTypes.some(type => api.modern.includes(type));
}

export function macInput(domain, fields, status = null) {
  const encoder = new TextEncoder();
  const parts = [encoder.encode(domain)];
  for (const field of fields) {
    const data = typeof field === "string" ? encoder.encode(field) : field;
    requireThat(data instanceof Uint8Array, "Invalid authenticated field.");
    const length = new Uint8Array(8); new DataView(length.buffer).setUint32(4, data.length, false);
    parts.push(length, data);
  }
  // The response status precedes its final body field, not the entire envelope.
  if (status !== null) {
    requireThat(Number.isInteger(status) && status >= 100 && status <= 599, "Invalid response status.");
    const encoded = new Uint8Array(2); new DataView(encoded.buffer).setUint16(0, status, false);
    parts.splice(parts.length - 2, 0, encoded);
  }
  const result = new Uint8Array(parts.reduce((sum, item) => sum + item.length, 0));
  let offset = 0; for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

/** One-use local factory admission. No source URL/path allowlist authorizes later objects. */
export class InstallGuard {
  constructor({ mirror, inspectFile, sameFile, signature, onUnavailable = () => {} }) {
    this.ids = protectedIds(mirror); this.inspectFile = inspectFile; this.sameFile = sameFile;
    this.signature = signature; this.onUnavailable = onUnavailable; this.ticket = null;
    this.consented = new WeakSet(); this.allowed = new WeakMap(); this.unavailable = false;
  }
  refresh(mirror) { this.ids = protectedIds(mirror); }
  prepare(candidate, file, now = Date.now()) {
    validateCandidate(candidate);
    requireThat(!this.unavailable && !this.ticket && candidate.expires_at_ms > now, "Extension receipt is unavailable, expired, or already in use.");
    requireThat(this.ids.has(candidate.addon_id), "Durable ownership receipt is missing.");
    this.ticket = { candidate, file };
  }
  authorize(install) { requireThat(this.allowed.has(install) && this.allowed.get(install).expires_at_ms > Date.now(), "The native extension consent expired."); this.consented.add(install); }
  revoke(install) { this.allowed.delete(install); this.consented.delete(install); }
  clearTicket() { this.ticket = null; }
  receipt(install) { return this.allowed.get(install) || null; }
  fail() { this.unavailable = true; this.ticket = null; this.onUnavailable(); }
  deny(install) { try { install.cancel(); } catch { this.fail(); } return false; }
  managed(install) { return this.ids.has(install?.addon?.id) || this.ids.has(install?.existingAddon?.id); }
  onNewInstall(install) {
    if (this.unavailable) return this.deny(install);
    const ticket = this.ticket;
    let matchesFile = false;
    try { matchesFile = !!ticket && this.sameFile(install.file, ticket.file); } catch { return this.deny(install); }
    if (matchesFile) {
      this.ticket = null;
      try {
        const actual = this.inspectFile(install.file);
        if (ticket.candidate.expires_at_ms <= Date.now() || actual.sha256 !== ticket.candidate.archive_sha256 || actual.bytes !== ticket.candidate.byte_length || !this.signature(install, ticket.candidate)) return this.deny(install);
        this.allowed.set(install, ticket.candidate);
        return true;
      } catch { return this.deny(install); }
    }
    return this.managed(install) ? this.deny(install) : true;
  }
  onDownloadStarted(install) { return this.unavailable || this.managed(install) ? this.deny(install) : true; }
  onDownloadEnded(install) { return this.unavailable || this.managed(install) ? this.deny(install) : true; }
  onInstallStarted(install) {
    if (this.unavailable) return this.deny(install);
    if (!this.managed(install)) return true;
    const candidate = this.allowed.get(install);
    return !!candidate && this.consented.has(install) && candidate.expires_at_ms > Date.now() && install.addon?.id === candidate.addon_id && install.addon?.version === candidate.version || this.deny(install);
  }
}
