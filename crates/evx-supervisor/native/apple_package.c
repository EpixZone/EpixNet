/* Authenticate the current host and its sealed EVX package policy through
 * public Security APIs. No shell command, environment or xite supplies it. */
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* The package assembler rejects a host built without this adapter or with a
 * different compiled release identity, including EPIX_SKIP_BUILD mistakes. */
#ifndef EVX_RELEASE_TEAM_ID
#define EVX_RELEASE_TEAM_ID ""
#endif
__attribute__((used)) const char evx_release_build_policy[] =
    "EVX_PACKAGE_V1|apple-xpc|team=" EVX_RELEASE_TEAM_ID;

struct evx_package_policy {
    char bundle[PATH_MAX];
    char identifier[256];
    char team[32];
    char manifest_sha256[65];
};
static bool string_field(CFDictionaryRef map, CFStringRef key, char *out, size_t length) {
    CFTypeRef value = map ? CFDictionaryGetValue(map, key) : NULL;
    return value && CFGetTypeID(value) == CFStringGetTypeID() &&
        CFStringGetCString(value, out, (CFIndex)length, kCFStringEncodingUTF8);
}
static bool package_fields(CFDictionaryRef plist, CFDictionaryRef signing, bool fixture, struct evx_package_policy *out) {
    char profile[64]; char bundle_id[256]; char filename[64];
    if (!string_field(plist, CFSTR("EVXExecutionProfile"), profile, sizeof(profile)) ||
        strcmp(profile, fixture ? "apple-xpc-fixture" : "apple-xpc-developer-id") ||
        !string_field(plist, CFSTR("CFBundleIdentifier"), bundle_id, sizeof(bundle_id)) ||
        !string_field(signing, kSecCodeInfoIdentifier, out->identifier, sizeof(out->identifier)) ||
        strcmp(bundle_id, out->identifier) ||
        !string_field(plist, CFSTR("EVXServiceManifest"), filename, sizeof(filename)) ||
        strcmp(filename, "evx-services.json") ||
        !string_field(plist, CFSTR("EVXServiceManifestSHA256"), out->manifest_sha256, sizeof(out->manifest_sha256))) return false;
    if (strlen(out->manifest_sha256) != 64) return false;
    for (unsigned n = 0; n < 64; ++n) if (!strchr("0123456789abcdef", out->manifest_sha256[n])) return false;
    return true;
}

static bool signing_flag(CFDictionaryRef signing, int required) {
    int flags = 0;
    CFTypeRef value = CFDictionaryGetValue(signing, kSecCodeInfoFlags);
    return value && CFGetTypeID(value) == CFNumberGetTypeID() &&
        CFNumberGetValue(value, kCFNumberIntType, &flags) && (flags & required);
}

static bool developer_certificate(SecStaticCodeRef code, const char *team) {
    char text[512];
    int length = snprintf(text, sizeof(text), "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"%s\"", team);
    if (length < 0 || (size_t)length >= sizeof(text)) return false;
    CFStringRef expression = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
    if (!expression) return false;
    SecRequirementRef requirement = NULL;
    bool valid = !SecRequirementCreateWithString(expression, kSecCSDefaultFlags, &requirement) &&
        !SecStaticCodeCheckValidity(code, kSecCSStrictValidate, requirement);
    if (requirement) CFRelease(requirement);
    CFRelease(expression);
    return valid;
}

static bool package_signature(CFDictionaryRef plist, CFDictionaryRef signing, SecStaticCodeRef code,
                              bool fixture, const char *expected_team, struct evx_package_policy *out) {
    if (fixture) return signing_flag(signing, kSecCodeSignatureAdhoc);
    if (strlen(expected_team) != 10) return false;
    for (unsigned n = 0; n < 10; ++n) {
        if (!strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", expected_team[n])) return false;
    }
    char declared[32];
    return string_field(signing, kSecCodeInfoTeamIdentifier, out->team, sizeof(out->team)) &&
        string_field(plist, CFSTR("EVXReleaseTeamIdentifier"), declared, sizeof(declared)) &&
        !strcmp(out->team, expected_team) && !strcmp(declared, expected_team) &&
        signing_flag(signing, kSecCodeSignatureRuntime) && developer_certificate(code, expected_team);
}

int evx_apple_package_policy(bool fixture, const char *expected_team, struct evx_package_policy *out) {
    SecCodeRef self = NULL; SecStaticCodeRef code = NULL;
    CFDictionaryRef signing = NULL; CFURLRef path = NULL;
    int result = -1;
    if (!out || !expected_team) return -1;
    memset(out, 0, sizeof(*out));
    if (SecCodeCopySelf(kSecCSDefaultFlags, &self) ||
        SecCodeCopyStaticCode(self, kSecCSDefaultFlags, &code) ||
        SecCodeCheckValidity(self, kSecCSDefaultFlags, NULL) ||
        SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, NULL) ||
        SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signing)) goto done;
    CFTypeRef value = CFDictionaryGetValue(signing, kSecCodeInfoPList);
    if (!value || CFGetTypeID(value) != CFDictionaryGetTypeID()) goto done;
    CFDictionaryRef plist = value;
    if (!package_fields(plist, signing, fixture, out)) goto done;
    if (!package_signature(plist, signing, code, fixture, expected_team, out)) goto done;
    if (SecCodeCopyPath(code, kSecCSDefaultFlags, &path) ||
        !CFURLGetFileSystemRepresentation(path, true, (UInt8 *)out->bundle, sizeof(out->bundle))) goto done;
    result = 0;
done:
    if (path) CFRelease(path);
    if (signing) CFRelease(signing);
    if (code) CFRelease(code);
    if (self) CFRelease(self);
    return result;
}
