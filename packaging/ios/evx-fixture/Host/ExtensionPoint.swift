import ExtensionFoundation

extension AppExtensionPoint {
    @Definition
    static var evxGameFixture: AppExtensionPoint {
        Name("evxGameFixture")
        EnhancedSecurity(true)
        // Default bundle-only scope. Do not broaden to system-wide extensions.
    }
}
