package zone.epix.app

/** Saved placement of the address and navigation rows. */
internal enum class BrowserControlsPosition(val preferenceValue: String, val label: String) {
    AUTOMATIC("auto", "Automatic"),
    TOP("top", "Top"),
    BOTTOM("bottom", "Bottom");

    fun isAtBottom(isLandscape: Boolean): Boolean = when (this) {
        AUTOMATIC -> !isLandscape
        TOP -> false
        BOTTOM -> true
    }

    companion object {
        fun fromStored(value: String?): BrowserControlsPosition =
            entries.firstOrNull { it.preferenceValue == value } ?: AUTOMATIC
    }
}
