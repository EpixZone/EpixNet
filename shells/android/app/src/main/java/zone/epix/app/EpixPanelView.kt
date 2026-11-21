package zone.epix.app

import android.content.Context
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.os.Build
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView

/** Native settings rows share the dialog's theme and keep their full text at large font sizes. */
internal class EpixPanelView(context: Context) : LinearLayout(context) {
    private val primary = themeColor(android.R.attr.textColorPrimary)
    private val secondary = themeColor(android.R.attr.textColorSecondary)
    private val accent = if (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK ==
        Configuration.UI_MODE_NIGHT_YES) 0xffb7a5ff.toInt() else 0xff6042b6.toInt()

    init {
        orientation = VERTICAL
        setPadding(dp(16), dp(4), dp(16), dp(8))
    }

    fun addSection(title: String) {
        addView(text(title, 12f, accent).apply {
            setTypeface(typeface, Typeface.BOLD)
            setPadding(dp(12), dp(16), dp(12), dp(6))
            if (Build.VERSION.SDK_INT >= 28) isAccessibilityHeading = true
        }, LayoutParams(MATCH, WRAP))
    }

    fun addInfo(icon: Int, title: String, summary: String, tint: Int = accent, selectable: Boolean = false) {
        val row = row().apply { gravity = Gravity.TOP }
        row.addView(icon(icon, tint), iconParams())
        val labels = labels(title, summary)
        if (selectable) (labels.getChildAt(1) as TextView).setTextIsSelectable(true)
        row.addView(labels, LayoutParams(0, WRAP, 1f))
        addView(row, LayoutParams(MATCH, WRAP))
    }

    fun addToggle(icon: Int, title: String, summary: String, checked: Boolean, onChanged: (Boolean) -> Unit): Switch {
        val row = row()
        row.addView(icon(icon), iconParams())
        val labels = LinearLayout(context).apply { orientation = VERTICAL }
        val toggle = Switch(context).apply {
            text = title
            textSize = 15f
            setTextColor(primary)
            minimumHeight = dp(48)
            switchPadding = dp(12)
            contentDescription = "$title. $summary"
            isChecked = checked
            setOnCheckedChangeListener { _, value -> onChanged(value) }
        }
        labels.addView(toggle, LayoutParams(MATCH, WRAP))
        labels.addView(text(summary, 13f, secondary).apply {
            importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
        }, LayoutParams(MATCH, WRAP))
        row.addView(labels, LayoutParams(0, WRAP, 1f))
        addView(row, LayoutParams(MATCH, WRAP))
        return toggle
    }

    fun addAction(icon: Int, title: String, summary: String, onClick: (ActionRow) -> Unit): ActionRow {
        val row = ActionRow(icon, title, summary)
        row.setOnClickListener { onClick(row) }
        addView(row, LayoutParams(MATCH, WRAP).apply { topMargin = dp(4) })
        return row
    }

    inner class ActionRow(icon: Int, private val title: String, summary: String) : LinearLayout(context) {
        private val detail = text(summary, 13f, secondary).apply { setPadding(0, dp(3), 0, 0) }

        init {
            orientation = HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = dp(64)
            setPadding(dp(12), dp(12), dp(12), dp(12))
            val card = GradientDrawable().apply {
                cornerRadius = dp(12).toFloat()
                setColor((accent and 0x00ffffff) or 0x10000000)
            }
            background = RippleDrawable(ColorStateList.valueOf((accent and 0x00ffffff) or 0x30000000), card, null)
            addView(icon(icon), iconParams())
            val labels = LinearLayout(context).apply {
                orientation = VERTICAL
                importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
                addView(text(title, 15f, primary))
                addView(detail)
            }
            addView(labels, LayoutParams(0, WRAP, 1f))
            addView(icon(R.drawable.ic_panel_chevron, secondary), LayoutParams(dp(20), dp(20)).apply {
                marginStart = dp(8)
            })
            isFocusable = true
            accessibilityDelegate = object : AccessibilityDelegate() {
                override fun onInitializeAccessibilityNodeInfo(host: View, info: AccessibilityNodeInfo) {
                    super.onInitializeAccessibilityNodeInfo(host, info)
                    info.className = Button::class.java.name
                }
            }
            updateSummary(summary)
        }

        fun updateSummary(summary: String) {
            detail.text = summary
            contentDescription = "$title. $summary"
        }
    }

    private fun row() = LinearLayout(context).apply {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(12), dp(8), dp(12), dp(8))
    }

    private fun labels(title: String, summary: String) = LinearLayout(context).apply {
        orientation = VERTICAL
        addView(text(title, 14f, primary))
        addView(text(summary, 13f, secondary).apply { setPadding(0, dp(3), 0, 0) })
    }

    private fun icon(resource: Int, tint: Int = accent) = ImageView(context).apply {
        setImageResource(resource)
        imageTintList = ColorStateList.valueOf(tint)
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    private fun iconParams() = LayoutParams(dp(24), dp(24)).apply { marginEnd = dp(16) }

    private fun text(value: String, size: Float, color: Int) = TextView(context).apply {
        text = value
        textSize = size
        setTextColor(color)
    }

    private fun themeColor(attribute: Int): Int {
        val values = context.obtainStyledAttributes(intArrayOf(attribute))
        return try { values.getColor(0, Color.GRAY) } finally { values.recycle() }
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density + 0.5f).toInt()

    private companion object {
        const val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
        const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT
    }
}
