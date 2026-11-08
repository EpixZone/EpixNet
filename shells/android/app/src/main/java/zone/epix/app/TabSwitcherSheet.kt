package zone.epix.app

import android.app.AlertDialog
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.os.Build
import android.os.Bundle
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowManager
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.BaseAdapter
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView

internal data class TabSwitcherEntry(
    val id: Any,
    val label: String,
    val subtitle: String,
    val current: Boolean,
)

/** Native tab controls. The Activity owns dismissal and session lifetimes. */
internal class TabSwitcherSheet(
    context: Context,
    entries: List<TabSwitcherEntry>,
    private val onSelect: (Any) -> Unit,
    private val onClose: (Any) -> Unit,
    private val onNewTab: () -> Unit,
) : AlertDialog(context, android.R.style.Theme_Material_Dialog_Alert) {
    private var entries = entries.toList()
    private val stableIds = mutableMapOf<Any, Long>()
    private var nextId = 0L
    private val adapter = TabAdapter()
    private lateinit var root: LinearLayout
    private lateinit var header: LinearLayout
    private lateinit var count: TextView
    private lateinit var list: ListView
    private lateinit var empty: TextView
    private lateinit var footer: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(8), dp(12), dp(12))
            background = shape(CHROME, 24)
        }
        header = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(8), dp(4), 0, dp(12))
        }
        val heading = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        heading.addView(text("Tabs", 22f, TEXT).apply {
            setTypeface(typeface, Typeface.BOLD)
            accessibilityHeading()
        })
        count = text("", 13f, MUTED)
        heading.addView(count)
        header.addView(heading, LinearLayout.LayoutParams(0, WRAP, 1f))
        header.addView(action("Done", 14f) { dismiss() })
        root.addView(header, LinearLayout.LayoutParams(MATCH, WRAP))

        list = ListView(context).apply {
            divider = ColorDrawable(Color.TRANSPARENT)
            dividerHeight = dp(8)
            selector = ColorDrawable(Color.TRANSPARENT)
            cacheColorHint = Color.TRANSPARENT
            isVerticalScrollBarEnabled = true
            overScrollMode = View.OVER_SCROLL_IF_CONTENT_SCROLLS
            itemsCanFocus = true
            this.adapter = this@TabSwitcherSheet.adapter
        }
        root.addView(list, LinearLayout.LayoutParams(MATCH, 0, 1f))
        empty = text("No tabs open", 16f, MUTED).apply {
            gravity = Gravity.CENTER
            minimumHeight = dp(80)
        }
        root.addView(empty, LinearLayout.LayoutParams(MATCH, 0, 1f))

        footer = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(12), 0, 0)
        }
        footer.addView(action("+ New tab", 16f, filled = true, onClick = onNewTab).apply {
            contentDescription = "New tab"
        }, LinearLayout.LayoutParams(MATCH, WRAP))
        root.addView(footer, LinearLayout.LayoutParams(MATCH, WRAP))
        setContentView(root)
        setCanceledOnTouchOutside(true)
        root.setOnApplyWindowInsetsListener { view, insets ->
            view.post { if (isShowing) resize() }
            insets
        }
        updateInventory()
    }

    override fun onStart() {
        super.onStart()
        window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setGravity(Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL)
            addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
            attributes = attributes.apply { dimAmount = 0.5f }
        }
        resize()
        list.post { list.setSelection(entries.indexOfFirst { it.current }.coerceAtLeast(0)) }
    }

    /** Rebind stable identities without jumping back to the first tab. */
    fun refresh(updated: List<TabSwitcherEntry>) {
        val position = if (::list.isInitialized) list.firstVisiblePosition else 0
        val anchor = entries.getOrNull(position)?.id
        val top = if (::list.isInitialized) list.getChildAt(0)?.top ?: 0 else 0
        entries = updated.toList()
        if (!::root.isInitialized) return
        updateInventory()
        adapter.notifyDataSetChanged()
        resize()
        val restored = entries.indexOfFirst { it.id == anchor }.takeIf { it >= 0 }
            ?: position.coerceAtMost((entries.size - 1).coerceAtLeast(0))
        list.post { list.setSelectionFromTop(restored, top) }
    }

    /** Call after Activity configuration changes; no Activity recreation is needed. */
    fun resize() {
        val dialogWindow = window ?: return
        if (!::root.isInitialized) return
        val (availableWidth, availableHeight) = safeSize()
        val margin = dp(8)
        val width = (availableWidth - margin * 2).coerceAtLeast(1).coerceAtMost(dp(560))
        val innerWidth = (width - root.paddingLeft - root.paddingRight).coerceAtLeast(1)
        val chrome = measureHeight(header, innerWidth) + measureHeight(footer, innerWidth) +
            root.paddingTop + root.paddingBottom
        // Large text can make the current row taller than its neighbours.
        // Fit that complete row when the available display height allows it.
        val currentPosition = entries.indexOfFirst { it.current }.coerceAtLeast(0)
        val minimumRow = if (entries.isEmpty()) dp(80) else
            measureHeight(adapter.getView(currentPosition, null, list), innerWidth)
        val limit = (availableHeight * 0.86f).toInt()
            .coerceAtLeast(chrome + minimumRow)
            .coerceAtMost((availableHeight - margin * 2).coerceAtLeast(1))
        val rows = if (entries.isEmpty()) dp(80) else (0 until minOf(entries.size, 6)).sumOf {
            measureHeight(adapter.getView(it, null, list), innerWidth) + if (it > 0) list.dividerHeight else 0
        }
        val height = (chrome + rows).coerceAtMost(limit)
        val params = dialogWindow.attributes
        if (params.width != width || params.height != height || params.y != margin) {
            params.width = width
            params.height = height
            params.y = margin
            dialogWindow.attributes = params
        }
    }

    private fun updateInventory() {
        val present = entries.mapTo(mutableSetOf()) { it.id }
        stableIds.keys.retainAll(present)
        for (entry in entries) stableIds.getOrPut(entry.id) { nextId++ }
        count.text = if (entries.size == 1) "1 open tab" else "${entries.size} open tabs"
        list.visibility = if (entries.isEmpty()) View.GONE else View.VISIBLE
        empty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
    }

    private inner class TabAdapter : BaseAdapter() {
        override fun getCount() = entries.size
        override fun getItem(position: Int) = entries[position]
        override fun hasStableIds() = true
        override fun getItemId(position: Int) = stableIds.getOrPut(entries[position].id) { nextId++ }
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View =
            (convertView as? TabRow ?: TabRow()).apply { bind(entries[position], position) }
    }

    private inner class TabRow : LinearLayout(context) {
        private val select = LinearLayout(context).apply {
            orientation = VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = dp(88)
            setPadding(dp(16), dp(12), dp(8), dp(12))
            background = ripple(shape(Color.TRANSPARENT, 12))
            buttonSemantics()
        }
        private val title = text("", 16f, TEXT).apply {
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
            setTypeface(typeface, Typeface.BOLD)
        }
        private val subtitle = text("", 13f, MUTED).apply {
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
            setPadding(0, dp(4), 0, 0)
        }
        private val current = text("Current", 12f, ACCENT).apply { setPadding(0, dp(6), 0, 0) }
        private val close = action("×", 26f) {}.apply {
            // Keep this icon inside its touch target at large text settings.
            setTextSize(android.util.TypedValue.COMPLEX_UNIT_DIP, 26f)
        }

        init {
            orientation = HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, dp(4), 0)
            select.addView(title)
            select.addView(subtitle)
            select.addView(current)
            addView(select, LayoutParams(0, WRAP, 1f))
            close.setPadding(0, 0, 0, 0)
            addView(close, LayoutParams(dp(48), dp(48)))
            // The combined selection target speaks these labels once.
            listOf(title, subtitle, current).forEach {
                it.importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
            }
        }

        fun bind(entry: TabSwitcherEntry, position: Int) {
            title.text = entry.label
            subtitle.text = entry.subtitle
            subtitle.visibility = if (entry.subtitle.isBlank()) GONE else VISIBLE
            current.visibility = if (entry.current) VISIBLE else GONE
            select.isSelected = entry.current
            background = shape(CARD, 12, if (entry.current) ACCENT else BORDER)
            val context = listOf(entry.label, entry.subtitle).filter { it.isNotBlank() }.joinToString(", ")
            select.contentDescription = if (entry.current) "$context, Current tab" else "Switch to $context"
            select.setOnClickListener { onSelect(entry.id) }
            close.contentDescription = "Close $context, tab ${position + 1} of ${entries.size}"
            close.setOnClickListener { onClose(entry.id) }
        }
    }

    private fun action(label: String, size: Float, filled: Boolean = false, onClick: () -> Unit): TextView =
        text(label, size, if (filled) CHROME else ACCENT).apply {
            gravity = Gravity.CENTER
            minimumWidth = dp(48)
            minimumHeight = dp(48)
            setPadding(dp(16), dp(10), dp(16), dp(10))
            background = ripple(shape(if (filled) ACCENT else Color.TRANSPARENT, 12))
            buttonSemantics()
            setOnClickListener { onClick() }
        }

    private fun View.buttonSemantics() {
        isFocusable = true
        isClickable = true
        accessibilityDelegate = object : View.AccessibilityDelegate() {
            override fun onInitializeAccessibilityNodeInfo(host: View, info: AccessibilityNodeInfo) {
                super.onInitializeAccessibilityNodeInfo(host, info)
                info.className = android.widget.Button::class.java.name
                info.isSelected = host.isSelected
            }
        }
    }

    private fun View.accessibilityHeading() {
        if (Build.VERSION.SDK_INT >= 28) isAccessibilityHeading = true
    }

    private fun text(value: String, size: Float, color: Int) = TextView(context).apply {
        text = value
        textSize = size
        setTextColor(color)
    }

    private fun shape(color: Int, radius: Int, border: Int? = null) = GradientDrawable().apply {
        setColor(color)
        cornerRadius = dp(radius).toFloat()
        if (border != null) setStroke(dp(1), border)
    }

    private fun ripple(background: GradientDrawable) = RippleDrawable(
        ColorStateList.valueOf(0x28b7a5ff), background, shape(Color.WHITE, 12),
    )

    private fun measureHeight(view: View, width: Int): Int {
        view.measure(View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED))
        return view.measuredHeight
    }

    private fun safeSize(): Pair<Int, Int> {
        if (Build.VERSION.SDK_INT >= 30) {
            val metrics = context.getSystemService(WindowManager::class.java).currentWindowMetrics
            val insets = metrics.windowInsets.getInsetsIgnoringVisibility(
                WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout(),
            )
            return (metrics.bounds.width() - insets.left - insets.right) to
                (metrics.bounds.height() - insets.top - insets.bottom)
        }
        val metrics = context.resources.displayMetrics
        return metrics.widthPixels to metrics.heightPixels
    }

    private fun dp(value: Int) = (value * context.resources.displayMetrics.density + 0.5f).toInt()

    private companion object {
        const val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
        const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT
        const val CHROME = 0xff0b0e14.toInt()
        const val CARD = 0xff151c28.toInt()
        const val BORDER = 0xff2a3445.toInt()
        const val TEXT = 0xfff3f0ff.toInt()
        const val MUTED = 0xffa9b3c7.toInt()
        const val ACCENT = 0xffb7a5ff.toInt()
    }
}
