package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.ListenerHandle
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.findBurpFrame
import java.awt.Component
import java.awt.Cursor
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.event.MouseMotionAdapter
import javax.swing.*
import javax.swing.JOptionPane.ERROR_MESSAGE
import javax.swing.JOptionPane.YES_NO_OPTION
import javax.swing.JOptionPane.YES_OPTION

/**
 * Panel that lets the user configure additional IP addresses to bind the MCP server on.
 * Includes a "Detect LAN IPs" button that enumerates actual network interfaces.
 */
class BindHostsPanel(private val config: McpConfig) : JPanel() {

    private var listenerHandle: ListenerHandle? = null
    private val listModel = DefaultListModel<String>()
    // Hold a strong reference so the WeakReference in McpConfig doesn't get GC'd
    private val refreshListener: () -> Unit = { SwingUtilities.invokeLater { refreshList() } }
    // Track last selection so Remove works even after focus leaves the list
    private var lastSelectedIndex: Int = -1

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        updateColors()
        alignmentX = LEFT_ALIGNMENT
        buildPanel()
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
    }

    private fun updateColors() {
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        )
    }

    private fun buildPanel() {
        add(Design.createSectionLabel("Additional Bind Addresses"))
        add(Box.createVerticalStrut(Design.Spacing.SM))

        val descLabel = JLabel("Bind the MCP server on extra IP addresses in addition to the primary host.").apply {
            alignmentX = LEFT_ALIGNMENT
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.onSurfaceVariant
            border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.SM, 0)
        }
        val noteLabel = JLabel("Restart the server after making changes.").apply {
            alignmentX = LEFT_ALIGNMENT
            font = Design.Typography.labelMedium
            foreground = Design.Colors.warning
            border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.MD, 0)
        }
        add(descLabel)
        add(noteLabel)

        val hostList = createHostList()
        refreshList()

        listenerHandle = config.addBindHostsChangeListener(refreshListener)

        val scrollPane = createScrollPane(hostList)
        val tableContainer = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.MD, 0)
            add(scrollPane)
        }
        add(tableContainer)

        val buttonsPanel = createButtonsPanel(hostList)
        add(buttonsPanel)
    }

    private fun createHostList(): JList<String> {
        return object : JList<String>(listModel) {
            private var rolloverIndex = -1

            init {
                selectionMode = ListSelectionModel.SINGLE_SELECTION
                visibleRowCount = 4
                font = Design.Typography.bodyMedium
                background = Design.Colors.surface
                foreground = Design.Colors.onSurface
                border = BorderFactory.createEmptyBorder(Design.Spacing.SM, Design.Spacing.MD, Design.Spacing.SM, Design.Spacing.MD)
                cellRenderer = buildCellRenderer()
                isFocusable = true

                addListSelectionListener {
                    if (!it.valueIsAdjusting && selectedIndex >= 0) {
                        lastSelectedIndex = selectedIndex
                    }
                }

                addMouseMotionListener(object : MouseMotionAdapter() {
                    override fun mouseMoved(e: MouseEvent) {
                        val idx = locationToIndex(e.point)
                        val newRollover = if (idx >= 0 && idx < model.size && getCellBounds(idx, idx)?.contains(e.point) == true) {
                            cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                            idx
                        } else {
                            cursor = Cursor.getDefaultCursor()
                            -1
                        }
                        if (rolloverIndex != newRollover) { rolloverIndex = newRollover; repaint() }
                    }
                })
                addMouseListener(object : MouseAdapter() {
                    override fun mouseExited(e: MouseEvent) {
                        if (rolloverIndex != -1) { rolloverIndex = -1; cursor = Cursor.getDefaultCursor(); repaint() }
                    }
                })
                addKeyListener(object : KeyAdapter() {
                    override fun keyPressed(e: KeyEvent) {
                        if ((e.keyCode == KeyEvent.VK_DELETE || e.keyCode == KeyEvent.VK_BACK_SPACE) && selectedIndex >= 0) {
                            val idx = selectedIndex
                            if (idx >= 0 && idx < listModel.size()) {
                                config.removeBindHost(listModel.getElementAt(idx))
                            }
                            e.consume()
                        }
                    }
                })
            }

            private fun buildCellRenderer() = object : DefaultListCellRenderer() {
                override fun getListCellRendererComponent(list: JList<*>, value: Any?, index: Int, isSelected: Boolean, cellHasFocus: Boolean): Component {
                    super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
                    border = BorderFactory.createEmptyBorder(Design.Spacing.SM, Design.Spacing.MD, Design.Spacing.SM, Design.Spacing.MD)
                    val isRollover = index == rolloverIndex && !isSelected
                    when {
                        isSelected  -> { background = Design.Colors.listSelectionBackground; foreground = Design.Colors.listSelectionForeground }
                        isRollover  -> { background = Design.Colors.listHoverBackground;     foreground = Design.Colors.onSurface }
                        else        -> {
                            // Use surface colour for all rows to avoid white flash in dark themes.
                            // Odd rows get a subtle tint via outlineVariant blended with surface.
                            background = if (index % 2 == 0) Design.Colors.surface
                                         else java.awt.Color(
                                             (Design.Colors.surface.red   * 0.92f + Design.Colors.outlineVariant.red   * 0.08f).toInt(),
                                             (Design.Colors.surface.green * 0.92f + Design.Colors.outlineVariant.green * 0.08f).toInt(),
                                             (Design.Colors.surface.blue  * 0.92f + Design.Colors.outlineVariant.blue  * 0.08f).toInt()
                                         )
                            foreground = Design.Colors.onSurface
                        }
                    }
                    return this
                }
            }
        }
    }

    private fun createScrollPane(list: JList<String>): JScrollPane {
        val scaleFactor = Design.Spacing.MD / 16f
        val h = (150 * scaleFactor).toInt().coerceAtLeast(100)
        val w = (400 * scaleFactor).toInt().coerceAtLeast(250)
        return JScrollPane(list).apply {
            maximumSize  = Dimension(Int.MAX_VALUE, h)
            preferredSize = Dimension(w, h)
            minimumSize  = Dimension((w * 0.625f).toInt(), (h * 0.68f).toInt())
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Design.Colors.listBorder, 1),
                BorderFactory.createEmptyBorder(1, 1, 1, 1)
            )
            background = Design.Colors.surface
            viewport.background = Design.Colors.surface
            verticalScrollBarPolicy   = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
        }
    }

    private fun createButtonsPanel(list: JList<String>): JPanel {
        val panel = JPanel(FlowLayout(FlowLayout.LEFT, Design.Spacing.SM, Design.Spacing.SM)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            border = BorderFactory.createEmptyBorder(Design.Spacing.SM, 0, 0, 0)
        }

        val addButton = Design.createFilledButton("Add IP").apply {
            addActionListener {
                val input = JOptionPane.showInputDialog(
                    findBurpFrame(),
                    "Enter an IPv4 address to bind on:\nExample: 192.168.1.100",
                    "Add Bind Address",
                    JOptionPane.PLAIN_MESSAGE
                )
                if (!input.isNullOrBlank()) {
                    val trimmed = input.trim()
                    if (isValidIp(trimmed)) {
                        if (!config.addBindHost(trimmed)) {
                            JOptionPane.showMessageDialog(
                                findBurpFrame(),
                                "Address \"$trimmed\" is already in the bind list.",
                                "Duplicate Address",
                                JOptionPane.INFORMATION_MESSAGE
                            )
                        }
                    } else {
                        JOptionPane.showMessageDialog(
                            findBurpFrame(),
                            "\"$trimmed\" is not a valid IPv4 or IPv6 address.",
                            "Invalid Address",
                            ERROR_MESSAGE
                        )
                    }
                }
            }
        }

        val detectButton = Design.createOutlinedButton("Detect LAN IPs").apply {
            toolTipText = "Scan network interfaces and add your local IPs"
            addActionListener {
                val detected = config.detectLanIps()
                if (detected.isEmpty()) {
                    JOptionPane.showMessageDialog(
                        findBurpFrame(),
                        "No LAN IPv4 addresses detected on this machine.",
                        "No LAN IPs Found",
                        JOptionPane.INFORMATION_MESSAGE
                    )
                    return@addActionListener
                }

                // Build a checkbox picker showing all detected IPs
                val checkBoxes = detected.map { ip ->
                    JCheckBox(ip).apply { isSelected = true }
                }
                val pickerPanel = JPanel().apply {
                    layout = BoxLayout(this, BoxLayout.Y_AXIS)
                    add(JLabel("Select IPs to add as additional bind addresses:").apply {
                        font = Design.Typography.bodyLarge
                        border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.SM, 0)
                    })
                    checkBoxes.forEach { add(it) }
                }

                val result = JOptionPane.showConfirmDialog(
                    findBurpFrame(), pickerPanel, "Detected LAN IPs", YES_NO_OPTION, JOptionPane.PLAIN_MESSAGE
                )
                if (result == YES_OPTION) {
                    val selected = checkBoxes.filter { it.isSelected }.map { it.text }
                    var added = 0
                    selected.forEach { ip -> if (config.addBindHost(ip)) added++ }
                    if (added > 0) {
                        JOptionPane.showMessageDialog(
                            findBurpFrame(),
                            "Added $added IP address${if (added > 1) "es" else ""}. Restart the server to apply.",
                            "Done",
                            JOptionPane.INFORMATION_MESSAGE
                        )
                    }
                }
            }
        }

        val removeButton = Design.createOutlinedButton("Remove").apply {
            addActionListener {
                // Use lastSelectedIndex as fallback when list has lost focus
                val idx = if (list.selectedIndex >= 0) list.selectedIndex else lastSelectedIndex
                if (idx >= 0 && idx < listModel.size()) {
                    lastSelectedIndex = -1
                    config.removeBindHost(listModel.getElementAt(idx))
                }
            }
        }

        val clearButton = Design.createOutlinedButton("Clear All").apply {
            addActionListener {
                val res = JOptionPane.showConfirmDialog(
                    findBurpFrame(), "Remove all additional bind addresses?", "Confirm", YES_NO_OPTION
                )
                if (res == YES_OPTION) config.clearAdditionalBindHosts()
            }
        }

        panel.add(addButton)
        panel.add(detectButton)
        panel.add(removeButton)
        panel.add(clearButton)
        return panel
    }

    private fun refreshList() {
        listModel.clear()
        config.getAdditionalBindHostsList().forEach { listModel.addElement(it) }
    }

    private fun isValidIp(ip: String): Boolean {
        // Accept dotted-decimal IPv4 or colon-hex IPv6
        return try {
            java.net.InetAddress.getByName(ip)
            // ensure we didn't just resolve a hostname
            ip.matches(Regex("^[\\d.:a-fA-F]+$"))
        } catch (_: Exception) { false }
    }

    fun cleanup() {
        listenerHandle?.remove()
        listenerHandle = null
    }
}
