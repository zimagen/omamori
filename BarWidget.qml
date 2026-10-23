import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui as Ui

Ui.BarWidget {
  id: root
  moduleName: "io.github.zimagen.omamori"

  property var status: ({daemon: false})
  readonly property bool daemonUp: status.daemon !== false && typeof status.paired === "boolean"
  readonly property var pending: daemonUp && Array.isArray(status.pending) ? status.pending : []
  readonly property bool opened: panelLoader.item ? panelLoader.item.opened : false
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing : false

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  function refresh() {
    if (!statusProcess.running) statusProcess.running = true
  }

  function open() {
    refresh()
    if (panelLoader.item) panelLoader.item.open()
  }

  function close() {
    if (panelLoader.item) panelLoader.item.close()
  }

  function togglePanel() { opened ? close() : open() }

  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  function injectPanel() {
    if (!panelLoader.item) return
    panelLoader.item.bar = root.bar
    panelLoader.item.settings = root.settings
    panelLoader.item.anchorItem = button
    panelLoader.item.hostWidget = root
  }

  // Only these fixed commands may request privilege, inside the visible terminal.
  function pairWatch() {
    if (bar) bar.run("omarchy-launch-floating-terminal-with-presentation sudo omamori pair")
    broadcast("refresh")
  }

  function unpairWatch() {
    if (bar) bar.run("omarchy-launch-floating-terminal-with-presentation sudo omamori unpair")
    broadcast("refresh")
  }

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()
  onVisibleChanged: if (visible) refresh()
  Component.onCompleted: if (visible) refresh()

  Timer {
    interval: 5000
    repeat: true
    running: root.visible
    onTriggered: root.refresh()
  }

  Process {
    id: statusProcess
    command: ["omamori", "status", "--json"]
    stdout: StdioCollector {
      onStreamFinished: {
        try {
          var value = JSON.parse(text)
          root.status = value && typeof value === "object" ? value : {daemon: false}
        } catch (error) {
          root.status = {daemon: false}
        }
      }
    }
    onExited: function(exitCode, exitStatus) {
      if (exitCode !== 0 || exitStatus !== 0) root.status = {daemon: false}
    }
  }

  // A wedged IPC connection must not leave a stale healthy indicator indefinitely.
  Timer {
    interval: 4000
    running: statusProcess.running
    onTriggered: {
      root.status = {daemon: false}
      statusProcess.running = false
    }
  }

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  ShellIpc {
    target: "io.github.zimagen.omamori"
    function refresh(): void { root.broadcast("refresh") }
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.togglePanel() }
  }

  Ui.WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "󰖉" // Nerd Font md-watch
    dimmed: !root.daemonUp || !root.status.paired
    active: root.daemonUp && (root.status.advertising === true || root.pending.length > 0)
    tooltipText: "Omamori: " + (!root.daemonUp ? "daemon down" : root.status.paired ? "paired" : "not paired")
      + "\nWatch: " + (root.daemonUp && root.status.watch_name ? root.status.watch_name : "none")
      + "\nPending: " + root.pending.length
    onPressed: function(b) { if (b === Qt.LeftButton) root.togglePanel() }
  }
}
