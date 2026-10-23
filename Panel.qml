import QtQuick
import Quickshell
import qs.Commons
import qs.Commons as Commons
import qs.Ui as Ui

Ui.Panel {
  id: root
  moduleName: "io.github.zimagen.omamori"
  ipcTarget: "io.github.zimagen.omamori"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root
  readonly property bool daemonUp: hostWidget ? hostWidget.daemonUp : false
  readonly property var status: hostWidget ? hostWidget.status : ({daemon: false})
  readonly property var pending: hostWidget ? hostWidget.pending : []
  readonly property color contentForeground: bar ? bar.foreground : Commons.Color.foreground
  readonly property string contentFontFamily: bar ? bar.fontFamily : Style.font.family

  function switchPanel(direction) {
    if (bar && typeof bar.switchPanelFrom === "function")
      return bar.switchPanelFrom(barIdentity, direction)
    return false
  }

  Ui.KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    centerOnBar: true
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(Style.space(360))
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight)

    content: FocusScope {
      implicitHeight: details.implicitHeight
      Keys.onEscapePressed: root.close()

      Flickable {
        anchors.fill: parent
        contentHeight: details.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        Column {
          id: details
          width: parent.width
          spacing: Style.spacing.sm

          Repeater {
            model: [
              "Omamori",
              "Daemon: " + (root.daemonUp ? "running" : "down"),
              "Watch: " + (root.daemonUp ? (root.status.watch_name || "not paired") : "unavailable"),
              "Host: " + (root.daemonUp ? (root.status.host_name || "unknown") : "unavailable"),
              "Adapter powered: " + (root.daemonUp ? (root.status.adapter_powered ? "yes" : "no") : "unavailable"),
              "Pending requests: " + root.pending.length
            ]
            Text {
              required property string modelData
              width: details.width
              text: modelData
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              color: root.contentForeground
              font.family: root.contentFontFamily
              font.pixelSize: Style.font.body
            }
          }

          Repeater {
            model: root.pending
            Text {
              required property var modelData
              width: details.width
              text: String(modelData.kind) + ": " + String(modelData.title)
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              color: root.contentForeground
              font.family: root.contentFontFamily
              font.pixelSize: Style.font.body
            }
          }

          Ui.Button {
            text: "Pair watch"
            focusable: true
            enabled: root.daemonUp && root.bar !== null
            onClicked: if (root.hostWidget) root.hostWidget.pairWatch()
          }

          Ui.Button {
            text: "Unpair"
            focusable: true
            enabled: root.daemonUp && root.status.paired === true && root.bar !== null
            onClicked: if (root.hostWidget) root.hostWidget.unpairWatch()
          }
        }
      }
    }
  }
}
