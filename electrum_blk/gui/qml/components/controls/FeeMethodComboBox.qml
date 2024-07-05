import QtQuick
import QtQuick.Controls

import org.electrum 1.0

ElComboBox {
    id: control

    required property QtObject feeslider

    textRole: 'text'
    valueRole: 'value'

    model: [
        { text: qsTr('Static'), value: 0 }
    ]
    onCurrentValueChanged: {
        if (activeFocus)
            feeslider.method = currentValue
    }
    Component.onCompleted: {
        currentIndex = indexOfValue(0)
        feeslider.method = 0
    }
}
