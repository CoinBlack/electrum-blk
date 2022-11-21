from typing import Optional

import qrcode

from PyQt5.QtGui import QColor, QPen
import PyQt5.QtGui as QtGui
from PyQt5.QtCore import Qt, QRect
from PyQt5.QtWidgets import (
    QApplication, QVBoxLayout, QTextEdit, QHBoxLayout, QPushButton, QWidget,
    QFileDialog,
)

from electrum_blk.i18n import _
from electrum_blk.simple_config import SimpleConfig

from .util import WindowModalDialog, WWLabel, getSaveFileName


class QRCodeWidget(QWidget):

    def __init__(self, data=None, *, manual_size: bool = False):
        QWidget.__init__(self)
        self.data = None
        self.qr = None
        self._framesize = None  # type: Optional[int]
        self._manual_size = manual_size
        self.setData(data)

    def setData(self, data):
        if self.data != data:
            self.data = data
        if self.data:
            self.qr = qrcode.QRCode(
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=0,
            )
            self.qr.add_data(self.data)
            if not self._manual_size:
                k = len(self.qr.get_matrix())
                self.setMinimumSize(k * 5, k * 5)
        else:
            self.qr = None

        self.update()


    def paintEvent(self, e):
        if not self.data:
            return

        black = QColor(0, 0, 0, 255)
        white = QColor(255, 255, 255, 255)
        black_pen = QPen(black)
        black_pen.setJoinStyle(Qt.MiterJoin)

        if not self.qr:
            qp = QtGui.QPainter()
            qp.begin(self)
            qp.setBrush(white)
            qp.setPen(white)
            r = qp.viewport()
            qp.drawRect(0, 0, r.width(), r.height())
            qp.end()
            return

        matrix = self.qr.get_matrix()
        k = len(matrix)
        qp = QtGui.QPainter()
        qp.begin(self)
        r = qp.viewport()
        framesize = min(r.width(), r.height())
        self._framesize = framesize
        boxsize = int(framesize/(k + 2))
        if boxsize < 2:
            qp.drawText(0, 20, 'Cannot draw QR code:')
            qp.drawText(0, 40, 'Boxsize too small')
            qp.end()
            return
        size = k*boxsize
        left = (framesize - size)/2
        top = (framesize - size)/2
        # Draw white background with margin
        qp.setBrush(white)
        qp.setPen(white)
        qp.drawRect(0, 0, framesize, framesize)
        # Draw qr code
        qp.setBrush(black)
        qp.setPen(black_pen)
        for r in range(k):
            for c in range(k):
                if matrix[r][c]:
                    qp.drawRect(int(left+c*boxsize), int(top+r*boxsize),
                                boxsize - 1, boxsize - 1)
        qp.end()

    def grab(self) -> QtGui.QPixmap:
        """Overrides QWidget.grab to only include the QR code itself,
        excluding horizontal/vertical stretch.
        """
        fsize = self._framesize
        if fsize is None:
            fsize = -1
        rect = QRect(0, 0, fsize, fsize)
        return QWidget.grab(self, rect)


class QRDialog(WindowModalDialog):

    def __init__(
            self,
            *,
            data,
            parent=None,
            title="",
            show_text=False,
            help_text=None,
            show_copy_text_btn=False,
            config: SimpleConfig,
    ):
        WindowModalDialog.__init__(self, parent, title)
        self.config = config

        vbox = QVBoxLayout()

        qrw = QRCodeWidget(data, manual_size=True)
        qrw.setMinimumSize(250, 250)
        vbox.addWidget(qrw, 1)

        help_text = data if show_text else help_text
        if help_text:
            text_label = WWLabel()
            text_label.setText(help_text)
            vbox.addWidget(text_label)
        hbox = QHBoxLayout()
        hbox.addStretch(1)

        def print_qr():
            filename = getSaveFileName(
                parent=self,
                title=_("Select where to save file"),
                filename="qrcode.png",
                config=self.config,
            )
            if not filename:
                return
            p = qrw.grab()
            p.save(filename, 'png')
            self.show_message(_("QR code saved to file") + " " + filename)

        def copy_image_to_clipboard():
            p = qrw.grab()
            QApplication.clipboard().setPixmap(p)
            self.show_message(_("QR code copied to clipboard"))

        def copy_text_to_clipboard():
            QApplication.clipboard().setText(data)
            self.show_message(_("Text copied to clipboard"))

        b = QPushButton(_("Copy Image"))
        hbox.addWidget(b)
        b.clicked.connect(copy_image_to_clipboard)

        if show_copy_text_btn:
            b = QPushButton(_("Copy Text"))
            hbox.addWidget(b)
            b.clicked.connect(copy_text_to_clipboard)

        b = QPushButton(_("Save"))
        hbox.addWidget(b)
        b.clicked.connect(print_qr)

        b = QPushButton(_("Close"))
        hbox.addWidget(b)
        b.clicked.connect(self.accept)
        b.setDefault(True)

        vbox.addLayout(hbox)
        self.setLayout(vbox)

        # note: the word-wrap on the text_label is causing layout sizing issues.
        #       see https://stackoverflow.com/a/25661985 and https://bugreports.qt.io/browse/QTBUG-37673
        #       workaround:
        self.setMinimumSize(self.sizeHint())
