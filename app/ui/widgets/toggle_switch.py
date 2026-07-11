"""
Widget: toggle switch animado (on/off).
"""

from PySide6.QtWidgets import QAbstractButton
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, Property, QRectF
from PySide6.QtGui import QPainter, QColor


class ToggleSwitch(QAbstractButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedSize(46, 24)
        self._offset = 2.0
        self._anim = QPropertyAnimation(self, b"offset", self)
        self._anim.setDuration(140)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

    def get_offset(self):
        return self._offset

    def set_offset(self, value):
        self._offset = value
        self.update()

    offset = Property(float, get_offset, set_offset)

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        self._anim.stop()
        if self.isChecked():
            self._anim.setStartValue(self._offset)
            self._anim.setEndValue(22.0)
        else:
            self._anim.setStartValue(self._offset)
            self._anim.setEndValue(2.0)
        self._anim.start()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        track_color = QColor("#3B82F6") if self.isChecked() else QColor("#29313D")
        p.setBrush(track_color)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, self.width(), self.height(), 12, 12)
        p.setBrush(QColor("#F1F3F5"))
        p.drawEllipse(QRectF(self._offset, 2, 20, 20))
        p.end()

    def setChecked(self, checked: bool):
        super().setChecked(checked)
        self._offset = 22.0 if checked else 2.0
        self.update()
