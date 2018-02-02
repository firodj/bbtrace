import os
import idaapi
import idautils
import idc
from PyQt5 import QtCore, QtGui, QtWidgets
import sip
from InfoParser import InfoParser
from TraceLog import TraceLog
from CallStackBuilder import CallStackBuilder

def asset_path(path):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'assets', path)

def MonospaceFont():
    """
    Convenience alias for creating a monospace Qt font object.
    """
    font = QtGui.QFont("Monospace", 10)
    font.setStyleHint(QtGui.QFont.TypeWriter)
    return font

class Canvas(QtWidgets.QWidget):
    def __init__(self):
        super(Canvas, self).__init__()
        self.initUI()

    def initUI(self):

        self.text = "Punten"

        # self.setGeometry(300, 300, 280, 170)
        self.setWindowTitle('Drawing text')
        self.show()

    def paintEvent(self, event):

        qp = QtGui.QPainter()
        qp.begin(self)
        self.drawWidget(qp)
        qp.end()

    def drawWidget(self, qp):
        size = self.size()
        rect = QtCore.QRect(QtCore.QPoint(0, 0), size)

        qp.setPen(QtGui.QColor(168, 34, 3))
        qp.setFont(MonospaceFont())
        qp.drawText(rect, QtCore.Qt.AlignCenter, self.text)

        #metrics = qp.fontMetrics()
        #fw = metrics.width(self.text)

        pen = QtGui.QPen(QtGui.QColor(20, 20, 20), 1,
            QtCore.Qt.SolidLine)

        qp.setPen(pen)
        qp.setBrush(QtCore.Qt.NoBrush)
        qp.drawRect(0, 0, size.width()-1, size.height()-1)


class Display(idaapi.PluginForm):
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

        # Initalize Data
        exename = idc.GetInputFile()
        path = os.path.dirname(idc.GetInputFilePath())

        infoname = "bbtrace.%s.log.info" % (exename,)
        infoname = os.path.join(path, infoname)

        self.infoparser = InfoParser(infoname)
        self.tracelog = TraceLog(infoname)
        self.callstack = CallStackBuilder(self.infoparser, self.tracelog)

    def CreateToolbar(self):
        toolbar = QtWidgets.QToolBar()
        label = QtWidgets.QLabel("Hello from <font color=blue>IDAPython</font>")
        label.setFont(MonospaceFont())

        toolbar.addWidget(label)

        btn_clear_color = QtWidgets.QPushButton(
            QtGui.QIcon(asset_path('splashing-sweat-symbol_1f4a6.png')),
            "Clear"
        )
        btn_clear_color.clicked.connect(self._btn_clear_color_clicked)

        toolbar.addWidget(btn_clear_color)

        return toolbar

    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        layout.addWidget(
            self.CreateToolbar()
        )
        layout.addWidget(
            Canvas()
        )
        self.parent.setLayout(layout)

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        idaapi.msg("Close")

    def _btn_clear_color_clicked(self):
        ea = idc.NextHead(0)
        while ea != idaapi.BADADDR:
            idc.SetColor(ea, idc.CIC_ITEM, 0xFFFFFFFF)
            ea = idc.NextHead(ea)

