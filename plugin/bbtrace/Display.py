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
        self.drawing = None

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

        qp.setPen(QtCore.Qt.NoPen)
        # qp.setBrush(QtGui.QBrush(QtGui.QColor(255, 100, 100)))

        if self.drawing:
            lines = self.drawing(0, size.width() - 2)
            for y, line in lines.iteritems():
                for box in line:
                    if box['color']:
                        r, g, b = box['color']
                        qp.setBrush(QtGui.QBrush(QtGui.QColor(r, g, b)))
                    else:
                        qp.setBrush(QtGui.QBrush(QtGui.QColor(0, 0, 0)))
                    w = box['x1'] - box['x0'] + 1
                    qp.drawRect(1+box['x0'], 1+(y*11), w, 10)


    def setDrawing(self, drawing):
        self.drawing = drawing
        self.update()


class Display(idaapi.PluginForm):
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """

        # Initalize Data
        exename = idc.GetInputFile()
        path = os.path.dirname(idc.GetInputFilePath())

        infoname = "bbtrace.%s.log.info" % (exename,)
        infoname = os.path.join(path, infoname)

        self.infoparser = InfoParser(infoname)
        self.infoparser.load()

        self.tracelog = TraceLog(infoname)
        self.callstack = CallStackBuilder(self.infoparser, self.tracelog)
        self.callstack.parse()

        self.canvas = None

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def CreateToolbar(self):
        toolbar = QtWidgets.QToolBar()

        btn_prev = QtWidgets.QPushButton(
            QtGui.QIcon(asset_path('black-left-pointing-double-triangle-with-vertical-bar_23ee.png')),
            ""
        )
        toolbar.addWidget(btn_prev)

        label = QtWidgets.QLabel("Hello from <font color=blue>IDAPython</font>")
        label.setFont(MonospaceFont())

        toolbar.addWidget(label)

        btn_next = QtWidgets.QPushButton(
            QtGui.QIcon(asset_path('black-right-pointing-double-triangle-with-vertical-bar_23ed.png')),
            ""
        )
        toolbar.addWidget(btn_next)

        btn_trace_color = QtWidgets.QPushButton(
            QtGui.QIcon(asset_path('herb_1f33f.png')),
            "Trace"
        )
        btn_trace_color.clicked.connect(self._btn_trace_color_clicked)

        toolbar.addWidget(btn_trace_color)

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

        self.canvas = Canvas()
        layout.addWidget(
            self.canvas
        )
        self.parent.setLayout(layout)

        self.canvas.setDrawing(self.callstack.draw)

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

    def _btn_trace_color_clicked(self):
        col = 0xccffcc

        for ea, basic_block in self.infoparser.basic_blocks.iteritems():
            while ea != idaapi.BADADDR:
                idc.set_color(ea, idc.CIC_ITEM, col)
                ea = idc.next_head(ea, basic_block['end'])
