#!/usr/bin/python
"""
This software is OSI Certified Open Source Software.
OSI Certified is a certification mark of the Open Source Initiative.

Copyright (c) 2006, Enthought, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
 * Neither the name of Enthought, Inc. nor the names of its contributors may
   be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The software contained in the traits/protocols/ directory is
the pyprotocols project (http://peak.telecommunity.com/PyProtocols.html),
it is originaly licensed under the terms of the Python Software
Foundation License, which is compatible with the above terms.
"""

from PySide import QtGui, QtCore

from RangeSlider import RangeSlider


class BoundsEditor(QtGui.QWidget):
    """
    Custom widget consisting of a QLineEdit, a custom double slider and another QLineEdit.
    """

    boundsChanged = QtCore.Signal()

    def __init__(self, name, min, max, low, high, is_float=True):
        super(BoundsEditor, self).__init__()
        self.name = name
        self.min = min
        self.max = max
        self.low = low
        self.high = high
        self.is_float = is_float

        self.format = "%d"
        if self.is_float:
            self.format = "%2.2f"

        panel = QtGui.QHBoxLayout(self)
        panel.setContentsMargins(0, 0, 0, 0)

        self._label_name = QtGui.QLabel(self.name)
        panel.addWidget(self._label_name)

        self._label_lo = QtGui.QLineEdit(self.format % self.low)
        self._label_lo.setMinimumSize(45, 0)
        self._label_lo.editingFinished.connect(self.update_low_on_enter)
        self._label_lo.returnPressed.connect(self.update_low_on_enter)
        panel.addWidget(self._label_lo)

        # The default size is a bit too big and probably doesn't need to grow.
        sh = self._label_lo.sizeHint()
        sh.setWidth(sh.width() / 2)
        self._label_lo.setMaximumSize(sh)

        self.slider = slider = RangeSlider(QtCore.Qt.Horizontal)
        slider.setMinimum(0)
        slider.setMaximum(10000)
        slider.setPageStep(1000)
        slider.setSingleStep(100)
        slider.setLow(self._convert_to_slider(self.low))
        slider.setHigh(self._convert_to_slider(self.high))

        slider.sliderMoved.connect(self.update_object_on_scroll)
        panel.addWidget(slider)

        self._label_hi = QtGui.QLineEdit(self.format % self.high)
        self._label_hi.setMinimumSize(45, 0)
        self._label_hi.editingFinished.connect(self.update_high_on_enter)
        self._label_hi.returnPressed.connect(self.update_high_on_enter)
        panel.addWidget(self._label_hi)

        # The default size is a bit too big and probably doesn't need to grow.
        sh = self._label_hi.sizeHint()
        sh.setWidth(sh.width() / 2)
        self._label_hi.setMaximumSize(sh)

    def update_low_on_enter(self):
        try:
            try:
                low = eval(unicode(self._label_lo.text()).strip())
            except Exception as exc:
                low = self.low
                self._label_lo.setText(self.format % self.low)
                print exc

            if not self.is_float:
                low = int(low)

            if low > self.high:
                low = self.high - self._step_size()
                self._label_lo.setText(self.format % low)

            self.slider.setLow(self._convert_to_slider(low))
            self.low = low

            self.boundsChanged.emit()
        except:
            pass

    def update_high_on_enter(self):
        try:
            try:
                high = eval(unicode(self._label_hi.text()).strip())
            except:
                high = self.high
                self._label_hi.setText(self.format % self.high)

            if not self.is_float:
                high = int(high)

            if high < self.low:
                high = self.low + self._step_size()
                self._label_hi.setText(self.format % high)

            self.slider.setHigh(self._convert_to_slider(high))
            self.high = high

            self.boundsChanged.emit()
        except:
            pass

    def update_object_on_scroll(self, pos):
        low = self._convert_from_slider(self.slider.low())
        high = self._convert_from_slider(self.slider.high())

        if self.is_float:
            self.low = low
            self.high = high
        else:
            self.low = int(low)
            self.high = int(high)

            # update the sliders to the int values or the sliders
            # will jiggle
            self.slider.setLow(self._convert_to_slider(low))
            self.slider.setHigh(self._convert_to_slider(high))

        self._label_hi.setText(self.format % self.high)
        self._label_lo.setText(self.format % self.low)

    def update_editor(self):
        return

    def _check_max_and_min(self):
        # check if max & min have been defined:
        if self.max is None:
            self.max = self.high
        if self.min is None:
            self.min = self.low

    def _step_size(self):
        slider_delta = self.slider.maximum() - self.slider.minimum()
        range_delta = self.max - self.min
        return float(range_delta) / slider_delta

    def _convert_from_slider(self, slider_val):
        self._check_max_and_min()
        return self.min + slider_val * self._step_size()

    def _convert_to_slider(self, value):
        self._check_max_and_min()
        return self.slider.minimum() + (value - self.min) / self._step_size()

    def _low_changed(self, low):
        if self._label_lo is not None:
            self._label_lo.setText(self.format % low)
        self.slider.setLow(self._convert_to_slider(low))

    def _high_changed(self, high):
        if self._label_hi is not None:
            self._label_hi.setText(self.format % high)
        self.slider.setHigh(self._convert_to_slider(self.high))

    def mouseReleaseEvent(self, event):
        event.accept()
        self.boundsChanged.emit()
