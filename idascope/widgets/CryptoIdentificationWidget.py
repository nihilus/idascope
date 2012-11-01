#!/usr/bin/python
########################################################################
# Copyright (c) 2012
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  This file is part of IDAscope
#
#  IDAscope is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

from PySide import QtGui, QtCore
from PySide.QtGui import QIcon

from NumberQTableWidgetItem import NumberQTableWidgetItem
from BoundsEditor import BoundsEditor


class CryptoIdentificationWidget(QtGui.QMainWindow):

    def __init__(self, parent):
        QtGui.QMainWindow.__init__(self)
        print "[|] loading CryptoIdentificationWidget"
        # enable access to shared IDAscope modules
        self.parent = parent
        self.name = "Crypto Identification"
        self.icon = QIcon(self.parent.config.icon_file_path + "crypto.png")
        # This widget relies on the crypto identifier and uses some functions via IDA proxy
        self.ci = self.parent.crypto_identifier
        self.ip = self.parent.ida_proxy
        # references to Qt-specific modules
        self.QtGui = QtGui
        self.QtCore = QtCore
        self.NumberQTableWidgetItem = NumberQTableWidgetItem

        self.central_widget = self.QtGui.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # toolbar
        self._createToolbar()

        # Aritlog heuristic
        self._createAritlogWidget()

        # signature
        self._createSignatureWidget()

        # layout and fill the widget
        crypto_layout = QtGui.QVBoxLayout()
        splitter = self.QtGui.QSplitter(self.QtCore.Qt.Vertical)
        q_clean_style = QtGui.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(self.aritlog_widget)
        splitter.addWidget(self.signature_widget)
        crypto_layout.addWidget(splitter)

        self.central_widget.setLayout(crypto_layout)

    def _createToolbar(self):
        """
        Creates the toolbar, containing buttons to control the widget.
        """
        self._createScanAction()
        self.toolbar = self.addToolBar('Crypto Identification Toobar')
        self.toolbar.addAction(self.scanAction)

    def _createScanAction(self):
        """
        Create an action for the scan button of the toolbar and connect it.
        """
        self.scanAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path + "scancrypto.png"), \
            "Perform deep scan with crypto signatures (might take some time)", self)
        self.scanAction.triggered.connect(self._onScanButtonClicked)

    def _onScanButtonClicked(self):
        """
        The logic of the scan button from the toolbar.
        Uses the scanning functions of I{CryptoIdentifier} and updates the elements displaying the results.
        """
        self.ci.scanCryptoPatterns()
        self.populateSignatureTree()
        self.ci.scanAritlog()
        self.populateAritlogTable()

################################################################################
# Aritlog GUI
################################################################################

    def _createAritlogWidget(self):
        """
        Create the widget for the arithmetic/logic heuristic.
        """
        self.aritlog_widget = QtGui.QWidget()
        aritlog_layout = QtGui.QVBoxLayout()
        self.aritlog_label = QtGui.QLabel("Arithmetic/Logic Heuristic")
        self.aritlog_result_label = QtGui.QLabel("0 Blocks matched with these settings.")

        # aritlog controls
        self.aritlog_controls_widget = QtGui.QWidget()
        aritlog_controls_layout = QtGui.QHBoxLayout()

        # aritlog control sliders
        self.aritlog_controls_slider_widget = QtGui.QWidget()
        aritlog_controls_editor_layout = QtGui.QVBoxLayout()
        self.aritlog_controls_threshold_editor = BoundsEditor("ArithLog Rating: ", 0, 100, 40, 100)
        self.aritlog_controls_threshold_editor.boundsChanged.connect(self.populateAritlogTable)
        self.aritlog_controls_bblock_size_editor = BoundsEditor("Basic Blocks size: ", 0, 100, 8, 100, \
            False)
        self.aritlog_controls_bblock_size_editor.boundsChanged.connect(self.populateAritlogTable)
        self.aritlog_controls_num_api_editor = BoundsEditor("Allowed calls: ", 0, 10, 0, 1, \
            False)
        self.aritlog_controls_num_api_editor.boundsChanged.connect(self.populateAritlogTable)
        aritlog_controls_editor_layout.addWidget(self.aritlog_controls_threshold_editor)
        aritlog_controls_editor_layout.addWidget(self.aritlog_controls_bblock_size_editor)
        aritlog_controls_editor_layout.addWidget(self.aritlog_controls_num_api_editor)
        self.aritlog_controls_slider_widget.setLayout(aritlog_controls_editor_layout)

        # aritlog control result aggregation modes
        self.aritlog_controls_aggregator_widget = QtGui.QWidget()
        aritlog_controls_aggregator_layout = QtGui.QVBoxLayout()
        self.aritlog_controls_zeroing_cb = QtGui.QCheckBox("Exclude Zeroing")
        self.aritlog_controls_zeroing_cb.setCheckState(self.QtCore.Qt.Checked)
        self.aritlog_controls_zeroing_cb.stateChanged.connect(self.populateAritlogTable)
        self.aritlog_controls_looped_cb = QtGui.QCheckBox("Looped Blocks only")
        self.aritlog_controls_looped_cb.setCheckState(self.QtCore.Qt.Checked)
        self.aritlog_controls_looped_cb.stateChanged.connect(self.populateAritlogTable)
        self.aritlog_controls_group_cb = QtGui.QCheckBox("Group by Functions")
        self.aritlog_controls_group_cb.stateChanged.connect(self.populateAritlogTable)
        aritlog_controls_aggregator_layout.addWidget(self.aritlog_controls_zeroing_cb)
        aritlog_controls_aggregator_layout.addWidget(self.aritlog_controls_looped_cb)
        aritlog_controls_aggregator_layout.addWidget(self.aritlog_controls_group_cb)
        self.aritlog_controls_aggregator_widget.setLayout(aritlog_controls_aggregator_layout)

        aritlog_controls_layout.addWidget(self.aritlog_controls_slider_widget)
        aritlog_controls_layout.addWidget(self.aritlog_controls_aggregator_widget)
        self.aritlog_controls_widget.setLayout(aritlog_controls_layout)

        # aritlog result visualization
        self.aritlog_result_widget = QtGui.QWidget()
        aritlog_result_layout = QtGui.QVBoxLayout()
        self._createAritlogTable()
        aritlog_result_layout.addWidget(self.aritlog_table)
        self.aritlog_result_widget.setLayout(aritlog_result_layout)

        # aritlog composition
        aritlog_layout.addWidget(self.aritlog_label)
        aritlog_layout.addWidget(self.aritlog_controls_widget)
        aritlog_layout.addWidget(self.aritlog_result_label)
        aritlog_layout.addWidget(self.aritlog_result_widget)
        self.aritlog_widget.setLayout(aritlog_layout)

    def _createAritlogTable(self):
        """
        Create the result table for displaying results of the arithmetic/logic heuristic.
        """
        self.aritlog_table = QtGui.QTableWidget()
        self.populateAritlogTable()
        self.aritlog_table.doubleClicked.connect(self._onAritlogResultDoubleClicked)

    def populateAritlogTable(self):
        """
        Populate the result table for the arithmetic/logic table.
        Called everytime control parameters or scan results change.
        """
        self.aritlog_table.clear()
        self.aritlog_table.setSortingEnabled(False)
        ts = self.aritlog_controls_threshold_editor
        bs = self.aritlog_controls_bblock_size_editor
        na = self.aritlog_controls_num_api_editor
        is_grouped = self.aritlog_controls_group_cb.isChecked()
        is_nonzero = self.aritlog_controls_zeroing_cb.isChecked()
        is_looped = self.aritlog_controls_looped_cb.isChecked()

        aritlog_blocks = self.ci.getAritlogBlocks(ts.low / 100.0, ts.high / 100.0, bs.low, bs.high, na.low, \
            na.high, is_nonzero, is_looped)

        self._setAritlogTableHeaderLabels(is_grouped)
        table_data = self._calculateAritlogTableData(aritlog_blocks, is_grouped)
        row_count = len(table_data)

        self.aritlog_table.setColumnCount(len(self.aritlog_table_header_labels))
        self.aritlog_table.setHorizontalHeaderLabels(self.aritlog_table_header_labels)
        self.aritlog_table.setRowCount(row_count)
        self.aritlog_table.resizeRowToContents(0)

        for row, data_item in enumerate(table_data):
            for column, column_name in enumerate(self.aritlog_table_header_labels):
                tmp_item = self._getAritlogTableItem(data_item, column, is_grouped)
                tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                tmp_item.setTextAlignment(self.QtCore.Qt.AlignRight)
                self.aritlog_table.setItem(row, column, tmp_item)
            self.aritlog_table.resizeRowToContents(row)

        self._setAritlogResultLabel(self.aritlog_table.rowCount(), is_grouped)

        self.aritlog_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.aritlog_table.resizeColumnsToContents()
        self.aritlog_table.setSortingEnabled(True)

    def _setAritlogResultLabel(self, num_hits, is_grouped):
        """
        Update the label displaying the current number of result entries (basic blocks or functions) after filtering.
        @param num_hits: the number to display
        @type num_hits: int
        @param is_grouped: decides whether to display in basic block or functions mode
        @type is_grouped: boolean
        """
        self.aritlog_result_label.setText("%d %s from a total of %d blocks matched with the above settings." % (num_hits, \
            (is_grouped and "functions" or "blocks"), self.ci.getUnfilteredBlockCount()))

    def _calculateAritlogTableData(self, aritlog_blocks, is_grouped):
        """
        Prepare data for display in the result table for the arithmetic/logic heuristic.
        If display is grouped to functions, data is transformed accordingly, otherwise the
        input is returned without manipulation.
        @param aritlog_blocks: the blocks to transform for display
        @type: aritlog_blocks: a list of I{AritLogBasicBlock}
        @param is_grouped: decides whether preparation shall be made for functionally grouped or basic block display.
        @type: is_grouped: boolean
        @return: (a list of elements) where elements are either I{AritLogBasicBlock}s or temporary dictionaries
        """
        if is_grouped:
            tmp_dict = {}
            for block in aritlog_blocks:
                function_address = self.ip.LocByName(self.ip.GetFunctionName(block.start_ea))
                if function_address not in tmp_dict.keys():
                    tmp_dict[function_address] = {"function_address": function_address, "num_blocks": 1, \
                        "num_log_arith_instructions": block.num_log_arit_instructions}
                else:
                    tmp_dict[function_address]["num_blocks"] += 1
                    tmp_dict[function_address]["num_log_arith_instructions"] += block.num_log_arit_instructions
            return [tmp_dict[key] for key in tmp_dict.keys()]
        else:
            return aritlog_blocks

    def _setAritlogTableHeaderLabels(self, is_grouped):
        """
        Set the header labels for the arithmetic/logic result table.
        @param is_grouped: decides whether header labels shall be created for functionally grouped or
                           basic block display.
        @type: is_grouped: boolean
        """
        if is_grouped:
            self.aritlog_table_header_labels = ["Address", "Name", "# Blocks", "# Log/Arith Instr"]
        else:
            self.aritlog_table_header_labels = ["Address", "Name", "Block Address", "# Instr", \
                "Arithmetic/Logic Rating"]

    def _getAritlogTableItem(self, data_item, column_index, is_grouped):
        """
        Transform a data item for display in the arithmetic/logic result table
        @param data_item: the item to prepare for display
        @type data_item: either a I{AritLogBasicBlock} or a dictionary for a function
        @param column_index: the column to prepare the item for
        @type column_index: int
        @param is_grouped: decides whether the item shall be prepared for functionally grouped or
                           basic block display.
        @type: is_grouped: boolean
        @return: the prepared item
        """
        tmp_item = self.QtGui.QTableWidgetItem()
        if column_index == 0:
            if is_grouped:
                tmp_item = self.QtGui.QTableWidgetItem("0x%x" % data_item["function_address"])
            else:
                function_address = self.ip.LocByName(self.ip.GetFunctionName(data_item.start_ea))
                tmp_item = self.QtGui.QTableWidgetItem("0x%x" % function_address)
        elif column_index == 1:
            if is_grouped:
                tmp_item = self.QtGui.QTableWidgetItem(self.ip.GetFunctionName(data_item["function_address"]))
            else:
                function_address = self.ip.LocByName(self.ip.GetFunctionName(data_item.start_ea))
                tmp_item = self.QtGui.QTableWidgetItem(self.ip.GetFunctionName(function_address))
        elif column_index == 2:
            if is_grouped:
                tmp_item = self.NumberQTableWidgetItem("%d" % (data_item["num_blocks"]))
            else:
                tmp_item = self.QtGui.QTableWidgetItem("0x%x" % data_item.start_ea)
        elif column_index == 3:
            if is_grouped:
                tmp_item = self.NumberQTableWidgetItem("%d" % (data_item["num_log_arith_instructions"]))
            else:
                tmp_item = self.NumberQTableWidgetItem("%d" % data_item.num_instructions)
        elif column_index == 4:
            if self.aritlog_controls_zeroing_cb.isChecked():
                tmp_item = self.NumberQTableWidgetItem("%2.2f" % (100.0 * data_item.getAritlogRating(True)))
            else:
                tmp_item = self.NumberQTableWidgetItem("%2.2f" % (100.0 * data_item.getAritlogRating()))
        return tmp_item

    def _onAritlogResultDoubleClicked(self, mi):
        """
        The action to perform when an entry in the arithmetic/logic table is double clicked.
        Changes IDA View either to the function or basic block, depending on the column clicked.
        """
        clicked_address = 0
        if mi.column() == 0 or mi.column() == 1:
            clicked_address = self.aritlog_table.item(mi.row(), 0).text()
        elif mi.column() >= 2:
            clicked_address = self.aritlog_table.item(mi.row(), 2).text()
        self.ip.Jump(int(clicked_address, 16))

################################################################################
# Signature GUI
################################################################################

    def _createSignatureWidget(self):
        """
        Create the widget for the signature part.
        """
        self.signature_widget = QtGui.QWidget()
        signature_layout = QtGui.QVBoxLayout()
        self.signature_tree = QtGui.QTreeWidget()
        self.signature_tree.setColumnCount(1)
        self.signature_tree.setHeaderLabels(["Found Crypto Signatures"])
        self.signature_tree.itemDoubleClicked.connect(self._onSignatureTreeItemDoubleClicked)
        signature_layout.addWidget(self.signature_tree)
        self.signature_widget.setLayout(signature_layout)

        self.populateSignatureTree()

    def populateSignatureTree(self):
        """
        populate the TreeWidget for display of the signature scanning results.
        """
        self.signature_tree.clear()
        self.signature_tree.setSortingEnabled(False)
        signature_hits = self.ci.getSignatureHits()
        self.qtreewidgetitems_to_addresses = {}

        for signature in signature_hits:
            root = self.QtGui.QTreeWidgetItem(self.signature_tree)
            root.setText(0, signature)
            for hit in signature_hits[signature]:
                hit_information = self.QtGui.QTreeWidgetItem(root)
                hit_information.setText(0, "0x%x (%d bytes matched)" % (hit.start_address, len(hit.matched_signature)))
                self.qtreewidgetitems_to_addresses[hit_information] = hit.start_address
                for xref in hit.code_refs_to:
                    code_ref = self.QtGui.QTreeWidgetItem(hit_information)
                    code_ref.setText(0, "referenced by 0x%x (function: %s)" % (xref[0], \
                        self.ip.GetFunctionName(xref[0])))
                    if xref[1]:
                        code_ref.setForeground(0, self.QtGui.QBrush(self.QtGui.QColor(0xFF0000)))
                    self.qtreewidgetitems_to_addresses[code_ref] = xref[0]
        self.signature_tree.setSortingEnabled(True)

    def _onSignatureTreeItemDoubleClicked(self, item, column):
        """
        The action to perform when an entry in the signature TreeWIdget is double clicked.
        Changes IDA View either to location clicked.
        """
        if item in self.qtreewidgetitems_to_addresses:
            self.ip.Jump(self.qtreewidgetitems_to_addresses[item])
