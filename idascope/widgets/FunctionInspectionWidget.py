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


class FunctionInspectionWidget(QtGui.QMainWindow):
    """
    This widget is the front-end for the semantic inspection.
    """

    def __init__(self, parent):
        QtGui.QMainWindow.__init__(self)
        print "[|] loading FunctionInspectionWidget"
        # enable access to shared IDAscope modules
        self.parent = parent
        self.name = "Function Inspection"
        self.icon = QIcon(self.parent.config.icon_file_path + "semantics.png")
        # This widget relies on the semantic identifier and uses some functions via IDA proxy
        self.si = self.parent.semantic_identifier
        self.dh = self.parent.documentation_helper
        self.ida_proxy = self.parent.ida_proxy
        # references to Qt-specific modules
        self.QtGui = QtGui
        self.QtCore = QtCore
        self.NumberQTableWidgetItem = NumberQTableWidgetItem
        self.central_widget = self.QtGui.QWidget()
        self.setCentralWidget(self.central_widget)
        self.createGui()

    def createGui(self):
        """
        Create the main GUI with its components.
        """
        self.funcs_label = QtGui.QLabel("Functions of Interest (0/0)")
        self.calls_label = QtGui.QLabel("Selected function contains the following API references with parameters:")

        self.create_toolbar()

        self.create_functions_table()
        self.create_calls_table()
        self.create_parameter_table()

        # layout and fill the widget
        semantics_layout = QtGui.QVBoxLayout()

        function_info_widget = QtGui.QWidget()
        function_info_layout = QtGui.QHBoxLayout()
        self.function_dummy_only_cb = QtGui.QCheckBox("Only dummy names")
        self.function_dummy_only_cb.stateChanged.connect(self.populate_function_table)
        function_info_layout.addWidget(self.funcs_label)
        function_info_layout.addWidget(self.function_dummy_only_cb)
        function_info_widget.setLayout(function_info_layout)

        upper_table_widget = QtGui.QWidget()
        upper_table_layout = QtGui.QVBoxLayout()
        upper_table_layout.addWidget(function_info_widget)
        upper_table_layout.addWidget(self.funcs_table)
        upper_table_widget.setLayout(upper_table_layout)

        calls_params_widget = QtGui.QWidget()
        calls_params_layout = QtGui.QHBoxLayout()
        calls_params_layout.addWidget(self.calls_table)
        calls_params_layout.addWidget(self.parameter_table)
        calls_params_widget.setLayout(calls_params_layout)

        lower_tables_widget = QtGui.QWidget()
        lower_tables_layout = QtGui.QVBoxLayout()
        lower_tables_layout.addWidget(self.calls_label)
        lower_tables_layout.addWidget(calls_params_widget)
        lower_tables_widget.setLayout(lower_tables_layout)

        splitter = self.QtGui.QSplitter(self.QtCore.Qt.Vertical)
        q_clean_style = QtGui.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(upper_table_widget)
        splitter.addWidget(lower_tables_widget)
        semantics_layout.addWidget(splitter)

        self.central_widget.setLayout(semantics_layout)

        self.populate_function_table()
        self.update_functions_label()

    def create_toolbar(self):
        """
        Create the toolbar, containing some of the actions that can be performed with this widget.
        """
        self.create_refresh_action()
        self.create_rename_action()
        self.create_coloring_action()
        self.create_fix_unknown_code_action()
        self.create_rename_wrappers_action()

        self.toolbar = self.addToolBar('Function Inspection Toobar')
        self.toolbar.addAction(self.refreshAction)
        self.toolbar.addAction(self.annotateAction)
        self.toolbar.addAction(self.toggleColorAction)
        self.toolbar.addAction(self.fixUnknownCodeAction)
        self.toolbar.addAction(self.renameWrappersAction)

    def create_refresh_action(self):
        """
        Create the refresh action for the toolbar. On activiation, it triggers a scan of I{SemanticIdentifier} and
        updates the GUI.
        """
        self.refreshAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path + "refresh.png"), "Refresh the " \
            + "view by scanning all named references again.", self)
        self.refreshAction.triggered.connect(self.onRefreshButtonClicked)

    def create_rename_action(self):
        """
        Create the action which performs renaming of the function names in the IDB that are covered by the scan of
        the I{SemanticIdentifier}.
        """
        self.annotateAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path + "tags.png"), "Rename functions " \
            + "according to the identified tags", self)
        self.annotateAction.triggered.connect(self.onRenameButtonClicked)

    def create_coloring_action(self):
        """
        Create the action which cycles through the semantic code coloring modes via I{DocumentationHelper}.
        """
        self.toggleColorAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path + "colors.png"), \
            "Toggle semantic coloring", self)
        self.toggleColorAction.triggered.connect(self.onColoringButtonClicked)

    def create_fix_unknown_code_action(self):
        """
        Create the action which fixes unknown code to functions via I{DocumentationHelper}.
        """
        self.fixUnknownCodeAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path + "fix.png"), \
            "Fix unknown code to functions", self)
        self.fixUnknownCodeAction.triggered.connect(self.onFixUnknownCodeButtonClicked)

    def create_rename_wrappers_action(self):
        """
        Create the action which fixes unknown code to functions via I{DocumentationHelper}.
        """
        self.renameWrappersAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path + "unwrap.png"), \
            "Rename potential wrapper functions", self)
        self.renameWrappersAction.triggered.connect(self.onRenameWrappersButtonClicked)

    def create_functions_table(self):
        """
        Create the top table used for showing all functions covered by scanning for semantic information.
        """
        self.funcs_table = QtGui.QTableWidget()
        self.funcs_table.clicked.connect(self.onFunctionClicked)
        self.funcs_table.doubleClicked.connect(self.onFunctionDoubleClicked)

    def create_calls_table(self):
        """
        Create the bottom left table used for showing all identified API calls that are contained in the function
        selected in the function table.
        """
        self.calls_table = QtGui.QTableWidget()
        self.calls_table.clicked.connect(self.onCallClicked)
        self.calls_table.doubleClicked.connect(self.onCallDoubleClicked)

    def create_parameter_table(self):
        """
        Create the bottom right table used for showing all parameters for the API call selected in the calls table.
        """
        self.parameter_table = QtGui.QTableWidget()
        self.parameter_table.doubleClicked.connect(self.onParameterDoubleClicked)

    def populate_function_table(self):
        """
        Populate the function table with information from the last scan of I{SemanticIdentifier}.
        """
        self.funcs_table.setSortingEnabled(False)
        self.funcs_header_labels = ["Address", "Name", "Blocks"]
        for tag in sorted(self.si.get_tags()):
            self.funcs_header_labels.append(tag)
        self.funcs_table.clear()
        self.funcs_table.setColumnCount(len(self.funcs_header_labels))
        self.funcs_table.setHorizontalHeaderLabels(self.funcs_header_labels)
        # Identify number of table entries and prepare addresses to display
        function_addresses = []
        if self.function_dummy_only_cb.isChecked():
            function_addresses = self.si.get_identified_dummy_function_addresses()
        else:
            function_addresses = self.si.get_identified_function_addresses()
        if self.ida_proxy.BAD_ADDR in function_addresses:
            self.funcs_table.setRowCount(len(function_addresses) - 1)
        else:
            self.funcs_table.setRowCount(len(function_addresses))
        self.funcs_table.resizeRowToContents(0)

        for row, function_address in enumerate(function_addresses):
            # we don't want to render entries in the table that appear because analysis failed on broken code.
            if function_address == self.ida_proxy.BAD_ADDR:
                continue
            for column, column_name in enumerate(self.funcs_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.QtGui.QTableWidgetItem("0x%x" % function_address)
                elif column == 1:
                    tmp_item = self.QtGui.QTableWidgetItem(self.ida_proxy.GetFunctionName(function_address))
                elif column == 2:
                    tmp_item = self.NumberQTableWidgetItem("%d" % \
                        self.si.get_number_of_basic_blocks_for_function_address(function_address))
                else:
                    tmp_item = self.NumberQTableWidgetItem("%d" % \
                        self.si.get_tag_count_for_function_address(column_name, function_address))
                tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                self.funcs_table.setItem(row, column, tmp_item)
            self.funcs_table.resizeRowToContents(row)
        self.funcs_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.funcs_table.resizeColumnsToContents()
        self.funcs_table.setSortingEnabled(True)
        self.update_functions_label()

    def populate_calls_table(self, function_address):
        """
        Populate the calls table based on the selected function in the functions table.
        """
        self.calls_table.setSortingEnabled(False)
        self.calls_header_labels = ["Address", "API", "Tag"]
        self.calls_table.clear()
        self.calls_table.setColumnCount(len(self.calls_header_labels))
        self.calls_table.setHorizontalHeaderLabels(self.calls_header_labels)

        tagged_call_contexts = self.si.get_tagged_apis_for_function_address(function_address)
        self.calls_table.setRowCount(len(tagged_call_contexts))
        for row, tagged_call_ctx in enumerate(tagged_call_contexts):
            for column, column_name in enumerate(self.calls_header_labels):
                if column == 0:
                    tmp_item = self.QtGui.QTableWidgetItem("0x%x" % tagged_call_ctx.address_of_call)
                elif column == 1:
                    tmp_item = self.QtGui.QTableWidgetItem(tagged_call_ctx.called_function_name)
                elif column == 2:
                    tmp_item = self.QtGui.QTableWidgetItem(tagged_call_ctx.tag)
                tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                self.calls_table.setItem(row, column, tmp_item)
            self.calls_table.resizeRowToContents(row)
        self.calls_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.calls_table.resizeColumnsToContents()
        self.calls_table.setSortingEnabled(True)

    def populate_parameter_table(self, call_address):
        """
        Populate the parameter table based on the selected API call in the calls table.
        """
        self.parameter_table.setSortingEnabled(False)
        self.parameter_header_labels = ["Address", "Type", "Name", "Value"]
        self.parameter_table.clear()
        self.parameter_table.setColumnCount(len(self.parameter_header_labels))
        self.parameter_table.setHorizontalHeaderLabels(self.parameter_header_labels)

        parameter_contexts = self.si.get_parameters_for_call_address(call_address)
        self.parameter_table.setRowCount(len(parameter_contexts))
        for row, parameter_ctx in enumerate(parameter_contexts):
            for column, column_name in enumerate(self.parameter_header_labels):
                if column == 0:
                    tmp_item = self.QtGui.QTableWidgetItem(parameter_ctx.get_rendered_push_address())
                elif column == 1:
                    tmp_item = self.QtGui.QTableWidgetItem(parameter_ctx.parameter_type)
                elif column == 2:
                    tmp_item = self.QtGui.QTableWidgetItem(parameter_ctx.parameter_name)
                elif column == 3:
                    tmp_item = self.QtGui.QTableWidgetItem(parameter_ctx.get_rendered_value())
                tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                self.parameter_table.setItem(row, column, tmp_item)
            self.parameter_table.resizeRowToContents(row)
        self.parameter_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.parameter_table.resizeColumnsToContents()
        self.parameter_table.setSortingEnabled(True)

    def update_functions_label(self):
        num_displayed_functions = 0
        if self.function_dummy_only_cb.isChecked():
            num_displayed_functions = len(self.si.get_identified_dummy_function_addresses())
        else:
            num_displayed_functions = len(self.si.get_identified_function_addresses())
        self.funcs_label.setText("Functions of Interest (%d/%d)" %
            (num_displayed_functions, self.si.calculate_number_of_functions()))

    def onRenameButtonClicked(self):
        """
        Action for renaming functions when the rename action from the toolbar is activated.
        """
        self.si.rename_functions()
        self.onRefreshButtonClicked()

    def onRefreshButtonClicked(self):
        """
        Action for refreshing the window data by performing another scan of I{SemanticIdentifier}.
        """
        self.si.scan()
        self.populate_function_table()

    def onColoringButtonClicked(self):
        """
        Action for performing semantic coloring of instructions.
        """
        self.dh.colorize(self.si.get_last_result())

    def onFixUnknownCodeButtonClicked(self):
        """
        Action for fixing unknown parts of code (red in address bar) to functions.
        """
        self.dh.convert_non_function_code()

    def onRenameWrappersButtonClicked(self):
        """
        Action for renaming potential wrapper functions to the wrapped API if they have a dummy name.
        """
        self.si.rename_potential_wrapper_functions()

    def onFunctionClicked(self, mi):
        """
        If a function in the functions table is clicked, the view of the calls and parameter table are updated.
        """
        clicked_function_address = int(self.funcs_table.item(mi.row(), \
            0).text(), 16)
        self.populate_calls_table(clicked_function_address)

    def onFunctionDoubleClicked(self, mi):
        """
        If a function in the functions table is doubleclicked, IDA View is located to the corresponding address.
        """
        clicked_function_address = self.funcs_table.item(mi.row(), 0).text()
        self.ida_proxy.Jump(int(clicked_function_address, 16))

    def onCallClicked(self, mi):
        """
        If an API call in the calls table is clicked, the view of the parameter table is updated.
        """
        clicked_function_address = int(self.calls_table.item(mi.row(), \
            0).text(), 16)
        self.populate_parameter_table(clicked_function_address)

    def onCallDoubleClicked(self, mi):
        """
        If an API in the calls table is doubleclicked, IDA View is located to the corresponding address.
        """
        if mi.column() == 1:
            for widget in self.parent.idascope_widgets:
                if widget.name == "WinAPI Browsing":
                    widget.navigate(self.calls_table.item(mi.row(), mi.column()).text())
                    self.parent.setTabFocus("WinAPI Browsing")
        else:
            clicked_function_address = self.calls_table.item(mi.row(), 0).text()
            self.ida_proxy.Jump(int(clicked_function_address, 16))

    def onParameterDoubleClicked(self, mi):
        """
        If a parameter in the parameter table is doubleclicked, IDA View is located to the corresponding address.
        """
        clicked_function_address = self.parameter_table.item(mi.row(), 0).text()
        self.ida_proxy.Jump(int(clicked_function_address, 16))
