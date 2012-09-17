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

import os
import time

import idaapi
from idaapi import PluginForm, plugin_t
from PySide import QtGui
from PySide.QtGui import QIcon

from idascope.core.structures.IDAscopeConfiguration import IDAscopeConfiguration
from idascope.core.SemanticIdentifier import SemanticIdentifier
from idascope.core.DocumentationHelper import DocumentationHelper
from idascope.core.WinApiProvider import WinApiProvider
from idascope.core.CryptoIdentifier import CryptoIdentifier
from idascope.core.IdaProxy import IdaProxy
from idascope.widgets.FunctionInspectionWidget import FunctionInspectionWidget
from idascope.widgets.WinApiWidget import WinApiWidget
from idascope.widgets.CryptoIdentificationWidget import CryptoIdentificationWidget

################################################################################
# Core of the IDAscope GUI.
################################################################################

HOTKEYS = None
IDASCOPE = None
NAME = "simpliFiRE.IDAscope v1.0"


class IDAscopeForm(PluginForm):
    """
    This class contains the main window of IDAscope
    Setup of core modules and widgets is performed in here.
    """

    def __init__(self):
        super(IDAscopeForm, self).__init__()
        banner =   "#############################################\n" \
                 + "  ___ ____    _                             \n" \
                 + " |_ _|  _ \  / \   ___  ___ ___  _ __   ___ \n" \
                 + "  | || | | |/ _ \ / __|/ __/ _ \\| '_ \\ / _ \\\n" \
                 + "  | || |_| / ___ \\\\__ \\ (_| (_) | |_) |  __/\n" \
                 + " |___|____/_/   \\_\\___/\\___\\___/| .__/ \\___|\n" \
                 + "                                |_|         \n" \
                 + "#############################################\n" \
                 + " by Daniel Plohmann and Alexander Hanel      \n" \
                 + "#############################################\n"
        print banner
        print ("[+] Loading simpliFiRE.IDAscope")
        global HOTKEYS
        HOTKEYS = []
        self.idascope_widgets = []
        self.root_file_path = \
                os.path.realpath(__file__)[:os.path.realpath(__file__).rfind(os.sep) + 1]
        self.config = IDAscopeConfiguration(self.root_file_path + os.sep + "config.json")
        self.icon = QIcon(self.config.icon_file_path + "idascope.png")

    def setup_shared_modules(self):
        """
        Setup shared IDAscope modules.
        """
        time_before = time.time()
        print ("[/] setting up shared modules...")
        self.semantic_identifier = SemanticIdentifier(self.config)
        self.semantic_identifier.scan()
        self.documentation_helper = DocumentationHelper(self.config)
        self.winapi_provider = WinApiProvider(self.config)
        self.ida_proxy = IdaProxy()
        self.crypto_identifier = CryptoIdentifier()
        print ("[\\] this took %3.2f seconds.\n" % (time.time() - time_before))

    def setup_widgets(self):
        """
        Setup IDAscope widgets.
        """
        time_before = time.time()
        print ("[/] setting up widgets...")
        self.idascope_widgets.append(FunctionInspectionWidget(self))
        self.idascope_widgets.append(WinApiWidget(self))
        self.idascope_widgets.append(CryptoIdentificationWidget(self))
        self.setup_IDAscope_form()
        print ("[\\] this took %3.2f seconds.\n" % (time.time() - time_before))

    def setup_IDAscope_form(self):
        """
        Orchestrate the already initialized widgets in tabs on the main window.
        """
        self.tabs = QtGui.QTabWidget()
        self.tabs.setTabsClosable(False)
        for widget in self.idascope_widgets:
            self.tabs.addTab(widget, widget.icon, widget.name)
        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.tabs)
        self.parent.setLayout(layout)

    def OnCreate(self, form):
        """
        When creating the form, setup the shared modules and widgets
        """
        self.parent = self.FormToPySideWidget(form)
        self.parent.setWindowIcon(self.icon)
        self.setup_shared_modules()
        self.setup_widgets()

    def OnClose(self, form):
        """
        Perform cleanup.
        """
        global IDASCOPE
        del IDASCOPE

    def Show(self):
        return PluginForm.Show(self,
            NAME,
            options=(PluginForm.FORM_CLOSE_LATER | PluginForm.FORM_RESTORE | PluginForm.FORM_SAVE))

################################################################################
# functionality offered to IDAscope's widgets
################################################################################

    def setTabFocus(self, widget_name):
        """
        Can be used by IDAscope widgets to set focus to a widget, identified by name.
        @param widget_name: A widget name
        @type widget_name: str
        """
        for widget in self.idascope_widgets:
            if widget.name == widget_name:
                tab_index = self.tabs.indexOf(widget)
                self.tabs.setCurrentIndex(tab_index)
        return

    def register_hotkey(self, shortcut, py_function_pointer):
        """
        Can be used by IDAscope widgets to register hotkeys.
        Uses a global list HOTKEYS of function pointers that link to the desired functionality.
        Right now, linked functions cannot take parameters and should scrape all information they need by themselves.
        @param shortcut: A string describing a shortcut, e.g. "ctrl+F3"
        @type shortcut: str
        @param py_function_pointer: a python function that shall be called when the shortcut is triggered.
        @type py_function_pointer: a pointer to a python function
        """
        global HOTKEYS
        hotkey_index = len(HOTKEYS)
        hotkey_name = "idascope_HOTKEY_%d" % hotkey_index
        HOTKEYS.append(py_function_pointer)
        self.ida_proxy.CompileLine('static %s() { RunPythonStatement("HOTKEYS[%d]()"); }' % (hotkey_name, hotkey_index))
        self.ida_proxy.AddHotkey(shortcut, hotkey_name)

################################################################################
# Usage as plugin
################################################################################


class IDAscopePlugin(plugin_t):
    """
    Plugin version of IDAscope. Use this to deploy IDAscope via IDA plugins folder.
    """
    flags = idaapi.PLUGIN_UNL
    comment = NAME
    help = "A plugin to help to identify the relevant parts"
    wanted_name = "IDAscope"
    wanted_hotkey = "Ctrl-F4"

    def init(self):
        # Some initialization
        self.icon_id = 0
        return idaapi.PLUGIN_OK

    def run(self, arg=0):
        # Create form
        f = IDAscopeForm()

        # Show the form
        exit_code = f.Show()
        if exit_code == 0:
            f.Free()
            return

        f.Free()
        return

    def term(self):
        pass


def PLUGIN_ENTRY():
    return IDAscopePlugin()

################################################################################
# Usage as script
################################################################################


def main():
    global IDASCOPE

    try:
        IDASCOPE
        IDASCOPE.OnClose(IDASCOPE)
        print ("reloading IDAscope")
        IDASCOPE = IDAscopeForm()
        return
    except Exception:
        IDASCOPE = IDAscopeForm()

    IDASCOPE.Show()


if __name__ == "__main__":
    main()
