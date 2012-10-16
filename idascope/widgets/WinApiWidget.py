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
from PySide.QtGui import QCompleter, QLineEdit, QStringListModel, QTextBrowser, QIcon


class WinApiWidget(QtGui.QWidget):
    """
    A widget for allowing easy access to Windows API information. Front-end to the I{idascope.core.WinApiProvider}.
    """

    def __init__(self, parent):
        QtGui.QWidget.__init__(self)
        print "[|] loading WinApiWidget"
        self.parent = parent
        self.name = "WinAPI Browsing"
        self.icon = QIcon(self.parent.config.icon_file_path + "winapi.png")
        self.search_icon = QIcon(self.parent.config.icon_file_path + "search.png")
        self.back_icon = QIcon(self.parent.config.icon_file_path + "back.png")
        self.forward_icon = QIcon(self.parent.config.icon_file_path + "forward.png")
        self.online_icon = QIcon(self.parent.config.icon_file_path + "online.png")
        self.ida_proxy = self.parent.ida_proxy
        self.QtGui = QtGui
        self.QtCore = QtCore
        self.winapi = self.parent.winapi_provider
        self.old_keyword_initial = ""
        self.winapi.register_data_receiver(self.populate_browser_window)
        self.createGui()
        self.update_availability()
        self.register_hotkeys()

    def update_availability(self):
        """
        Adjust the availability of this widget by checking if the keyword database has been loaded or
        online mode is enabled.
        """
        if not self.winapi.has_offline_msdn_available() and \
            not self.winapi.has_online_msdn_available():
            self.browser_window.setHtml("<p><font color=\"#FF0000\">Offline MSDN database is not available. To use " \
                + "it, have a look at the installation instructions located in the manual: " \
                + "IDAscope/documentation/manual.html. Online mode is deactivated as well.</font></p>")
            self.search_button.setEnabled(False)
            self.api_chooser_lineedit.setEnabled(False)
        else:
            self.browser_window.setHtml("<p>Enter a search term in the above field to search offline/online MSDN.</p>")
            self.search_button.setEnabled(True)
            self.api_chooser_lineedit.setEnabled(True)

    def register_hotkeys(self):
        """
        Register hotkeys with IDAscope in order to ease the use of this widget.
        """
        self.parent.register_hotkey(self.parent.config.winapi_shortcut, self.navigate_to_highlighted_identifier)

    def createGui(self):
        """
        Create the GUI for this widget and all of its components.
        """
        self.create_back_button()
        self.create_next_button()
        self.create_online_button()
        self.create_api_chooser_lineedit()
        self.create_search_button()
        self.create_browser_window()

        winapi_layout = QtGui.QVBoxLayout()
        selection_widget = QtGui.QWidget()
        selection_layout = QtGui.QHBoxLayout()
        selection_layout.addWidget(self.online_button)
        selection_layout.addWidget(self.back_button)
        selection_layout.addWidget(self.next_button)
        selection_layout.addWidget(self.api_chooser_lineedit)
        selection_layout.addWidget(self.search_button)
        selection_widget.setLayout(selection_layout)
        winapi_layout.addWidget(selection_widget)
        winapi_layout.addWidget(self.browser_window)
        self.setLayout(winapi_layout)

    def create_back_button(self):
        """
        Create a back button to allow easier browsing
        """
        self.back_button = QtGui.QPushButton(self.back_icon, "", self)
        self.back_button.setToolTip("Go back to previously accessed content.")
        self.back_button.resize(self.back_button.sizeHint())
        self.back_button.setEnabled(False)
        self.back_button.clicked.connect(self.onBackButtonClicked)

    def create_next_button(self):
        """
        Create a next button to allow easier browsing
        """
        self.next_button = QtGui.QPushButton(self.forward_icon, "", self)
        self.next_button.setToolTip("Go forward to previously accessed content.")
        self.next_button.resize(self.next_button.sizeHint())
        self.next_button.setEnabled(False)
        self.next_button.clicked.connect(self.onNextButtonClicked)

    def create_online_button(self):
        """
        Create a next button to allow easier browsing
        """
        self.online_button = QtGui.QPushButton(self.online_icon, "", self)
        self.online_button.setCheckable(True)
        if self.winapi.has_online_msdn_available():
            self.online_button.setChecked(QtCore.Qt.Checked)
        self.online_button.setToolTip("Enable/disable MSDN online lookup.")
        self.online_button.resize(self.online_button.sizeHint())
        self.online_button.clicked.connect(self.onOnlineButtonClicked)

    def create_api_chooser_lineedit(self):
        """
        Create the I{QLineEdit }used for selecting API names. This includes a QCompleter to make suggestions based on
        the keyword database.
        """
        self.api_chooser_lineedit = QLineEdit()
        self.api_chooser_lineedit.returnPressed.connect(self.populate_browser_window)
        self.api_chooser_lineedit.textChanged.connect(self.update_completer_model)

        completer = QCompleter()
        completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
        completer.setModelSorting(QCompleter.CaseSensitivelySortedModel)
        self.completer_model = QStringListModel([])
        completer.setModel(self.completer_model)
        self.api_chooser_lineedit.setCompleter(completer)

    def create_search_button(self):
        """
        Create a search button besides the QLineEdit.
        """
        self.search_button = QtGui.QPushButton(self.search_icon, "", self)
        self.search_button.setToolTip("Search for the chosen API name, structure or whatever WinAPI documentation " \
            + "might have for you.")
        self.search_button.resize(self.search_button.sizeHint())
        self.search_button.clicked.connect(self.onSearchButtonClicked)

    def create_browser_window(self):
        """
        Create the browser window with a I{QTextBrowser}. This display component is chosen over I{QWebView} because
        WebKit is not included in the standard PySide installation as distributed with IDA Pro.
        """
        self.browser_window = QTextBrowser()
        self.browser_window.anchorClicked.connect(self.browserAnchorClicked)

    def update_completer_model(self):
        """
        Update the completer model used to make suggestions. The model is only updated if anything is entered into the
        search line and the initial character differs from the previous initial character.
        """
        keyword_data = []
        api_chooser_text = self.api_chooser_lineedit.text()
        if len(api_chooser_text) > 0:
            keyword_initial = api_chooser_text[0].lower()
            if keyword_initial != self.old_keyword_initial:
                self.old_keyword_initial = keyword_initial
                keyword_data = self.winapi.get_keywords_for_initial(keyword_initial)
                self.completer_model.setStringList(keyword_data)

    def populate_browser_window(self, content=""):
        """
        Populate the browser window based upon the entered term in the search line.
        @param content: the content to render in the browser
        @type content: str
        """
        if content == "":
            api_chooser_text = self.api_chooser_lineedit.text()
            if len(api_chooser_text) > 0:
                content = self.winapi.get_keyword_content(api_chooser_text)
        self.browser_window.setHtml(content)
        self.update_history_button_state()

    def onSearchButtonClicked(self):
        """
        Action that is performed when the search button is clicked. This will populate the browser window.
        """
        self.populate_browser_window()

    def onBackButtonClicked(self):
        """
        Action that is performed when the search button is clicked. This will populate the browser window.
        """
        document_content, anchor = self.winapi.get_previous_document_content()
        if document_content != "":
            self.browser_window.setHtml(document_content)
        self.browser_window.scrollToAnchor(anchor)
        self.update_history_button_state()

    def onNextButtonClicked(self):
        """
        Action that is performed when the search button is clicked. This will populate the browser window.
        """
        document_content, anchor = self.winapi.get_next_document_content()
        if document_content != "":
            self.browser_window.setHtml(document_content)
        self.browser_window.scrollToAnchor(anchor)
        self.update_history_button_state()

    def onOnlineButtonClicked(self):
        """
        Action that is performed when the search button is clicked. This will populate the browser window.
        """
        self.winapi.set_online_msdn_enabled(not self.winapi.has_online_msdn_available())
        self.update_availability()

    def browserAnchorClicked(self, url):
        """
        Callback for the case an anchor (or any link) within the browser window is clicked. This will fetch
        document content and anchor based on the URL of the link and update the browser window.
        @param url: a URL as triggered by the callback
        @type url: QUrl
        """
        document_content, anchor = self.winapi.get_linked_document_content(url)
        if document_content != "":
            self.browser_window.setHtml(document_content)
        self.browser_window.scrollToAnchor(anchor)
        self.update_history_button_state()

    def navigate(self, api_name):
        """
        A function exposed in order to allow the widget to be navigated to an arbitrary API name.
        @param api_name: the API name to navigate the widget to.
        @type api_name: str
        """
        self.api_chooser_lineedit.setText(api_name)
        self.populate_browser_window()

    def navigate_to_highlighted_identifier(self):
        """
        A function exposed to allow navigating the widget to the currently highlighted identifier from the IDA view.
        """
        if self.winapi.has_offline_msdn_available():
            highlighted_identifier = self.ida_proxy.get_highlighted_identifier()
            self.navigate(highlighted_identifier)
            self.parent.setTabFocus(self.name)

    def update_history_button_state(self):
        """
        Update the button state (enabled/disabled) according to availability of history information from the
        WinApiProvider
        """
        self.back_button.setEnabled(self.winapi.has_backward_history())
        self.next_button.setEnabled(self.winapi.has_forward_history())
