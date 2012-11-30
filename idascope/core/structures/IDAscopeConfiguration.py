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


class IDAscopeConfiguration():
    """
    This class is an information container for a segment.
    """

    def __init__(self, configuration, os_ref=None):
        if os_ref is not None:
            self.os = os_ref
        else:
            self.os = os
        # FIXME: second level path problem of referencing modules when accessing os.path.*
        try:
            self.os_path_normpath = self.os.path.normpath
        except:
            self.os_path_normpath = None
        # default configuration
        self.idascope_plugin_only = False
        self.root_file_path = ""
        self.icon_file_path = ""
        self.semantics_file = ""
        self.winapi_keywords_file = ""
        self.winapi_rootdir = ""
        self.winapi_shortcut = "ctrl+y"
        self.winapi_load_keyword_database = False
        self.winapi_online_enabled = False
        self._loadConfig(configuration)

    def _loadConfig(self, configuration):
        self.root_file_path = configuration["paths"]["idascope_root_dir"]
        # options directly affecting IDAscope
        self.idascope_plugin_only = configuration["plugin_only"]
        # file path to the directory containing icons used by IDAscope
        self.icon_file_path = self.root_file_path + self.os.sep \
            + "idascope" + self.os.sep + "icons" + self.os.sep
        # parse other paths
        self.config_path_sep = configuration["config_path_sep"]
        self.semantics_file = self.root_file_path + self.os.sep \
            + self._normalizePath(configuration["paths"]["semantics_file"])
        self.winapi_keywords_file = self.root_file_path + self.os.sep + \
            self._normalizePath(configuration["paths"]["winapi_keywords_file"])
        self.winapi_rootdir = self._normalizePath(configuration["paths"]["winapi_rootdir"]) + self.os.sep
        # widget related configurations
        self.winapi_shortcut = configuration["winapi"]["search_hotkey"]
        self.winapi_load_keyword_database = configuration["winapi"]["load_keyword_database"]
        self.winapi_online_enabled = configuration["winapi"]["online_enabled"]

    def _normalizePath(self, path):
        if self.os_path_normpath is None:
            # print "Skipping path normalization.", path
            return path
        else:
            parts = path.split(self.config_path_sep)
            return self.os_path_normpath(self.os.sep.join(parts))

    def __str__(self):
        """
        Convenience function.
        @return: a nice string representation for this object
        """
        return "IDAscope configuration: \n" \
            + "  root_file_path: %s\n" % self.root_file_path \
            + "  icon_file_path: %s\n" % self.icon_file_path \
            + "  semantics_file: %s\n" % self.semantics_file \
            + "  winapi_keywords_file: %s\n" % self.winapi_keywords_file \
            + "  winapi_rootdir: %s" % self.winapi_rootdir
