#!/usr/bin/python
########################################################################
# Copyright (c) 2014
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
#
########################################################################

import os
import re
import time

import yara

from IdaProxy import IdaProxy
import idascope.core.helpers.Misc as Misc


class YaraScanner():
    """
    A module to analyze and explore an IDB for semantics. For a set of API names, references to these
    are identified and used for creating context and allowing tagging of them.
    """

    def __init__(self, idascope_config):
        print ("[|] loading YaraScanner")
        self.os = os
        self.re = re
        self.time = time
        self.ida_proxy = IdaProxy()
        self.yara = yara
        # fields
        self.idascope_config = idascope_config
        self._yara_rules = []
        self._results = []
        # FIXME: test more, then create GUI
        self.test()

    def test(self):
        self.load_rules()
        print self._yara_rules
        self.scan()
        print self._results

    def load_rules(self):
        self._yara_rules = []
        for yara_path in self.idascope_config.yara_sig_folders:
            for dirpath, dirnames, filenames in os.walk(yara_path):
                for filename in filenames:
                    filepath = dirpath + os.sep + filename
                    try:
                        rules = yara.compile(filepath)
                        self._yara_rules.append(rules)
                    except:
                        print "[!] Could not load yara rules file: %s" % filepath

    def _get_memory(self):
        result = ""
        start = [ea for ea in self.ida_proxy.Segments()][0]
        end = self.ida_proxy.SegEnd(start)
        for ea in Misc.lrange(start, end):
            result += chr(self.ida_proxy.Byte(ea))
        return result

    def _result_callback(self, data):
        self._results.append(data)
        yara.CALLBACK_CONTINUE

    def scan(self):
        memory = self._get_memory()
        self._results = []
        matches = []
        for rule in self._yara_rules:
            matches.append(rule.match(data=memory, callback=self._result_callback))
