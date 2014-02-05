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
        # FIXME: APT1 sample source: http://contagiodump.blogspot.de/2013/03/mandiant-apt1-samples-categorized-by.html
        print ("[|] loading YaraScanner")
        self.os = os
        self.re = re
        self.time = time
        self.ida_proxy = IdaProxy()
        self.yara = yara
        # fields
        self.idascope_config = idascope_config
        self.num_files_loaded = 0
        self._yara_rules = []
        self._results = []
        self.segment_offsets = []

    def test(self):
        self.load_rules()
        self.scan()

    def getResults(self):
        return self._results

    def load_rules(self):
        self.num_files_loaded = 0
        self._yara_rules = []
        for yara_path in self.idascope_config.yara_sig_folders:
            for dirpath, dirnames, filenames in os.walk(yara_path):
                for filename in filenames:
                    filepath = dirpath + os.sep + filename
                    try:
                        rules = yara.compile(filepath)
                        self._yara_rules.append(rules)
                        if rules:
                            self.num_files_loaded += 1
                    except:
                        print "[!] Could not load yara rules file: %s" % filepath

    def _get_memory(self):
        result = ""
        segment_starts = [ea for ea in self.ida_proxy.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = self.ida_proxy.SegEnd(start)
            for ea in Misc.lrange(start, end):
                result += chr(self.ida_proxy.Byte(ea))
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return result, offsets

    def _result_callback(self, data):
        adjusted_offsets = []
        for string in data["strings"]:
            adjusted_offsets.append((self._translateMemOffsetToVirtualAddress(string[0]), string[1], string[2]))
        data["strings"] = adjusted_offsets
        self._results.append(data)
        if data["matches"]:
            print "  [+] Yara Match for signature: %s" % data["rule"]
        yara.CALLBACK_CONTINUE

    def _translateMemOffsetToVirtualAddress(self, offset):
        va_offset = 0
        for seg in self.segment_offsets:
            if seg[1] < offset < seg[2]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset

    def scan(self):
        memory, offsets = self._get_memory()
        self.segment_offsets = offsets
        self._results = []
        matches = []
        print "[!] Performing Yara scan..."
        for rule in self._yara_rules:
            matches.append(rule.match(data=memory, callback=self._result_callback))
        if len(matches) == 0:
            print "  [-] no matches. :("
