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


class FunctionContextFilter():
    """
    This class is defines the filter properties applicable to a scan result in order to select gathered information
    more precisely.
    """

    def __init__(self):
        self.display_tags = True
        self.display_groups = False
        self.display_tag_only = True
        self.display_dummy_only = False
        self.enabled_tags = []
        self.enabled_groups = []
        self.enabled_additions = []

    def setGroupDisplay(self):
        self.display_tags = False
        self.display_groups = True

    def setTagDisplay(self):
        self.display_tags = True
        self.display_groups = False
