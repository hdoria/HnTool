# -*- coding: utf-8 -*-
#
# HnTool rules - base class
# Copyright (C) 2010 Mauricio Vieira <mauricio@mauriciovieira.net>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

import os

class Rule:
   def __init__(self, options):
      '''Type must be "config" or "files"
      short_name
      long_name
      '''
      self.check_results = {'ok': [], 'low': [], 'medium': [], 'high': [], 'info': []}
      self.type = ""
      self.short_name = ""
      self.long_name = ""
      pass

   def requires(self):
      '''This method should return all the required files to run
      the module. Usually, it's the same as self.conf_file'''
      return None

   def analyze(self, options):
      '''Do your magic and fill self.check_results with strings'''