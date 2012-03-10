# -*- coding: utf-8 -*-
#
# HnTool - utility functions
# Copyright (C) 2009-2010 Hugo Doria <mail@hugodoria.org>
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#

import os
import sys
import re
import shlex

# Functions

def is_root():
    '''Method to check if hntool is running as root.'''
    if os.getuid() == 0:
        return True

def is_unix():
    '''Method to check if we have power'''
    if os.name == 'posix':
        return True
    return False

def term_len():
    return int(os.popen('stty size', 'r').read().split()[1])

def split_len(seq, length):
    result = []
    p = re.compile("(.{,"+str(length)+"})\s")
    while len(seq) > 0:
        if len(seq) < length:
            result.append(seq)
            break
        else:
            tmp,seq = (p.split(seq,1))[1:]
            result.append(tmp)
    return result

def hntool_conf_parser(pfile):
    '''This method parses a config file and returns a list with
    all the lines that aren't comments or blank'''

    result = {}

    if os.path.isfile(pfile):
        fp = open(pfile,'r') # reading the file
        for line in fp:
            # getting all the lines that aren't comments
            line = shlex.split(line, comments=True)
            if len(line) >= 2:
                result[line[0]] = line[1]
        fp.close() #closing the file

    # returns a list with all the lines
    # [['option1', 'value1'], ['option2', 'value2']]
    # and so on
    return result

def requirements_met(pfile):
    '''This method should check if all the requirements (files)
    are met (one or more files can be found on the system)'''

    for f in pfile:
        if os.path.isfile(f):
            return True

    return False