# -*- coding: utf-8 -*-
#
# HnTool - output module - treminal
# Copyright (C) 2009-2010 Authors
# Authors:
#   * Hugo Doria <mail at hugodoria.org>
#   * Aurelio A. Heckert <aurium at gmail dot com>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   ( at your option ) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import HnTool.modules
import string


class Format:

    description = "Human friendly output for terminal"

    def __init__(self, options):
        options.add_option("-n", "--term_nocolors",
                            action="store_false",
                            dest="term_use_colors", default=True,
                            help="does not use colors on terminal output")

    def format_status(self, token):
        use_colors = self.conf.term_use_colors
        if token == 'ok':
            if use_colors:
                return '[\033[1;92m   OK   \033[0m]'
            else:
                return '[   OK   ]'
        elif token == 'low':
            if use_colors:
                return '[\033[1;30m  LOW   \033[0m]'
            else:
                return '[  LOW   ]'
        elif token == 'medium':
            if use_colors:
                return '[\033[1;93m MEDIUM \033[0m]'
            else:
                return '[ MEDIUM ]'
        elif token == 'high':
            if use_colors:
                return '[\033[1;91m  HIGH  \033[0m]'
            else:
                return '[  HIGH  ]'
        elif token == 'info':
            if use_colors:
                return '[ \033[37m INFO \033[0m ]'
            else:
                return '[  INFO  ]'

    # Method to show the check results
    def msg_status(self, msg, status):
        '''
        Method to show the check results
        '''
        maxmsg_len = HnTool.modules.util.term_len() - 15
        # verifica se é str, se for converte para unicode para garantir que
        # letras acentuadas nao serao consideradas de tamanho 2
        # isso evita o erro de formatacao em strings acentuadas
        if isinstance(msg, str):
            msg = unicode(msg, 'utf-8')
        msg_splited = HnTool.modules.util.split_len(msg, maxmsg_len)

        result = ""
        i = 0
        while i < len(msg_splited) - 1:
            result += u'   {0}\n'.format(string.ljust(msg_splited[i], maxmsg_len))
            i += 1

        return result + "   " + \
                string.ljust(msg_splited[i], maxmsg_len) + \
                self.format_status(status)

    def output(self, report, conf):
        self.conf = conf
        # Print all the results, from the 5 types of messages ( ok, low, medium, high and info ).
        # First message is the "ok" one ( m['results'][0] ). The second one is
        # "low" ( m['results'][1] ). The third ( m['results'][2] ) is for "warnings"
        # and the fourth one is "high" ( m['results'][3] ), The last one is for
        # info messages.

        for m in report:
            if conf.term_use_colors:
                print '\n \033[96m' + m['title'] + '\033[0m'
            else:
                print '\n' + m['title']

            if m['results']['ok'] != []:
                for result in m['results']['ok']:
                    print self.msg_status(result, 'ok')
            if m['results']['low'] != []:
                for result in m['results']['low']:
                    print self.msg_status(result, 'low')
            if m['results']['medium'] != []:
                for result in m['results']['medium']:
                    print self.msg_status(result, 'medium')
            if m['results']['high'] != []:
                for result in m['results']['high']:
                    print self.msg_status(result, 'high')
            if m['results']['info'] != []:
                for result in m['results']['info']:
                    print self.msg_status(result, 'info')
