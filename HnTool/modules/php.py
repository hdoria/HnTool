# -*- coding: utf-8 -*-
#
# HnTool rules - php
# Copyright (C) 2009-2010 Candido Vieira <cvieira.br@gmail.com>
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
import ConfigParser
import HnTool.modules.util
from HnTool.modules.rule import Rule as MasterRule

class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name="php"
        self.long_name="Checks security problems on php config file"
        self.type="config"
        self.required_files = ['/etc/php5/apache2/php.ini', '/etc/php5/cli/php.ini', '/etc/php.ini']

    def requires(self):
        return self.required_files

    def analyze(self, options):
        check_results = self.check_results
        conf_files = self.required_files

        for php_conf in conf_files:
            if os.path.isfile(php_conf):

                config = ConfigParser.ConfigParser()

                try:
                    config.read(php_conf)
                except ConfigParser.ParsingError, (errno, strerror):
                    check_results['info'].append('Could not parse %s: %s' % (php_conf, strerror))
                    continue

                if not config.has_section('PHP'):
                    check_results['info'].append('%s is not a PHP config file' % (php_conf))
                    continue

                if config.has_option('PHP', 'register_globals'):
                    rg = config.get('PHP', 'register_globals').lower()
                    if rg == 'on':
                        check_results['medium'].append('Register globals is on (%s)' % (php_conf))
                    elif rg == 'off':
                        check_results['ok'].append('Register globals is off (%s)' % (php_conf))
                    else:
                        check_results['info'].append('Unknown value for register globals (%s)' % (php_conf))
                else:
                    check_results['info'].append('Register globals not found (%s)' % (php_conf))

                if config.has_option('PHP', 'safe_mode'):
                    sm = config.get('PHP', 'safe_mode').lower()
                    if sm == 'on':
                        check_results['low'].append('Safe mode is on (fake security) (%s)' % (php_conf))
                    elif sm == 'off':
                        check_results['info'].append('Safe mode is off (%s)' % (php_conf))
                    else:
                        check_results['info'].append('Unknown value for safe mode (%s)' % (php_conf))
                else:
                    check_results['info'].append('Safe mode not found (%s)' % (php_conf))

                if config.has_option('PHP', 'display_errors'):
                    de = config.get('PHP', 'display_errors').lower()
                    if de == 'on':
                        check_results['medium'].append('Display errors is on (stdout) (%s)' % (php_conf))
                    elif de == 'off':
                        check_results['ok'].append('Display errors is off (%s)' % (php_conf))
                    elif de == 'stderr':
                        check_results['info'].append('Display errors set to stderr (%s)' % (php_conf))
                    else:
                        check_results['info'].append('Unknown value for display errors (%s)' % (php_conf))
                else:
                    check_results['info'].append('Display errors not found (%s)' % (php_conf))

                if config.has_option('PHP', 'expose_php'):
                    ep = config.get('PHP', 'expose_php').lower()
                    if ep == 'on':
                        check_results['low'].append('Expose PHP is on (%s)' % (php_conf))
                    elif ep == 'off':
                        check_results['ok'].append('Expose PHP is off (%s)' % (php_conf))
                    else:
                        check_results['info'].append('Unknown value for expose PHP (%s)' % (php_conf))
                else:
                    check_results['info'].append('Expose PHP not found (%s)' % (php_conf))

        return check_results
