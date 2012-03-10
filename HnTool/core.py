#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# HnTool - A hardening tool for Linux/BSD
# Copyright (C) 2009-2010 Authors
# Authors:
#   * Hugo Doria <mail at hugodoria dot org>
#   * Aurelio A. Heckert <aurium at gmail dot com>
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

import sys

import string
from optparse import OptionParser
from optparse import OptionGroup

import gettext
gettext.install('HnTool')

import HnTool.modules.util
import HnTool.modules
import HnTool.output
from HnTool import __version__

class HnToolCore:

    def __init__(self):
        self.rule_modules = {}
        self.output_modules = {}
        self.report = []
        self.options = None

        self.opt_parser = OptionParser(
            usage = _("Usage: %prog [options]"),
            version="%prog " + str(__version__))

        self.output_options = OptionGroup(self.opt_parser, _("Output Options"))
        self.rule_options = OptionGroup(self.opt_parser, _("Rule Options"))

    # Method to list all rules available
    def list_rules(self, *args):
        '''Method to list all rules available'''

        print '-' * 31 + _(' HnTool rule list ') + '-' * 31
        print

        for module in sorted(self.rule_modules):
            print string.ljust(self.rule_modules[module].short_name, 16) +\
                ': ' + self.rule_modules[module].long_name

        sys.exit(0)

    # Method to list all output formats available
    def list_output_formats(self, *args):
        '''Method to list all output formats available'''

        print '-' * 30 + _(' HnTool output list ') + '-' * 30

        for module in self.output_modules:
            print string.ljust(module, 11) + ': ' \
            + self.output_modules[module].description

        sys.exit(0)

    # Loading all rule modules
    def load_modules(self):
        '''Method to load all rule modules'''

        for module in sorted(HnTool.modules.__all__):
            self.rule_modules[module] = \
               __import__('HnTool.modules.' + module, globals(), \
               locals(), [HnTool]).Rule(self.rule_options)

    # Loading all output modules
    def load_output_modules(self):
        '''Method to load all output modules'''

        for module in HnTool.output.__formats__:
            self.output_modules[module] = \
               __import__('HnTool.output.' + module, globals(), \
               locals(), [HnTool]).Format(self.output_options)

    # Parsing all the configuration options
    def config_option_parser(self):
        '''Method to parse all the configuration options'''

        # -l/--list option: list all available rules
        self.opt_parser.add_option("-l", "--list",
                              action="callback",
                              callback=self.list_rules,
                              help=_("returns a list of available rules"))

        # -t/--output_type: select the way that the report will
        # be generate (html or terminal, for now)
        self.opt_parser.add_option("-t", "--output_type",
                              action="store",
                              dest="output_format", default="terminal",
                              help=_("select the output format"))

        # --list_output_type: list all available output formats
        self.opt_parser.add_option("--list_output_type",
                              action="callback",
                              callback=self.list_output_formats,
                              help=_("list the avaliable output formats"))

        # -m/--modules: run specific modules
        self.opt_parser.add_option("-m","--modules",
                              type="string",
                              action="store",
                              dest="modules_list",
                              help=_("run only the tests specified by MODULES_LIST."))

        # -e/--exclude: don't run specific modules
        self.opt_parser.add_option("-e","--exclude",
                              type="string",
                              action="store",
                              dest="exclude_list",
                              help=_("don't run the tests specified by MODULES_LIST."))

        # adding the rules to they respective groups (rules or output)
        self.opt_parser.add_option_group(self.output_options)
        self.opt_parser.add_option_group(self.rule_options)

        self.options, args = self.opt_parser.parse_args(sys.argv[1:])

#TODO: define one error code for each error to allow automatic interactions.

    # Checking if all requirements are met
    def initial_check(self):
        '''Method to check if all HnTool's requirements are met'''

        # yes, only unix for now
        if not HnTool.modules.util.is_unix():
            print >> sys.stderr, \
            _('Error: You must have a Unix(-like) box. (No candy for you)')

            sys.exit(2)

    # Main initialization
    def init_core(self):
        '''Method to run the initial checks and load all modules,
        output modules and configuration options'''

        # status message must not go to stdout to not mess with the output
        #format.
        self.initial_check() # checking HnTool's requirements
        self.load_modules() # loading all the modules
        self.load_output_modules() # loading all the output modules
        self.config_option_parser() # getting all the options

    # This is where we run all the tests
    def run_tests(self):
        '''Method to run all tests available on HnTool'''

        self.init_core() # main initialization

        # checking if we are root. we need to be. oh yeah, baby.
        if not HnTool.modules.util.is_root():
            print >> sys.stderr, _('Error: You must be root to run HnTool')
            print >> sys.stderr, ''
            print >> sys.stderr, self.opt_parser.print_help()

            sys.exit(2)

        # starting the checks/output
        print >> sys.stderr, _('[ Starting HnTool checks... ]')

        #if we used the -e or --exclude option
        if self.options.exclude_list:
            # getting a liste with the difference between the list
            # with all modules and the list passed by the -e option
            modules_list = list(set(HnTool.modules.__all__) -
                                set(self.options.exclude_list.split(',')))

        elif self.options.modules_list: # if we just want to run specific modules
            modules_list = self.options.modules_list.split(',')

        else: # gets all the modules
            modules_list = HnTool.modules.__all__

        # Run all the modules and its checks.
        # The results of each module goes to "report"
        for m in modules_list:

            if m in HnTool.modules.__all__:

                # if the module requires something
                if self.rule_modules[m].requires() != None:

                    # if all the requiremets are met
                    if HnTool.modules.util.requirements_met(self.rule_modules[m].requires()):
                        self.report.append({'title': self.rule_modules[m].long_name, \
                        'results': self.rule_modules[m].analyze(self.options)})

                    else: # if the requirements aren't met
                        tmp_check_results = {'ok': [], 'low': [], 'medium': [],
                                             'high': [], 'info': []}
                        tmp_check_results['info'].append('One or more files required to run ' +
                        'this module could not be found')
                        self.report.append({'title': self.rule_modules[m].long_name, \
                        'results': tmp_check_results})

                # if the module does NOT requires something
                else:
                    self.report.append({'title': self.rule_modules[m].long_name, \
                        'results': self.rule_modules[m].analyze(self.options)})

            else:
                print >> sys.stderr, _('Invalid module ') + m
                sys.exit(2)

        # Give the report to the user
        self.output_modules[self.options.output_format].output(
            self.report,
            self.options
        )

if __name__ == "__main__":
    hn = HnToolCore()
    hn.run_tests()