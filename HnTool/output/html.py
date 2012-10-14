# -*- coding: utf-8 -*-
#
# HnTool - output module - html
# Copyright (C) 2009-2010 Authors
# Authors:
#   * Hugo Doria <mail at hugodoria dot org>
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

    description = "HTML output for a web browser"

    def __init__(self, options):
        pass

    def format_status( self, token ):
        if token == 'ok':
            return '<td class="status-ok">OK</td>'
        elif token == 'low':
            return '<td class="status-low">LOW</td>'
        elif token == 'medium':
            return '<td class="status-medium">MEDIUM</td>'
        elif token == 'high':
            return '<td class="status-high">HIGH</td>'
        elif token == 'info':
            return '<td class="status-info">INFO</td>'

    # Method to show the check results
    def msg_status( self, msg, status ):
        '''
        Method to show the check results
        '''
        return '<tr>' + \
               self.format_status( status ) + \
               '<td>' + msg + '</td>' + \
               '</tr>'

    def output( self, report, conf ):
        self.conf = conf
        # Print all the results, from the 5 types of messages ( ok, low, medium, high and info ).
        # First message is the "ok" one ( m['results'][0] ). The second one is
        # "low" ( m['results'][1] ). The third ( m['results'][2] ) is for "warnings"
        # and the fourth one is "high" ( m['results'][3] ), The last one is for
        # info messages.
        print '''<html>
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
            <title>HnTool - A hardening tool for *nixes - Report</title>

            <style type="text/css">

                body  {
                    font: 12px 'Lucida Grande', sans-serif;
                    color: #666666;
                    text-align: center;
                    margin-right: auto;
                    margin-left: auto;
                    margin-top: 0;
                    border-top: 3px solid black;
                }

                h2 {
                    text-align:  left;
                    font-size:        15px;
                    padding-top:      15px;
                    padding-bottom:   5px;
                    padding-left:     5px;
                    border-bottom: 1px solid #000;
                }

                #wrap {
                    width: 1000px;
                    margin:0 auto;
                    margin-top: 10px;
                    text-align: center;
                }

                #left {
                    width: 700px;
                    float: left;
                }

                #right {
                    margin-top:      15px;
                    margin-left: 720px;
                    border: 1px solid #ddd;
                }

                ul {
                    text-align: left;
                    text-decoration: none;
                }

                table {
                    border: 0;
                    width: 690px;
                }

                td {
                    color: #000;
                    padding: 5px;
                }

                .status-ok {
                    background: lightgreen;
                    text-align: center;
                    font-size: 12px;
                }

                .status-low {
                    background: lightgray;
                    text-align: center;
                    font-size: 12px;
                }

                .status-medium {
                    background: yellow;
                    text-align: center;
                    font-size: 12px;
                }

                .status-high {
                    background: red;
                    text-align: center;
                    font-size: 12px;
                }

                .status-info {
                    background: lightblue;
                    text-align: center;
                    font-size: 12px;
                }
            </style>
        </head>

        <body>

        <div id="wrap">
            <div id="header">
                <h1>HnTool - A hardening tool for *nixes - Report</h1>
            </div>

            <div id="left">
                <table>'''

        statistics = {'ok': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for m in report:
            print '<tr><th colspan="2" align="left"><h2>' + m['title'] + '</h2></th></tr>'
            if m['results']['ok'] != []:
                for result in m['results']['ok']:
                    print self.msg_status( result, 'ok' )
                    statistics['ok'] += 1
            if m['results']['low'] != []:
                for result in m['results']['low']:
                    print self.msg_status( result, 'low' )
                    statistics['low'] += 1
            if m['results']['medium'] != []:
                for result in m['results']['medium']:
                    print self.msg_status( result, 'medium' )
                    statistics['medium'] += 1
            if m['results']['high'] != []:
                for result in m['results']['high']:
                    print self.msg_status( result, 'high' )
                    statistics['high'] += 1
            if m['results']['info'] != []:
                for result in m['results']['info']:
                    print self.msg_status( result, 'info' )
                    statistics['info'] += 1

        print '''
                </table>
            </div> <!-- closing the left div -->

            <div id="right">
                <h3>Statistics</h3>
                <ul>'''

        print '    <li><strong>OK:</strong> ' + str(statistics['ok']) + '</li>'
        print '    <li><strong>HIGH:</strong> ' + str(statistics['high']) + '</li>'
        print '    <li><strong>MEDIUM:</strong> ' + str(statistics['medium']) + '</li>'
        print '    <li><strong>LOW:</strong> ' + str(statistics['low']) + '</li>'
        print '    <li><strong>INFO:</strong> ' + str(statistics['info']) + '</li>'

        print '''
                </ul>
            </div> <!-- closing the right div -->
        </div> <!-- closing the wrap div -->
        </body>
        </html>'''
