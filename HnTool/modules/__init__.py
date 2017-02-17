# -*- coding: utf-8 -*-
#
# hntool rules - __init__
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
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

__files__ = ['authentication', 'filesystems', 'php', 'remote', 'system-wide', 'selinux']
__services__ = ['apache', 'proftpd', 'ports', 'postgresql', 'ssh', 'vsftpd']

__all__ = __files__ + __services__
