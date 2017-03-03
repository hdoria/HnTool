#!/usr/bin/env python

from setuptools import setup
from os.path import join
from sys import prefix
from HnTool import __version__

DATAFILES = [
      (join(prefix, 'share', 'man', 'man1'), [join('doc', 'hntool.1')]),
      ('share/doc/hntool-%s' % __version__, ['AUTHORS', 'LICENSE', 'NEWS', 'README', 'TODO'])]

setup(name='HnTool',
      version=str(__version__),
      license='GPL-2',
      description='A hardening tool for *nixes',
      long_description=open('README').read(),
      author='Hugo Doria',
      author_email='hugodoria@gmail.com',
      url='http://code.google.com/p/hntool/',
      packages = ['HnTool', 'HnTool.output', 'HnTool.modules'],
      entry_points={'console_scripts': ['hntool=HnTool.core:main'] },
      # scripts=['hntool'],
      data_files=DATAFILES)
