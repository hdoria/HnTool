# HnTool

## What is it?

HnTool is an open source (GPLv2) hardening tool for Unix. It scans your system for vulnerabilities or problems in configuration files allowing you to get a quick overview of the security status of your system.

To use HnTool download it and run: ::

	# ./hntool


## Supported systems

HnTool was already tested and is working on:

* Arch Linux
* CentOS
* Debian
* Fedora
* Gentoo
* Ubuntu

If you are using HnTool on a system that is not listed above, please, let us know.

## How to install

To install HnTool run the following command, as root: ::

	# python setup.py install --prefix /usr/ --root /

## How to use

Run HnTool with: ::

	# ./hntool

You can also see the hntool(1) manual by typing 'man hntool' at the command line
or see the usage help: ::

	$ hntool -h


## Understanding the output

There are 5 types of results:

 * OK :
	Means that the item checked is fine and that you do not need to worry

 * INFO:
	Means that you should know the item status, but probably it is fine. A port
	opened, for example.

 * LOW:
	Means that a security problem was found, but it does not provides a high risk
	for your system.

 * MEDIUM:
	Things are getting worse and you should start to worry about these itens.

 * HIGH:
	You have an important security hole/problem on your system and you
	should fix it NOW or run and save your life.


## How can I help?

There are several ways that you can contribute and help HnTool's development.
You can contribute with code, patchs, bugs and feature requests.

To report a bug or a feature request for HnTool, file a issue in our Google Code
page: https://github.com/hdoria/HnTool

If you're reporting a bug, please give concrete examples of how and where the
problem occurs.

If you've a patch (fixing a bug or a new HnTool module), then you can file an
issue on Google Code too: http://code.google.com/p/hntool/issues/list

HnTool's source is available on:

https://github.com/hdoria/HnTool


## How to create a module

This section documents the innards of HnTool and specifies how to create
a new module.

The main HnTool program (hntool.py) runs a list of rules defined in `__files__`
and `__services__`.

 * __files__ :
	defines the rules which process simple files and configs.

 * __services__ :
	defines the rules which checks the security on services and
	daemons.

Once your module is finalized, remember to add it to the appropriate array
(__files__ or __services__) defined in hntool/__init__.py

A sample HnTool module is like this (hntool/ssh.py): ::

    import os
    import HnTool.modules.util
    from HnTool.modules.rule import Rule as MasterRule

    class Rule(MasterRule):
    def __init__(self, options):
        MasterRule.__init__(self, options)
        self.short_name="ssh"
        self.long_name="Checks security problems on sshd config file"
        self.type="config"
        self.required_files = ['/etc/ssh/sshd_config', '/etc/sshd_config']

    def requires(self):
        return self.required_files

    def analyze(self, options):
        check_results = self.check_results
        ssh_conf_file = self.required_files

        for sshd_conf in ssh_conf_file:
            if os.path.isfile(sshd_conf):
                # dict with all the lines
                lines = HnTool.modules.util.hntool_conf_parser(sshd_conf)

                # Checking if SSH is using the default port
                if 'Port' in lines:
                    if int(lines['Port']) == 22:
                        check_results['low'].append('SSH is using the default port')
                    else:
                        check_results['ok'].append('SSH is not using the default port')
                else:
                    check_results['low'].append('SSH is using the default port')

        return check_results


Mostly, the code is self-explanatory. The following are the list of the attributes and methods
that each HnTool module must have:

 * self.short_name
	String containing a short name of the module. Usually,this is the
	same as the basename of the module file.

 * self.long_name
	String containing a concise description of the module. This
	description is used when listing all the rules using hntool -l.

 * analyze(self)
	Should return a list comprising in turn of five lists: ok, low, medium,
	high and info.

 * self.type
	"files" or "config" for a module processing simple files and configs
	"services" for a module processing services and daemons
