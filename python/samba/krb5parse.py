#!/usr/bin/python
from ConfigParser import ConfigParser, ParsingError, DuplicateSectionError, MissingSectionHeaderError
import re

krb5_dot_conf = '/etc/krb5.conf'

class KRB5Parser():
    def __init__(self, fname):
        self.dict = {}
        self.sects = []
        self.fname = fname
        self._read()

    def _read(self):
        _SECT_TMPL = r"""\s*(?P<outerhead>\[(?P<header>[^]]+)\])"""
        conf = open(self.fname).read()
        headers = re.compile(_SECT_TMPL)
        section_splits = []
        for mo in headers.finditer(conf):
            section_splits.append(mo.start('outerhead'))
            self.sects.append(mo.group('header'))
        for i in range(0, len(self.sects)-1):
            self.dict[self.sects[i]] = conf[section_splits[i]:section_splits[i+1]]
        self.dict[self.sects[-1]] = conf[section_splits[-1]:]

    def sections(self):
        return self.sects

    def add_section(self, section):
        self.sects.append(section)
        self.dict[section] = ''

    def set(self, section, option, value):
        _OPT_TMPL = r"""\s*(%s\s*=\s*.*)\s*""" % option
        opts = re.compile(_OPT_TMPL)
        index = None
        while True:
            mo = opts.search(self.dict[section])
            if not mo:
                break
            index = mo.start(1)
            length = len(mo.group(1))
            self.dict[section] = self.dict[section][0:index] + self.dict[section][index+length:]
        if index:
            self.dict[section] = self.dict[section][:index] + ('%s = %s' % (option, value)) + self.dict[section][index:]
        else:
            self.dict[section] = self.dict[section].strip() + ('\n\t%s = %s\n\n' % (option, value))

    def write(self):
        with open(self.fname, 'w') as conf:
            for section in self.sects:
                conf.write(self.dict[section])

def set_krb5_conf_opt(section, option, value):
    global krb5_dot_conf
    krb5_conf = KRB5Parser(krb5_dot_conf)
    if section not in krb5_conf.sections():
        krb5_conf.add_section(section)
    krb5_conf.set(section, option, value)
    krb5_conf.write()

