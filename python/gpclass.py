#!/usr/bin/env python
# Copyright Luke Morrison <luc785@.hotmail.com> 2013

'''Reads important GPO parameters and updates Samba'''
import sys
import os
sys.path.insert(0, "bin/python")
import samba.gpo as gpo
import optparse
import ldb
from samba.auth import system_session
import samba.getopt as options
from samba.samdb import SamDB
import codecs

class gp_ext(object):
    def list(self, rootpath):
        return None

    def __str__(self):
        return "default_gp_ext"


class inf_to_ldb(object):
    def __init__(self, ldb, dn, attribute, val):
        self.ldb = ldb
        self.dn = dn
        self.attribute = attribute
        self.val = val

    def ch_minPwdAge(self, val):
        '''TODO change this to do only call prints on debugging option mode'''
        print 'Old value of Minimum Password age = %s' % self.ldb.get_minPwdAge()

        print 'New value of Minimum Password age = %s' % self.ldb.get_minPwdAge()


    def ch_minPwdLength(self, val):
        ldb = self.ldb
        ldb.set_minPwdLength(val)

    def nullstamp(self):
        return self.val

    def nttime2unix(self):
        seconds = 60
        minutes = 60
        hours = 24
        sam_add = 10000000
        val = (self.val)
        val = int(val)
        return  str(-(val * seconds * minutes * hours))

    def mapper(self):
        return { "minPwdAge" : (self.ch_minPwdAge, self.nttime2unix),
                 "maxPwdAge" : (self.ch_maxPwdAge, self.nttime2unix),
                 "minPwdLength" : (self.ch_minPwdLength, self.nullstamp)
               }

    def update_samba(self):
        (upd_sam, value) = self.mapper().get(self.attribute)
        upd_sam( value() )   #or val = value() then update(val)

class gp_sec_ext(gp_ext):
    count = 0
    def __str__(self):
        return "Security GPO extension"

    def list(self, rootpath):
        path = "%s/%s" % (rootpath, "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf")
        if os.path.exists(path):
            return path

    def listmachpol(self, rootpath):
        path = "%s/%s" % (rootpath, "Machine/Registry.pol")
        if os.path.exists(path):
            return path

    def listuserpol(self, rootpath):
        path = "%s/%s" % (rootpath, "User/Registry.pol")
        if os.path.exists(path):
            return path

    def populate_inf(self):
        return {"System Access": {"MinimumPasswordAge": ("minPwdAge", inf_to_ldb),
                                  "MaximumPasswordAge": ("maxPwdAge", inf_to_ldb),
                                  "MinimumPasswordLength": ("minPwdLength",inf_to_ldb),
                                  "PasswordComplexity": None
                                  }
               }

    def read_inf(self, path):
        inftable = self.populate_inf()
        # The inf file to be mapped
        policy = codecs.open(path, encoding='utf-16')
        if not policy:
        # 42
            return None
        current_section = None
        for line in policy.readlines():
            line = line.strip()
            if line[0] == '[':
                section = line[1: -1]
                current_section = inftable.get(section.encode('ascii','ignore'))

            else:
                # We must be in a section
                if not current_section:
                    continue
                (key, value) = line.split("=")
                key = key.strip()
                print "key = %s" % key
                if current_section.get(key):
                    print "ok I have to do something on with key %s" % key
                    (att, setter) = current_section.get(key)
                    value = value.encode('ascii', 'ignore')
                    setter(self.ldb, self.dn, att, value).update_samba()

    def parse(self, afile, ldb):
        self.ldb = ldb
        self.dn = ldb.get_default_basedn()
        print "Parsing file %s" % afile
        if afile.endswith('inf'):
            self.read_inf(afile)

# Finds all GPO Files ending in inf
def gp_path_list(path):

    GPO_LIST = []
    for ext in gp_extensions:
        GPO_LIST.append((ext, ext.list(path)))

    return GPO_LIST

# Reads the GPOs and sends them to their proper handlers
def gpo_parser(GPO_LIST, ldb):
    for entry in GPO_LIST:
        (ext, thefile) = entry
        ext.parse(thefile, ldb)
