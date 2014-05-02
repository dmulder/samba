#!/usr/bin/env python
#
# Reads important GPO parameters and updates Samba
# Copyright (C) Luke Morrison <luc785@.hotmail.com> 2013
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import sys
import os
sys.path.insert(0, "bin/python")
import samba.gpo as gpo
import optparse
import ldb
from samba.auth import system_session
import samba.getopt as options
from samba.samdb import SamDB
from samba.netcmd import gpo as gpo_user
import codecs

class gp_ext(object):
    def list(self, rootpath):
        return None

    def __str__(self):
        return "default_gp_ext"


class inf_to_ldb(object):
    '''This class takes the .inf file parameter (essentially a GPO file mapped to a GUID),
    hashmaps it to the Samba parameter, which then uses an ldb object to update the
    parameter to Samba4. Not registry oriented whatsoever.
    '''

    def __init__(self, ldb, dn, attribute, val):
        self.ldb = ldb
        self.dn = dn
        self.attribute = attribute
        self.val = val

    def ch_minPwdAge(self, val):
        self.ldb.set_minPwdAge(val)

    def ch_maxPwdAge(self, val):
        self.ldb.set_maxPwdAge(val)

    def ch_minPwdLength(self, val):
        self.ldb.set_minPwdLength(val)

    def ch_pwdProperties(self, val):
        self.ldb.set_pwdProperties(val)

    def explicit(self):
        return self.val

    def nttime2unix(self):
        seconds = 60
        minutes = 60
        hours = 24
        sam_add = 10000000
        val = (self.val)
        val = int(val)
        return  str(-(val * seconds * minutes * hours * sam_add))

    def mapper(self):
        '''ldap value : samba setter'''
        return { "minPwdAge" : (self.ch_minPwdAge, self.nttime2unix),
                 "maxPwdAge" : (self.ch_maxPwdAge, self.nttime2unix),
                 # Could be none, but I like the method assignment in update_samba
                 "minPwdLength" : (self.ch_minPwdLength, self.explicit),
                 "pwdProperties" : (self.ch_pwdProperties, self.explicit),

               }

    def update_samba(self):
        (upd_sam, value) = self.mapper().get(self.attribute)
        upd_sam(value())     # or val = value() then update(val)


class gp_sec_ext(gp_ext):
    '''This class does the following two things:
        1) Identifies the GPO if it has a certain kind of filepath,
        2) Finally parses it.
    '''

    count = 0

    def __str__(self):
        return "Security GPO extension"

    def list(self, rootpath):
        path = "%s%s" % (rootpath, "MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf")
        return path

    def listmachpol(self, rootpath):
        path = "%s%s" % (rootpath, "Machine/Registry.pol")
        return path

    def listuserpol(self, rootpath):
        path = "%s%s" % (rootpath, "User/Registry.pol")
        return path

    def populate_inf(self):
        return {"System Access": {"MinimumPasswordAge": ("minPwdAge", inf_to_ldb),
                                  "MaximumPasswordAge": ("maxPwdAge", inf_to_ldb),
                                  "MinimumPasswordLength": ("minPwdLength", inf_to_ldb),
                                  "PasswordComplexity": ("pwdProperties", inf_to_ldb),
                                 }
               }
#FIXME. EACH gpo should have a parser, and a creater. Essentially a gpo is just a file. Possibly a method and class to link it to organization unit (if that already does not exist) so that GPO's can be created arithmetically, possibly with a hashtable for certain GPO, then linked if desired. Also could store a backup folder of gpo's and then configure them without necessarily deploying it.

    def read_inf(self, path, conn, attr_log):
        inftable = self.populate_inf()
        try:
            policy = conn.loadfile(path).decode('utf-16')
        except:
            return None
        current_section = None
        LOG = open(attr_log, "a")
        LOG.write(str(path.split('/')[2]) + '\n')
        for line in policy.splitlines():
            line = line.strip()
            if line[0] == '[':
                section = line[1: -1]
                current_section = inftable.get(section.encode('ascii', 'ignore'))

            else:
                # We must be in a section
                if not current_section:
                    continue
                (key, value) = line.split("=")
                key = key.strip()
                if current_section.get(key):
                    (att, setter) = current_section.get(key)
                    value = value.encode('ascii', 'ignore')
                    # so value is the value that it contains, and the att is the attribute
                    LOG.write(att + ' ' + value + '\n')
                    # copy and paste this logic to backwalk deleted GPO
                    setter(self.ldb, self.dn, att, value).update_samba()

    def parse(self, afile, ldb, conn, attr_log):
        self.ldb = ldb
        self.dn = ldb.get_default_basedn()
        if afile.endswith('inf'):
            self.read_inf(afile, conn, attr_log)


def scan_log(sysvol_path):
    a = open(sysvol_path, "r")
    data = {}
    for line in a.readlines():
        line = line.strip()
        (guid, version) = line.split(" ")
        data[guid] = int(version)
    return data

# The hierarchy is as per MS http://msdn.microsoft.com/en-us/library/windows/desktop/aa374155%28v=vs.85%29.aspx
#
# It does not care about local GPO, because GPO and snap-ins are not made in Linux yet.
# It follows the linking order and children GPO are last written format.
#
# Also, couple further testing with call scripts entitled informant and informant2.
# They explicitly show the returned hierarchically sorted list.


def container_indexes(GUID_LIST):
    '''So the original list will need to be seperated into containers.
    Returns indexed list of when the container changes after hierarchy
    '''
    count = 0
    container_indexes = []
    while count < (len(GUID_LIST)-1):
        if GUID_LIST[count][2] != GUID_LIST[count+1][2]:
            container_indexes.append(count+1)
        count += 1
    container_indexes.append(len(GUID_LIST))
    return container_indexes


def sort_linked(SAMDB, guid_list, start, end):
    '''So GPO in same level need to have link level.
    This takes a container and sorts it.

    TODO:  Small small problem, it is backwards
    '''
    containers = gpo_user.get_gpo_containers(SAMDB, guid_list[start][0])
    for right_container in containers:
        if right_container.get('dn') == guid_list[start][2]:
            break
    gplink = str(right_container.get('gPLink'))
    gplink_split = gplink.split('[')
    linked_order = []
    ret_list = []
    for ldap_guid in gplink_split:
        linked_order.append(str(ldap_guid[10:48]))
    count = len(linked_order) - 1
    while count > 0:
        ret_list.append([linked_order[count], guid_list[start][1], guid_list[start][2]])
        count -= 1
    return ret_list


def establish_hierarchy(SamDB, GUID_LIST, DC_OU, global_dn):
    '''Takes a list of GUID from gpo, and sorts them based on OU, and realm.
    See http://msdn.microsoft.com/en-us/library/windows/desktop/aa374155%28v=vs.85%29.aspx
    '''
    final_list = []
    count_unapplied_GPO = 0
    for GUID in GUID_LIST:

        container_iteration = 0
        # Assume first it is not applied
        applied = False
        # Realm only written on last call, if the GPO is linked to multiple places
        gpo_realm = False

        # A very important call. This gets all of the linked information.
        GPO_CONTAINERS = gpo_user.get_gpo_containers(SamDB, GUID)
        for GPO_CONTAINER in GPO_CONTAINERS:

            container_iteration += 1

            if DC_OU == str(GPO_CONTAINER.get('dn')):
                applied = True
                insert_gpo = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                final_list.append(insert_gpo)
                break

            if global_dn == str(GPO_CONTAINER.get('dn')) and (len(GPO_CONTAINERS) == 1):
                gpo_realm = True
                applied = True


            if global_dn == str(GPO_CONTAINER.get('dn')) and (len(GPO_CONTAINERS) > 1):
                gpo_realm = True
                applied = True


            if container_iteration == len(GPO_CONTAINERS):
                if gpo_realm == False:
                    insert_dud = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                    final_list.insert(0, insert_dud)
                    count_unapplied_GPO += 1
                else:
                    REALM_GPO = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                    final_list.insert(count_unapplied_GPO, REALM_GPO)

    # After GPO are sorted into containers, let's sort the containers themselves.
    # But first we can get the GPO that we don't care about, out of the way.
    indexed_places = container_indexes(final_list)
    count = 0
    unapplied_gpo = []
    # Sorted by container
    sorted_gpo_list = []
    '''Since the unapplied GPO are put at the front of the list, just once again append them to the linked container sorted list'''
    while count < indexed_places[0]:
        unapplied_gpo.append(final_list[count])
        count += 1
    count = 0
    sorted_gpo_list += unapplied_gpo

    # A single container call gets the linked order for all GPO in container.
    # So we need one call per container - > index of the Original list
    while count < (len(indexed_places)-1):
        sorted_gpo_list += (sort_linked(SamDB, final_list, indexed_places[count], indexed_places[count+1]))
        count += 1
    return sorted_gpo_list
