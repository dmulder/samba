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

'''This class takes the .inf file parameter (Essentially a GPO file mapped to a GUID), hashmaps it to the Samba parameter, which then uses an ldb object to update the parameter to Samba4. Non Registry oriented whatsoever'''
class inf_to_ldb(object):
    def __init__(self, ldb, dn, attribute, val):
        self.ldb = ldb
        self.dn = dn
        self.attribute = attribute
        self.val = val

    def ch_minPwdAge(self, val):
        #print 'Old value of Minimum Password age = %s' % self.ldb.get_minPwdAge()
        self.ldb.set_minPwdAge(val)
        #print 'New value of Minimum Password age = %s' % self.ldb.get_minPwdAge()

    def ch_maxPwdAge(self, val):
        #print 'Old value of Maximum Password age = %s' % self.ldb.get_maxPwdAge()
        self.ldb.set_maxPwdAge(val)
        #print 'New value of Maximum Password age = %s' % self.ldb.get_maxPwdAge()

    def ch_minPwdLength(self, val):
        #print 'Password Min length before is %s ' % ldb.get_minPwdLength()
        self.ldb.set_minPwdLength(val)
        #print 'Password Min length after is %s ' % ldb.get_minPwdLength()

    def ch_pwdProperties(self, val):
        #print 'Old value of Minimum Password age = %s' % self.ldb.get_minPwdAge()
        self.ldb.set_pwdProperties(val)
        #print 'New value of Minimum Password age = %s' % self.ldb.get_minPwdAge()

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

    '''ldap value : samba setter'''
    def mapper(self):
        return { "minPwdAge" : (self.ch_minPwdAge, self.nttime2unix),
                 "maxPwdAge" : (self.ch_maxPwdAge, self.nttime2unix),
                 "minPwdLength" : (self.ch_minPwdLength, self.explicit), # Could be none, but I like the method assignment in update_samba
                 "pwdProperties" : (self.ch_pwdProperties, self.explicit),

               }

    def update_samba(self):
        (upd_sam, value) = self.mapper().get(self.attribute)
        upd_sam( value() )     # or val = value() then update(val)


'''This class does 2 things. 1) Identifies the GPO if it has a certain kind of filepath, 2) Finally parses it. '''
class gp_sec_ext(gp_ext):
    count = 0
    def __str__(self):
        return "Security GPO extension"

    def list(self, rootpath):
        path = "%s/%s" % (rootpath, "/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf")
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
                                  "PasswordComplexity": ("pwdProperties", inf_to_ldb),
                                 }
               }
#FIXME. EACH gpo should have a parser, and a creater. Essentially a gpo is just a file. Possibly a method and class to link it to organization unit (if that already does not exist) so that GPO's can be created arithmetically, possibly with a hashtable for certain GPO, then linked if desired. Also could store a backup folder of gpo's and then configure them without necessarily deploying it.

    def read_inf(self, path):
        inftable = self.populate_inf()
        '''The inf file to be mapped'''
        policy = codecs.open(path, encoding='utf-16')
        if not policy:
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
                if current_section.get(key):
                    (att, setter) = current_section.get(key)
                    value = value.encode('ascii', 'ignore')
                    setter(self.ldb, self.dn, att, value).update_samba()
    #FIXME read registry files (.pol). Can they ever apply? Define read_registry():

    def parse(self, afile, ldb):
        self.ldb = ldb
        self.dn = ldb.get_default_basedn()
        if afile.endswith('inf'):
            self.read_inf(afile)

class samba4_gpo_hierarchy(object):

    def __init__(self, SamDB, sysvol_guid_list, DC_OU, GLOBAL_DN):
        """
        :param SamDB: An instance of the live samba database
        :param sysvol_guid_list: The complete list of all GPO GUID's listed in sysvol folder
        :param DC_OU: The respective distinguished name of the Domain Controller
        :param GLOBAL_DN: The Domain DN that Samba is a part of
        """
        self.SamDB = SamDB
        self.GUID_L = sysvol_guid_list
        self.DC_OU = DC_OU
        self.GL_DN = GLOBAL_DN
        self.sorted_containers = []
        self.sorted_full = []
        self.indexed_places = []
        self.unapplied_gpo = 0

    def update_unapplied_gpo(self):
        self.update_unapplied_gpo += 1

    '''Returns list of int indexes to where the dn changes'''
    def container_indexes(self):
        count = 0
        container_indexes = []
        while count < (len(self.GUID_L)-1):
            if self.sorted_containers[count][2] != self.sorted_containers[count+1][2]:
                container_indexes.append(count+1)
            count += 1
        container_indexes.append(len(self.sorted_containers))
        return container_indexes


    def establish_hierarchy(self):
        final_list = []
        count_unapplied_GPO = 0
        for GUID in self.GUID_L:
            container_iteration = 0
            applied = False # Assume first it is not applied
            gpo_realm = False # Realm only written on last call, if the GPO is linked to multiple places
            '''Get all of the linked information'''
            GPO_CONTAINERS = gpo_user.get_gpo_containers(self.SamDB, GUID)
            for GPO_CONTAINER in GPO_CONTAINERS:

                container_iteration +=1

                if self.DC_OU == str(GPO_CONTAINER.get('dn')):
                    applied = True
                    insert_gpo = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                    self.sorted_containers.append(insert_gpo)
                    break

                if self.GL_DN == str(GPO_CONTAINER.get('dn')) and (len(GPO_CONTAINERS) == 1):
                    gpo_realm = True
                    applied = True
                    #REALM_GPO = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                    #final_list.insert(count_unapplied_GPO, REALM_GPO)

                if self.GL_DN == str(GPO_CONTAINER.get('dn')) and (len(GPO_CONTAINERS) > 1):
                    gpo_realm = True
                    applied = True

                if container_iteration == len(GPO_CONTAINERS):
                    if gpo_realm == False:
                        insert_dud = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                        self.sorted_containers.insert(0, insert_dud)
                        self.count_unapplied_GPO()
                    else :
                        REALM_GPO = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                        self.sorted_containers.insert(count_unapplied_GPO, REALM_GPO)

        '''After GPO are sorted into containers, sort the containers themselves. But first append non-applicable GPO.'''
        self.indexed_places = self.container_indexes()
        count = 0
        unapplied_gpo = []
        self.sorted_full = []
        '''Append all empties to final from first change of container'''
        while count < self.indexed_places[0]:
            unapplied_gpo.append(self.sorted_containers[count])
            count += 1

        count = 0
        self.sorted_full += unapplied_gpo
        while count < (len(self.indexed_places)-1): # Already accounted for one in empties
            self.sorted_full += (sort_linked(self.SamDB, self.sorted_containers, self.indexed_places[count], self.indexed_places[count + 1]))
            count += 1


def scan_log(sysvol_path):
    a = open(sysvol_path, "r")
    data = {}
    for line in a.readlines():
        line = line.strip()
        (guid,version) = line.split(" ")
        data[guid] = int(version)
    return data

########################################################################################################################################
'''The hierarchy is as per MS http://msdn.microsoft.com/en-us/library/windows/desktop/aa374155%28v=vs.85%29.aspx. It does not care about local GPO, because GPO and snap ins are not made in Linux yet. It follows the linking order and children GPO are last written format. Also, couple further testing with call scripts entitled informant and informant2 that show the explicit returned hierarchically sorted list'''


'''So the original list will need to be seperated into containers. Returns indexed list of when the container changes after hierarchy'''
def container_indexes(GUID_LIST):
    count = 0
    container_indexes = []
    while count < (len(GUID_LIST)-1):
        if GUID_LIST[count][2] != GUID_LIST[count+1][2]:
            container_indexes.append(count+1)
        count += 1
    container_indexes.append(len(GUID_LIST))
    return container_indexes

'''So GPO in same level need to have link level. This takes a container and sorts it'''
def sort_linked(SAMDB, guid_list, start, end):
    containers = gpo_user.get_gpo_containers(SAMDB, guid_list[start][0])
    for right_container in containers:
        if right_container.get('dn') == guid_list[start][2]:
            break
    print 'the container is %s' % (right_container.get('dn'))
    gplink = str(right_container.get('gPLink'))
    gplink_split = gplink.split('[')
    linked_order = []
    ret_list = []
    for ldap_guid in gplink_split:
        linked_order.append(str(ldap_guid[10:48]))
    count = len(linked_order) - 1
    while count > 0:
        ret_list.append([linked_order[count], True, guid_list[start][2]])
        count -= 1
    return ret_list

   # Accepts sysvol parameters to return a hierarchically sorted list, with application flag indicators.


#A GPO may have a single or multiple links. Get all of the containers (OU, SITE, etc..) and return them'''
    #def get_gpo_containers( ) :
    #   return gpo_netcmd_user.get_gpo_containers(self.SamDB, self.GUID)

  #  def

'''Takes a list of GUID from gpo, and sorts them based on OU, and realm. See http://msdn.microsoft.com/en-us/library/windows/desktop/aa374155%28v=vs.85%29.aspx'''
def establish_hierarchy(SamDB, GUID_LIST, DC_OU, global_dn):
    final_list = []
    count_unapplied_GPO = 0
    for GUID in GUID_LIST:
        container_iteration = 0
        applied = False # Assume first it is not applied
        gpo_realm = False # Realm only written on last call, if the GPO is linked to multiple places
        '''A very important call. This gets all of the linked information'''
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
                #REALM_GPO = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                #final_list.insert(count_unapplied_GPO, REALM_GPO)


            if global_dn == str(GPO_CONTAINER.get('dn')) and (len(GPO_CONTAINERS) > 1):
                gpo_realm = True
                applied = True


            if container_iteration == len(GPO_CONTAINERS):
                if gpo_realm == False:
                    insert_dud = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                    final_list.insert(0, insert_dud)
                    count_unapplied_GPO += 1
                else :
                    REALM_GPO = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                    final_list.insert(count_unapplied_GPO, REALM_GPO)
    '''After GPO are sorted into containers, let's sort the containers themselves. But first we can get the GPO that we don't care about out of the way'''
    indexed_places = container_indexes(final_list)
    count = 0
    unapplied_gpo = []
    '''Sorted by container'''
    sorted_gpo_list = []
    '''Since the unapplied GPO are put at the front of the list, just once again append them to the linked container sorted list'''
    while count < indexed_places[0]:
        unapplied_gpo.append(final_list[count])
        count += 1
    count = 0
    sorted_gpo_list += unapplied_gpo
    '''A single container call gets the linked order for all GPO in container. So we need one call per container - > index of the Original list'''
    while count < (len(indexed_places)-1):
        sorted_gpo_list += (sort_linked(SamDB, final_list, indexed_places[count], indexed_places[count + 1]))
        count += 1
    return sorted_gpo_list
