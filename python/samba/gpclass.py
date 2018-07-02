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
import tdb
sys.path.insert(0, "bin/python")
from samba import NTSTATUSError
from ConfigParser import ConfigParser
from StringIO import StringIO
from abc import ABCMeta, abstractmethod
import xml.etree.ElementTree as etree
import re
from samba.net import Net
from samba.dcerpc import nbt
from samba import smb
import samba.gpo as gpo
from samba.param import LoadParm
from uuid import UUID

try:
    from enum import Enum
    GPOSTATE = Enum('GPOSTATE', 'APPLY ENFORCE UNAPPLY')
except ImportError:
    class GPOSTATE:
        APPLY = 1
        ENFORCE = 2
        UNAPPLY = 3

class gp_log:
    ''' Log settings overwritten by gpo apply
    The gp_log is an xml file that stores a history of gpo changes (and the
    original setting value).

    The log is organized like so:

<gp>
    <user name="KDC-1$">
        <applylog>
            <guid count="0" value="{31B2F340-016D-11D2-945F-00C04FB984F9}" />
        </applylog>
        <guid value="{31B2F340-016D-11D2-945F-00C04FB984F9}">
            <gp_ext name="System Access">
                <attribute name="minPwdAge">-864000000000</attribute>
                <attribute name="maxPwdAge">-36288000000000</attribute>
                <attribute name="minPwdLength">7</attribute>
                <attribute name="pwdProperties">1</attribute>
            </gp_ext>
            <gp_ext name="Kerberos Policy">
                <attribute name="ticket_lifetime">1d</attribute>
                <attribute name="renew_lifetime" />
                <attribute name="clockskew">300</attribute>
            </gp_ext>
        </guid>
    </user>
</gp>

    Each guid value contains a list of extensions, which contain a list of
    attributes. The guid value represents a GPO. The attributes are the values
    of those settings prior to the application of the GPO.
    The list of guids is enclosed within a user name, which represents the user
    the settings were applied to. This user may be the samaccountname of the
    local computer, which implies that these are machine policies.
    The applylog keeps track of the order in which the GPOs were applied, so
    that they can be rolled back in reverse, returning the machine to the state
    prior to policy application.
    '''
    def __init__(self, user, gpostore, db_log=None):
        ''' Initialize the gp_log
        param user          - the username (or machine name) that policies are
                              being applied to
        param gpostore      - the GPOStorage obj which references the tdb which
                              contains gp_logs
        param db_log        - (optional) a string to initialize the gp_log
        '''
        self._state = GPOSTATE.APPLY
        self.gpostore = gpostore
        self.username = user
        if db_log:
            self.gpdb = etree.fromstring(db_log)
        else:
            self.gpdb = etree.Element('gp')
        self.user = user
        user_obj = self.gpdb.find('user[@name="%s"]' % user)
        if user_obj is None:
            user_obj = etree.SubElement(self.gpdb, 'user')
            user_obj.attrib['name'] = user

    def state(self, value):
        ''' Policy application state
        param value         - APPLY, ENFORCE, or UNAPPLY

        The behavior of the gp_log depends on whether we are applying policy,
        enforcing policy, or unapplying policy. During an apply, old settings
        are recorded in the log. During an enforce, settings are being applied
        but the gp_log does not change. During an unapply, additions to the log
        should be ignored (since function calls to apply settings are actually
        reverting policy), but removals from the log are allowed.
        '''
        # If we're enforcing, but we've unapplied, apply instead
        if value == GPOSTATE.ENFORCE:
            user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
            apply_log = user_obj.find('applylog')
            if apply_log is None or len(apply_log) == 0:
                self._state = GPOSTATE.APPLY
            else:
                self._state = value
        else:
            self._state = value

    def set_guid(self, guid):
        ''' Log to a different GPO guid
        param guid          - guid value of the GPO from which we're applying
                              policy
        '''
        self.guid = guid
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        obj = user_obj.find('guid[@value="%s"]' % guid)
        if obj is None:
            obj = etree.SubElement(user_obj, 'guid')
            obj.attrib['value'] = guid
        if self._state == GPOSTATE.APPLY:
            apply_log = user_obj.find('applylog')
            if apply_log is None:
                apply_log = etree.SubElement(user_obj, 'applylog')
            item = etree.SubElement(apply_log, 'guid')
            item.attrib['count'] = '%d' % (len(apply_log)-1)
            item.attrib['value'] = guid

    def apply_log_pop(self):
        ''' Pop a GPO guid from the applylog
        return              - last applied GPO guid

        Removes the GPO guid last added to the list, which is the most recently
        applied GPO.
        '''
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        apply_log = user_obj.find('applylog')
        if apply_log is not None:
            ret = apply_log.find('guid[@count="%d"]' % (len(apply_log)-1))
            if ret is not None:
                apply_log.remove(ret)
                return ret.attrib['value']
            if len(apply_log) == 0 and apply_log in user_obj:
                user_obj.remove(apply_log)
        return None

    def store(self, gp_ext_name, attribute, old_val):
        ''' Store an attribute in the gp_log
        param gp_ext_name   - Name of the extension applying policy
        param attribute     - The attribute being modified
        param old_val       - The value of the attribute prior to policy
                              application
        '''
        if self._state == GPOSTATE.UNAPPLY or self._state == GPOSTATE.ENFORCE:
            return None
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        guid_obj = user_obj.find('guid[@value="%s"]' % self.guid)
        assert guid_obj is not None, "gpo guid was not set"
        ext = guid_obj.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is None:
            ext = etree.SubElement(guid_obj, 'gp_ext')
            ext.attrib['name'] = gp_ext_name
        attr = ext.find('attribute[@name="%s"]' % attribute)
        if attr is None:
            attr = etree.SubElement(ext, 'attribute')
            attr.attrib['name'] = attribute
            attr.text = old_val

    def retrieve(self, gp_ext_name, attribute):
        ''' Retrieve a stored attribute from the gp_log
        param gp_ext_name   - Name of the extension which applied policy
        param attribute     - The attribute being retrieved
        return              - The value of the attribute prior to policy
                              application
        '''
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        guid_obj = user_obj.find('guid[@value="%s"]' % self.guid)
        assert guid_obj is not None, "gpo guid was not set"
        ext = guid_obj.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is not None:
            attr = ext.find('attribute[@name="%s"]' % attribute)
            if attr is not None:
                return attr.text
        return None

    def list(self, gp_extensions):
        ''' Return a list of attributes, their previous values, and functions
            to set them
        param gp_extensions - list of extension objects, for retrieving attr to
                              func mappings
        return              - list of (attr, value, apply_func) tuples for
                              unapplying policy
        '''
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        guid_obj = user_obj.find('guid[@value="%s"]' % self.guid)
        assert guid_obj is not None, "gpo guid was not set"
        ret = []
        data_maps = {}
        for gp_ext in gp_extensions:
            data_maps.update(gp_ext.apply_map())
        exts = guid_obj.findall('gp_ext')
        if exts is not None:
            for ext in exts:
                attrs = ext.findall('attribute')
                for attr in attrs:
                    func = None
                    if attr.attrib['name'] in data_maps[ext.attrib['name']]:
                        func = data_maps[ext.attrib['name']]\
                               [attr.attrib['name']][-1]
                    else:
                        for dmap in data_maps[ext.attrib['name']].keys():
                            if data_maps[ext.attrib['name']][dmap][0] == \
                               attr.attrib['name']:
                                func = data_maps[ext.attrib['name']][dmap][-1]
                                break
                    ret.append((attr.attrib['name'], attr.text, func))
        return ret

    def get_applied(self):
        ''' Return a list of applied ext guids
        return              - List of tuples containing the guid of a gpo, then
                              a dictionary of policies and their values prior
                              policy application. These are sorted so that the
                              most recently applied settings are removed first.
        '''
        guids = []
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        if user_obj is not None:
            apply_log = user_obj.find('applylog')
            if apply_log is None:
                return guids
            for i in reversed(range(0, len(apply_log))):
                guid_obj = apply_log.find('guid[@count="%d"]' % i)
                guid = guid_obj.attrib['value']
                guid_settings = user_obj.find('guid[@value="%s"]' % guid)
                exts = guid_settings.findall('gp_ext')
                settings = {}
                for ext in exts:
                    attr_dict = {}
                    attrs = ext.findall('attribute')
                    for attr in attrs:
                        attr_dict[attr.attrib['name']] = attr.text
                    settings[ext.attrib['name']] = attr_dict
                guids.append((guid, settings))
        return guids

    def delete(self, gp_ext_name, attribute):
        ''' Remove an attribute from the gp_log
        param gp_ext_name   - name of extension from which to remove the
                              attribute
        param attribute     - attribute to remove
        '''
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        guid_obj = user_obj.find('guid[@value="%s"]' % self.guid)
        assert guid_obj is not None, "gpo guid was not set"
        ext = guid_obj.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is not None:
            attr = ext.find('attribute[@name="%s"]' % attribute)
            if attr is not None:
                ext.remove(attr)
                if len(ext) == 0:
                    guid_obj.remove(ext)

    def commit(self):
        ''' Write gp_log changes to disk '''
        self.gpostore.store(self.username, etree.tostring(self.gpdb, 'utf-8'))

class GPOStorage:
    def __init__(self, log_file):
        if os.path.isfile(log_file):
            self.log = tdb.open(log_file)
        else:
            self.log = tdb.Tdb(log_file, 0, tdb.DEFAULT, os.O_CREAT|os.O_RDWR)

    def start(self):
        self.log.transaction_start()

    def get_int(self, key):
        try:
            return int(self.log.get(key))
        except TypeError:
            return None

    def get(self, key):
        return self.log.get(key)

    def get_gplog(self, user):
        return gp_log(user, self, self.log.get(user))

    def store(self, key, val):
        self.log.store(key, val)

    def cancel(self):
        self.log.transaction_cancel()

    def delete(self, key):
        self.log.delete(key)

    def commit(self):
        self.log.transaction_commit()

    def __del__(self):
        self.log.close()

class gp_ext(object):
    __metaclass__ = ABCMeta

    def __init__(self, logger, lp, creds, store):
        self.logger = logger
        self.lp = lp
        self.creds = creds
        self.gp_db = store.get_gplog(creds.get_username())

    @abstractmethod
    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):
        pass

    @abstractmethod
    def read(self, policy):
        pass

    def parse(self, afile):
        local_path = self.lp.cache_path('gpo_cache')
        data_file = os.path.join(local_path, check_safe_path(afile)).lower()
        if os.path.exists(data_file):
            return self.read(open(data_file, 'r').read())
        return None

    @abstractmethod
    def __str__(self):
        pass

class gp_ext_setter():
    __metaclass__ = ABCMeta

    def __init__(self, logger, gp_db, lp, attribute, val):
        self.logger = logger
        self.attribute = attribute
        self.val = val
        self.lp = lp
        self.gp_db = gp_db

    def explicit(self):
        return self.val

    def update_samba(self):
        (upd_sam, value) = self.mapper().get(self.attribute)
        upd_sam(value())

    @abstractmethod
    def mapper(self):
        pass

    def delete(self):
        upd_sam, _ = self.mapper().get(self.attribute)
        upd_sam(self.val)

    @abstractmethod
    def __str__(self):
        pass

class gp_inf_ext(gp_ext):
    @abstractmethod
    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):
        pass

    def read(self, policy):
        inf_conf = ConfigParser()
        inf_conf.optionxform=str
        try:
            inf_conf.readfp(StringIO(policy))
        except:
            inf_conf.readfp(StringIO(policy.decode('utf-16')))
        return inf_conf

    @abstractmethod
    def __str__(self):
        pass

''' Fetch the hostname of a writable DC '''
def get_dc_hostname(creds, lp):
    net = Net(creds=creds, lp=lp)
    cldap_ret = net.finddc(domain=lp.get('realm'), flags=(nbt.NBT_SERVER_LDAP |
        nbt.NBT_SERVER_DS))
    return cldap_ret.pdc_dns_name

''' Fetch a list of GUIDs for applicable GPOs '''
def get_gpo_list(dc_hostname, creds, lp):
    gpos = []
    ads = gpo.ADS_STRUCT(dc_hostname, lp, creds)
    if ads.connect():
        gpos = ads.get_gpo_list(creds.get_username())
    return gpos

FILE_ATTRIBUTE_DIRECTORY = 0x10
def cache_gpo_dir(conn, cache, sub_dir):
    loc_sub_dir = sub_dir.lower()
    try:
        os.makedirs(os.path.join(cache, loc_sub_dir), mode=0o755)
    except OSError:
        pass # File Exists
    for fdata in conn.list(sub_dir):
        if fdata['attrib'] & FILE_ATTRIBUTE_DIRECTORY:
            cache_gpo_dir(conn, cache, os.path.join(sub_dir, fdata['name']))
        else:
            local_name = fdata['name'].lower()
            with open(os.path.join(cache, loc_sub_dir, local_name), 'w') as f:
                fname = os.path.join(sub_dir, fdata['name']).replace('/', '\\')
                f.write(conn.loadfile(fname))

def check_safe_path(path):
    if 'sysvol' in path:
        dirs = re.split('/|\\\\', path)
        dirs = dirs[dirs.index('sysvol')+1:]
        if not '..' in dirs:
            return os.path.join(*dirs)
    raise OSError(path)

def check_refresh_gpo_list(dc_hostname, lp, creds, gpos):
    conn = smb.SMB(dc_hostname, 'sysvol', lp=lp, creds=creds, sign=True)
    cache_path = lp.cache_path('gpo_cache')
    for gpo in gpos:
        if not gpo.file_sys_path:
            continue
        cache_gpo_dir(conn, cache_path, check_safe_path(gpo.file_sys_path))

def gpo_version(lp, path):
    # gpo.gpo_get_sysvol_gpt_version() reads the GPT.INI from a local file,
    # read from the gpo client cache.
    gpt_path = lp.cache_path(os.path.join('gpo_cache', path))
    return int(gpo.gpo_get_sysvol_gpt_version(gpt_path)[1])

def apply_gp(lp, creds, logger, store, gp_extensions):
    gp_db = store.get_gplog(creds.get_username())
    dc_hostname = get_dc_hostname(creds, lp)
    gpos = get_gpo_list(dc_hostname, creds, lp)
    try:
        check_refresh_gpo_list(dc_hostname, lp, creds, gpos)
    except:
        logger.error('Failed downloading gpt cache from \'%s\' using SMB' \
            % dc_hostname)
        return

    changed_gpos = []
    for gpo_obj in gpos:
        if not gpo_obj.file_sys_path:
            continue
        guid = gpo_obj.name
        path = check_safe_path(gpo_obj.file_sys_path.lower())
        version = gpo_version(lp, path)
        if version != store.get_int(guid):
            logger.info('GPO %s has changed' % guid)
            changed_gpos.append(gpo_obj)

    store.start()
    for ext in gp_extensions:
        try:
            ext.process_group_policy([], changed_gpos)
        except Exception as e:
            logger.error('Failed to apply extension  %s' % str(ext))
            logger.error('Message was: ' + str(e))
            continue
    for gpo_obj in gpos:
        if not gpo_obj.file_sys_path:
            continue
        guid = gpo_obj.name
        path = check_safe_path(gpo_obj.file_sys_path.lower())
        version = gpo_version(lp, path)
        store.store(guid, '%i' % version)
    store.commit()

def unapply_gp(lp, creds, logger, store, gp_extensions):
    gp_db = store.get_gplog(creds.get_username())
    gp_db.state(GPOSTATE.UNAPPLY)
    del_gpos = gp_db.get_applied() # Treat all applied gpos as deleted
    store.start()
    for ext in gp_extensions:
        try:
            ext.process_group_policy(del_gpos, [])
        except Exception as e:
            logger.error('Failed to unapply extension  %s' % str(ext))
            logger.error('Message was: ' + str(e))
            continue
    store.commit()

def register_gp_extension(guid, name, path,
                          smb_conf=None, machine=True, user=True):
    # Check that the module exists
    if not os.path.exists(path):
        return False
    # Check for valid guid
    if not guid[0] == '{' or not guid[-1] == '}':
        return False
    try:
        uuid = guid[1:-1]
        UUID(uuid, version=4)
    except:
        return False

    lp = LoadParm()
    if smb_conf is not None:
        lp.load(smb_conf)
    else:
        lp.load_default()
    ext_conf = lp.state_path('gpext.conf')
    parser = ConfigParser()
    parser.read(ext_conf)
    if not guid in parser.sections():
        parser.add_section(guid)
    parser.set(guid, 'DllName', path)
    parser.set(guid, 'ProcessGroupPolicy', name)
    parser.set(guid, 'NoMachinePolicy', 0 if machine else 1)
    parser.set(guid, 'NoUserPolicy', 0 if user else 1)

    f = open(ext_conf, 'w')
    parser.write(f)
    f.close()

    return True

def list_gp_extensions(smb_conf=None):
    lp = LoadParm()
    if smb_conf is not None:
        lp.load(smb_conf)
    else:
        lp.load_default()
    ext_conf = lp.state_path('gpext.conf')
    parser = ConfigParser()
    parser.read(ext_conf)

    results = {}
    for guid in parser.sections():
        results[guid] = {}
        results[guid]['DllName'] = parser.get(guid, 'DllName')
        results[guid]['ProcessGroupPolicy'] = \
            parser.get(guid, 'ProcessGroupPolicy')
        results[guid]['MachinePolicy'] = \
            not int(parser.get(guid, 'NoMachinePolicy'))
        results[guid]['UserPolicy'] = not int(parser.get(guid, 'NoUserPolicy'))
    return results

def unregister_gp_extension(guid, smb_conf=None):
    # Check for valid guid
    if not guid[0] == '{' or not guid[-1] == '}':
        return False
    try:
        uuid = guid[1:-1]
        UUID(uuid, version=4)
    except:
        return False

    lp = LoadParm()
    if smb_conf is not None:
        lp.load(smb_conf)
    else:
        lp.load_default()
    ext_conf = lp.state_path('gpext.conf')
    parser = ConfigParser()
    parser.read(ext_conf)

    if guid in parser.sections():
        parser.remove_section(guid)

    f = open(ext_conf, 'w')
    parser.write(f)
    f.close()

    return True
