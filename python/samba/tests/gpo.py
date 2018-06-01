# Unix SMB/CIFS implementation. Tests for smb manipulation
# Copyright (C) David Mulder <dmulder@suse.com> 2018
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

import os
from samba import gpo, tests
from samba.param import LoadParm
import ldap, ldap.sasl
from subprocess import Popen, PIPE

poldir = r'\\addom.samba.example.com\sysvol\addom.samba.example.com\Policies'
dspath = 'CN=Policies,CN=System,DC=addom,DC=samba,DC=example,DC=com'
gpt_data = '[General]\nVersion=%d'

def realm_to_dn(realm):
    return ','.join(['DC=%s' % part for part in realm.lower().split('.')])

def kinit_for_gssapi(creds):
    p = Popen(['kinit', creds.get_username()], stdin=PIPE, stdout=PIPE)
    p.stdin.write('%s\n' % creds.get_password())
    p.stdin.flush()
    return p.wait() == 0

def get_ldap(server, creds):
    l = ldap.initialize('ldap://%s' % server)
    if kinit_for_gssapi(creds):
        auth_tokens = ldap.sasl.gssapi('')
        l.sasl_interactive_bind_s('', auth_tokens)
        l.set_option(ldap.OPT_REFERRALS,0)
    return l

def set_gpo_version(server, lp, creds, guid, version):
    l = get_ldap(server, creds)
    realm = lp.get('realm')
    realm_dn = realm_to_dn(realm)
    dn = 'CN=%s,CN=Policies,CN=System,%s' % (guid, realm_dn)
    ldap_mod = [(1, 'versionNumber', None),
                (0, 'versionNumber', ['%d' % version])]

    l.modify_s(dn, ldap_mod)

    sysvol = lp.get("path", "sysvol")
    gpo_path = os.path.join(sysvol, realm.lower(), 'Policies', guid)
    with open(os.path.join(gpo_path, 'GPT.INI'), 'w') as gpt:
        gpt.write(gpt_data % version)

class GPOTests(tests.TestCase):
    def setUp(self):
        super(GPOTests, self).setUp()
        self.server = os.environ["SERVER"]
        self.lp = LoadParm()
        self.lp.load_default()
        self.creds = self.insta_creds(template=self.get_credentials())

    def tearDown(self):
        super(GPOTests, self).tearDown()

    def test_gpo_list(self):
        global poldir, dspath
        ads = gpo.ADS_STRUCT(self.server, self.lp, self.creds)
        if ads.connect():
            gpos = ads.get_gpo_list(self.creds.get_username())
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        names = ['Local Policy', guid]
        file_sys_paths = [None, '%s\\%s' % (poldir, guid)]
        ds_paths = [None, 'CN=%s,%s' % (guid, dspath)]
        for i in range(0, len(gpos)):
            assert gpos[i].name == names[i], \
              'The gpo name did not match expected name %s' % gpos[i].name
            assert gpos[i].file_sys_path == file_sys_paths[i], \
              'file_sys_path did not match expected %s' % gpos[i].file_sys_path
            assert gpos[i].ds_path == ds_paths[i], \
              'ds_path did not match expected %s' % gpos[i].ds_path


    def test_gpo_ads_does_not_segfault(self):
        try:
            ads = gpo.ADS_STRUCT(self.server, 42, self.creds)
        except:
            pass

    def test_gpt_version(self):
        global gpt_data
        local_path = self.lp.get("path", "sysvol")
        policies = 'addom.samba.example.com/Policies'
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        gpo_path = os.path.join(local_path, policies, guid)
        old_vers = gpo.gpo_get_sysvol_gpt_version(gpo_path)[1]

        with open(os.path.join(gpo_path, 'GPT.INI'), 'w') as gpt:
            gpt.write(gpt_data % 42)
        assert gpo.gpo_get_sysvol_gpt_version(gpo_path)[1] == 42, \
          'gpo_get_sysvol_gpt_version() did not return the expected version'

        with open(os.path.join(gpo_path, 'GPT.INI'), 'w') as gpt:
            gpt.write(gpt_data % old_vers)
        assert gpo.gpo_get_sysvol_gpt_version(gpo_path)[1] == old_vers, \
          'gpo_get_sysvol_gpt_version() did not return the expected version'

    def test_gpt_ext_register(self):
        ext_path = '/home/dmulder/code/samba/bin/python/samba/gp_sec_ext.py'
        ext_guid = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
        gpo.register_gp_extension(ext_guid, 'gp_sec_ext', ext_path,
                                  smb_conf=self.lp.configfile,
                                  machine=True, user=False)
        gp_exts = gpo.list_gp_extensions(self.lp.configfile)
        assert ext_guid in gp_exts.keys(), \
            'Failed to list gp exts from registry'
        assert gp_exts[ext_guid]['DllName'] == ext_path, \
            'Failed to list gp exts from registry'

        gpo.unregister_gp_extension(ext_guid)
        gp_exts = gpo.list_gp_extensions(self.lp.configfile)
        assert ext_guid not in gp_exts.keys(), \
            'Failed to unregister gp exts from registry'

    def test_check_refresh_gpo_list(self):
        # Increment version for {31B2F340-016D-11D2-945F-00C04FB984F9}
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        set_gpo_version(self.server, self.lp, self.creds, guid, 1)

        cache = self.lp.cache_path('gpo_cache')
        ads = gpo.ADS_STRUCT(self.server, self.lp, self.creds)
        if ads.connect():
            gpos = ads.get_gpo_list(self.creds.get_username())
        gpo.check_refresh_gpo_list(gpos, self.lp, self.creds, cache)

        assert os.path.exists(cache), 'GPO cache %s was not created' % cache

