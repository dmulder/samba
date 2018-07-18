# gp_smb_conf_ext smb.conf gpo policy
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

import os, re, numbers
from samba.gpclass import gp_ext_setter, gp_pol_ext
from tempfile import NamedTemporaryFile
from samba.compat import get_string, binary_type

def is_number(x):
    return isinstance(x, numbers.Number) and \
           type(x) != bool

class smb_conf_setter(gp_ext_setter):
    def set_smb_conf(self, val):
        old_val = self.lp.get(self.attribute)

        if isinstance(val, binary_type):
            val = get_string(val)
        if is_number(val) and is_number(old_val):
            val = str(val)
        elif is_number(val) and type(old_val) == bool:
            val = bool(val)
        if type(val) == bool:
            val = 'yes' if val else 'no'

        self.lp.set(self.attribute, val)
        with NamedTemporaryFile(delete=False,
                                dir=os.path.dirname(self.lp.configfile)) as f:
            tmp_conf = f.name
        self.lp.dump(False, tmp_conf)
        os.rename(tmp_conf, self.lp.configfile)

        self.logger.info('smb.conf [global] %s was changed from %s to %s' % \
                         (self.attribute, old_val, str(val)))

        if is_number(old_val):
            old_val = str(old_val)
        if type(old_val) == bool:
            old_val = 'yes' if old_val else 'no'
        self.gp_db.store(str(self), self.attribute, old_val)

    def mapper(self):
        return self

    def __getitem__(self, key):
        return (self.set_smb_conf, self.explicit)

    def get(self, key):
        return (self.set_smb_conf, self.explicit)

    def __str__(self):
        return "smb.conf"

class gp_smb_conf_ext(gp_pol_ext):
    def __str__(self):
        return "smb.conf Extension"

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):

        pol_file = 'MACHINE/Registry.pol'
        for gpo in deleted_gpo_list:
            self.gp_db.set_guid(gpo[0])
            for section in gpo[1].keys():
                if section != 'smb.conf':
                    continue
                for key, value in gpo[1][section].items():
                    value = value.encode('ascii', 'ignore')
                    smb_conf_setter(self.logger, self.gp_db, self.lp,
                                    self.creds, key, value).delete()
                    self.gp_db.delete(section, key)
                    self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section_name = 'Software\\Policies\\Samba\\smb_conf'
                self.gp_db.set_guid(gpo.name)
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue
                for e in pol_conf.entries:
                    if e.keyname != section_name:
                        continue
                    smb_conf_setter(self.logger, self.gp_db, self.lp,
                                    self.creds, e.valuename, e.data).update_samba()
                    self.gp_db.commit()
