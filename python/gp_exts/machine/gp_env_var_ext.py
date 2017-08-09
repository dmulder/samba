from samba.gpclass import gp_ext, file_to
from samba.gp_file_append import ini_file_append
import xml.etree.ElementTree as etree
import re, os, os.path

sysconfdir = 'st/ad_dc/etc'

class xml_to_env(file_to):

    def set_env_var(self, val):
        global sysconfdir
        if type(val) is not dict:
            val = { 'value': val, 'action': 'U' }

        # MS PATH variable is seperated by ';', which if placed in a posix
        # PATH causes everything after the ';' to be executed, which is not
        # what we intend. So, ignore PATH variables that contain ';'. Also
        # ensure the first character in the PATH is something valid (rather
        # than C:\ or something).
        if val['value'] and self.attribute == 'PATH' and \
           (';' in val['value'] or \
           val['value'][0] not in ['/', '$', '~', '.']):
            self.logger.info('Ignored PATH variable assignment due to it\'s' +\
                ' similarity to a Windows PATH: %s' % val['value'])
            return

        profile = ini_file_append(os.path.join(sysconfdir, 'profile'))

        old_val = profile[self.attribute]
        self.logger.info('Environment Variable %s was changed from %s to %s' \
                         % (self.attribute, old_val, val['value']))

        if val['value'] == None:
            del profile[self.attribute]
        # Update, Replace, and Create all really do the same thing
        elif val['action'] == 'U' or \
             val['action'] == 'R' or \
             val['action'] == 'C':
            if self.attribute == 'PATH' and \
               'partial' in val and \
               val['partial'] == '1':
                profile[self.attribute] = '$PATH:%s' % val['value']
            else:
                profile[self.attribute] = val['value']
        # Remove should blank the variable
        elif val['action'] == 'D':
            profile[self.attribute] = ''

        self.gp_db.store(str(self), self.attribute, old_val)

    def mapper(self):
        return self

    def __getitem__(self, key):
        return (self.set_env_var, self.explicit)

    def __str__(self):
        return 'Environment'

class env_var_unapply_map:
    def __getitem__(self, key):
        return (key, xml_to_env)

    def __contains__(self, key):
        return True

class gp_environment_variable_ext(gp_ext):

    def list(self, rootpath):
        return os.path.join(rootpath,
           'MACHINE/Preferences/EnvironmentVariables/EnvironmentVariables.xml')

    def apply_map(self):
        if not hasattr(self, 'xml_conf'):
            return { 'Environment' : env_var_unapply_map() }
        else:
            return {
                'Environment' : {
                    a.attrib['name']: (a.attrib['name'], xml_to_env) \
                        for a in self.xml_conf.findall('EnvironmentVariable')
                }
            }

    def read(self, policy):
        self.xml_conf = etree.fromstring(policy)
        apply_map = self.apply_map()['Environment']
        ret = False

        for env_var in self.xml_conf.findall('EnvironmentVariable'):
            (att, setter) = apply_map.get(env_var.attrib['name'])
            ret = True
            setter(self.logger,
                   self.ldb,
                   self.gp_db,
                   self.lp,
                   self.creds,
                   att,
                   env_var.find('Properties').attrib).update_samba()
            self.gp_db.commit()
        return ret

    def __str__(self):
        return 'Environment GPO extension'

    @staticmethod
    def disabled_file():
        return os.path.splitext(os.path.abspath(__file__))[0] + '.py.disabled'

