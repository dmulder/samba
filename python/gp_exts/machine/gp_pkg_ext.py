from samba.gpclass import gp_ext, file_to, rootpath_to_dn
from subprocess import Popen, PIPE

class package_installer(file_to):

    def install_pkg(self, val):
        local_path = os.path.join(self.lp.get('cache directory'), 'gpt', val)
        if not os.path.exists(os.path.dirname(local_path)):
            os.makedirs(os.path.dirname(local_path))
        # is this right? this is writing binary, not text
        data = conn.loadfile(val)
        encoding = chardet.detect(data)
        open(local_path, 'w').write(data.decode(encoding['encoding']))
        p = Popen(['rpm', '-i', local_path], stdout=PIPE, stderr=PIPE)
        ret = p.communicate()
        if p.returncode != 0:
            self.logger.error('\n'.join(ret))
        else:
            self.gp_db.store(str(self), self.attribute, None)

    def to_int(self):
        return int(self.val)

    def mapper(self):
        return { 'install' : (self.install_pkg, self.explicit),
               }

    def __str__(self):
        return "Package"

class gp_pkg_ex(gp_ext):
    expression = '(objectCategory=packageRegistration)'

    def __str__(self):
        return "RPM package extension"

    def read(self, policy):
        mappings = self.apply_map()

        for pkg in policy:
            att, setter = mappings['Package'].get('msiScriptPath')
            values = set(pkg['msiScriptPath'])
            assert len(values) == 1
            setter(self.logger,
                   self.ldb,
                   self.gp_db,
                   self.lp,
                   None,
                   att,
                   values.pop()).update_samba()
            self.gp_db.commit()

    def list(self, rootpath):
        return 'CN=Packages,CN=Class Store,CN=Machine,%s' % \
            rootpath_to_dn(rootpath)

    def apply_map(self):
        return { "Package" : { "msiScriptPath" : ('install', package_installer),
                             }
               }

    @staticmethod
    def disabled_file():
        return os.path.splitext(os.path.abspath(__file__))[0] + '.py.disabled'

