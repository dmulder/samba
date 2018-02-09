# -*- coding: utf-8 -*-
import samba, os, random, sys
from samba import smb

PY3 = sys.version_info[0] == 3
addom = 'addom.samba.example.com/'
sysvolfile = os.path.join(addom,
                'Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI')
test_contents = 'abcd'*256
test_literal_contents = '\xff\xfe\x14\x61\x62\x63\x64'*256
utf_contents = u'Süßigkeiten Äpfel '*128
binary_contents = b'\xff\xfe\x53\xc3\xbc\xc3\x9f\x69\x67\x6b\x65\x69\x74\x65\x6e\x20\xc3\x84\x70\x66\x65\x6c\x20'*128
test_dir = os.path.join(addom, 'testing_%d' % random.randint(0,0xFFFF))
real_dir=os.path.join(os.environ["PREFIX"], os.path.join(os.environ["ENVNAME"], os.path.join('statedir', os.path.join('sysvol',test_dir))))

class SMBTests(samba.tests.TestCase):
    def setUp(self):
        super(SMBTests, self).setUp()
        self.server = os.environ["SERVER"]
        creds = self.insta_creds(template=self.get_credentials())
        self.conn = smb.SMB(self.server,
                            "sysvol",
                            lp=self.get_loadparm(),
                            creds=creds)

    def tearDown(self):
        global test_dir
        super(SMBTests, self).tearDown()
        try:
            self.conn.deltree(test_dir)
        except:
            pass

    def test_list(self):
        global addom
        ls = [f['name'] for f in self.conn.list(addom)]
        assert 'scripts' in ls, '"scripts" directory not found in sysvol'
        assert 'Policies' in ls, '"Policies" directory not found in sysvol'

    def test_save_load(self):
        global test_dir, test_contents, utf_contents
        self.conn.mkdir(test_dir)
        test_file = os.path.join(test_dir, 'testing').replace('/', '\\')

        self.conn.savefile(test_file, test_contents)
        contents = self.conn.loadfile(test_file)
        assert contents == test_contents, \
            'contents of test file did not match what was written'

        self.conn.savefile(test_file, test_literal_contents)
        contents = self.conn.loadfile(test_file)
        assert contents == test_literal_contents, \
            'contents of test file did not match what was written'

        if PY3:
            from io import open
            self.conn.savefile(test_file, utf_contents)
            contents = self.conn.loadfile(test_file)
            assert contents == utf_contents, \
                'contents of test file did not match what was written'
            real_file = os.path.join(real_dir, 'testing')

            # we can't use smb.savefile to write some non string content
            # we need to write to the file directly instead
            f = open(real_file, 'wb')
            f.write(binary_contents)
            f.close()
            contents = self.conn.loadfile(test_file)
            assert contents == binary_contents, \
                'contents of test file did not match what was written'
