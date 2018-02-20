#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Unix SMB/CIFS implementation. Tests for smb python bindings
# Copyright (C) David Mulder <dmulder@suse.com> 2017
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
#
import os
from samba import smb
import samba.tests
from samba.credentials import Credentials
from samba.tests import TestCase

TEXT = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

GREEK_TEXT = u"Λορεμ ιπσθμ δολορ σιτ αμετ, ινcορρθπτε εφφιcιενδι πρι ατ. Μθνδι σιμθλ περ εθ, μελ αδ ρεπθδιανδαε λιβεραvισσε, cθ vισ δεσερθντ εφφιcιαντθρ. Vιδιτ λαθδεμ ιθσ θτ, πθταντ θτροqθε αccθσατα ηισ νο. Ετ τολλιτ vολθπταρια δθο. Εθ qθασ ατqθι προ, θτ εθμ ανcιλλαε σενσιβθσ vιτθπερατοριβθσ. Μεα qθοδ αθτεμ αθδιρε αν, εαμ τε μεισ ηαρθμ ιισqθε. Ιθσ αν qθοδ νομιναvι, αδ ετιαμ δεσερθισσε vισ. Μεα ατ φαλλι ρεπθδιανδαε. Προ cθ γραεcι δολορεσ εθριπιδισ."

CHINESE_TEXT = u"助界北差読移開夜構横連社島挑部。速重木鳥学手学中煙転載告会梯月古点堀。数見時筋典北極誘記麗文面死駅味再止道。話混点係選迎仏欠視転信況読児生直車任分。迫計増善管世際事方掲見株取探円。響決旅子著国軽県報感確外相意現。野人可総均謙休治調時錦黒食発判。影富薔品遊南撃類刺公雪風閉熊礎写説自投物。権状約迭袋単在展世全姿九暮肢屋。"

class PyBindingsTests(TestCase):

    def setUp(self):
        super(PyBindingsTests, self).setUp()
        self.lp = samba.tests.env_loadparm()
        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.creds.set_username(samba.tests.env_get_var_value('DC_USERNAME'))
        self.creds.set_password(samba.tests.env_get_var_value('DC_PASSWORD'))
        self.smb = smb.SMB(os.environ["SERVER"],
                           "sysvol",
                           lp=self.lp,
                           creds=self.creds)
        self.testfile = 'test_%s'

    def tearDown(self):
        super(PyBindingsTests, self).tearDown()
        try:
            self.smb.deltree(self.testfile)
        except SystemError:
            pass

    def test_smb_savefile_utf16(self):
        self.testfile = self.testfile % 'utf16'
        contents = TEXT.encode('utf-16')
        self.smb.savefile(self.testfile, contents)

        results = self.smb.loadfile(self.testfile).decode('utf-16')
        self.assertEquals(results, TEXT, 'utf-16 text was not correctly decoded')

    def test_smb_savefile_utf16_greek(self):
        self.testfile = self.testfile % 'utf16_greek'
        contents = GREEK_TEXT.encode('utf-16')
        self.smb.savefile(self.testfile, contents)

        results = self.smb.loadfile(self.testfile).decode('utf-16')
        self.assertEquals(results, GREEK_TEXT, 'utf-16 greek text was not correctly decoded')

    def test_smb_savefile_utf16_chinese(self):
        self.testfile = self.testfile % 'utf16_chinese'
        contents = CHINESE_TEXT.encode('utf-16')
        self.smb.savefile(self.testfile, contents)

        results = self.smb.loadfile(self.testfile).decode('utf-16')
        self.assertEquals(results, CHINESE_TEXT, 'utf-16 chinese text was not correctly decoded')

    def test_smb_savefile_utf8(self):
        self.testfile = self.testfile % 'utf8'
        contents = TEXT.encode('utf-8')
        self.smb.savefile(self.testfile, contents)

        results = self.smb.loadfile(self.testfile).decode('utf-8')
        self.assertEquals(results, TEXT, 'utf-8 text was not correctly decoded')

    def test_smb_savefile_utf8_greek(self):
        self.testfile = self.testfile % 'utf8_greek'
        contents = GREEK_TEXT.encode('utf-8')
        self.smb.savefile(self.testfile, contents)

        results = self.smb.loadfile(self.testfile).decode('utf-8')
        self.assertEquals(results, GREEK_TEXT, 'utf-8 greek text was not correctly decoded')

    def test_smb_savefile_utf8_chinese(self):
        self.testfile = self.testfile % 'utf8_chinese'
        contents = CHINESE_TEXT.encode('utf-8')
        self.smb.savefile(self.testfile, contents)

        results = self.smb.loadfile(self.testfile).decode('utf-8')
        self.assertEquals(results, CHINESE_TEXT, 'utf-8 chinese text was not correctly decoded')

    def test_smb_savefile_ascii(self):
        self.testfile = self.testfile % 'ascii'
        contents = TEXT
        print('trying to save file')
        self.smb.savefile(self.testfile, contents)

        print('trying to read file')
        results = self.smb.loadfile(self.testfile)
        self.assertEquals(results, TEXT, 'ascii text was not correctly decoded')

