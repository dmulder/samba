#!/usr/bin/env python

#
# Unix SMB/CIFS implementation.
#
# WERROR error definition generation
#
# Copyright (C) Catalyst.Net Ltd. 2017
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

import sys, os.path, io, string
from gen_error_common import parseErrorDescriptions, ErrorDef
from io import open
from builtins import str

def generateHeaderFile(out_file, errors):
    out_file.write(u"/*\n")
    out_file.write(u" * Descriptions for errors generated from\n")
    out_file.write(u" * [MS-ERREF] https://msdn.microsoft.com/en-us/library/cc231199.aspx\n")
    out_file.write(u" */\n\n")
    out_file.write(u"#ifndef _WERR_GEN_H\n")
    out_file.write(u"#define _WERR_GEN_H\n")
    for err in errors:
        line = u"#define %s W_ERROR(%s)\n" % (str(err.err_define), str(hex(err.err_code)))
        out_file.write(line)
    out_file.write(u"\n#endif /* _WERR_GEN_H */\n")

def generateSourceFile(out_file, errors):
    out_file.write(u"#include \"werror.h\"\n")

    out_file.write(u"/*\n")
    out_file.write(u" * Names for errors generated from\n")
    out_file.write(u" * [MS-ERREF] https://msdn.microsoft.com/en-us/library/cc231199.aspx\n")
    out_file.write(u" */\n")

    out_file.write(u"static const struct werror_code_struct dos_errs[] = \n")
    out_file.write(u"{\n")
    for err in errors:
        out_file.write(u"\t{ \"%s\", %s },\n" % (str(err.err_define), str(err.err_define)))
    out_file.write(u"{ 0, W_ERROR(0) }\n")
    out_file.write(u"};\n")

    out_file.write(u"\n/*\n")
    out_file.write(u" * Descriptions for errors generated from\n")
    out_file.write(u" * [MS-ERREF] https://msdn.microsoft.com/en-us/library/cc231199.aspx\n")
    out_file.write(u" */\n")

    out_file.write(u"static const struct werror_str_struct dos_err_strs[] = \n")
    out_file.write(u"{\n")
    for err in errors:
        # Account for the possibility that some errors may not have descriptions
        if err.err_string == "":
            continue
        out_file.write(u"\t{ %s, \"%s\" },\n"%(str(err.err_define), str(err.err_string)))
    out_file.write(u"\t{ W_ERROR(0), 0 }\n")
    out_file.write(u"};")

def generatePythonFile(out_file, errors):
    out_file.write(u"/*\n")
    out_file.write(u" * Errors generated from\n")
    out_file.write(u" * [MS-ERREF] https://msdn.microsoft.com/en-us/library/cc231199.aspx\n")
    out_file.write(u" */\n")
    out_file.write(u"#include <Python.h>\n")
    out_file.write(u"#include \"python/py3compat.h\"\n")
    out_file.write(u"#include \"includes.h\"\n\n")
    out_file.write(u"static inline PyObject *ndr_PyLong_FromUnsignedLongLong(unsigned long long v)\n");
    out_file.write(u"{\n");
    out_file.write(u"\tif (v > LONG_MAX) {\n");
    out_file.write(u"\t\treturn PyLong_FromUnsignedLongLong(v);\n");
    out_file.write(u"\t} else {\n");
    out_file.write(u"\t\treturn PyInt_FromLong(v);\n");
    out_file.write(u"\t}\n");
    out_file.write(u"}\n\n");
    # This is needed to avoid a missing prototype error from the C
    # compiler. There is never a prototype for this function, it is a
    # module loaded by python with dlopen() and found with dlsym().
    out_file.write(u"static struct PyModuleDef moduledef = {\n")
    out_file.write(u"\tPyModuleDef_HEAD_INIT,\n")
    out_file.write(u"\t.m_name = \"werror\",\n")
    out_file.write(u"\t.m_doc = \"WERROR defines\",\n")
    out_file.write(u"\t.m_size = -1,\n")
    out_file.write(u"};\n\n")
    out_file.write(u"MODULE_INIT_FUNC(werror)\n")
    out_file.write(u"{\n")
    out_file.write(u"\tPyObject *m;\n\n")
    out_file.write(u"\tm = PyModule_Create(&moduledef);\n");
    out_file.write(u"\tif (m == NULL)\n");
    out_file.write(u"\t\treturn NULL;\n\n");
    for err in errors:
        line = u"""\tPyModule_AddObject(m, \"%s\",
                  \t\tndr_PyLong_FromUnsignedLongLong(W_ERROR_V(%s)));\n""" % (str(err.err_define), str(err.err_define))
        out_file.write(line)
    out_file.write(u"\n");
    out_file.write(u"\treturn m;\n");
    out_file.write(u"}\n");

def transformErrorName( error_name ):
    if error_name.startswith("WERR_"):
        error_name = error_name.replace("WERR_", "", 1)
    elif error_name.startswith("ERROR_"):
        error_name = error_name.replace("ERROR_", "", 1)
    return "WERR_" + error_name.upper()

# Script to generate files werror_gen.h, doserr_gen.c and
# py_werror.c.
#
# These files contain generated definitions for WERRs and
# their descriptions/names.
#
# This script takes four inputs:
# [1]: The name of the text file which is the content of an HTML table
#      (e.g. the one found at https://msdn.microsoft.com/en-us/library/cc231199.aspx)
#      copied and pasted.
# [2]: [[output werror_gen.h]]
# [3]: [[output doserr_gen.c]]
# [4]: [[output py_werror.c]]
def main():
    if len(sys.argv) == 5:
        input_file_name = sys.argv[1]
        gen_headerfile_name = sys.argv[2]
        gen_sourcefile_name = sys.argv[3]
        gen_pythonfile_name = sys.argv[4]
    else:
        print("usage: %s winerrorfile headerfile sourcefile pythonfile" % sys.argv[0])
        sys.exit()

    input_file = open(input_file_name, "r", encoding='utf8')
    errors = parseErrorDescriptions(input_file, True, transformErrorName)
    input_file.close()

    print("writing new header file: %s" % gen_headerfile_name)
    out_file = open(gen_headerfile_name, "w", encoding='utf8')
    generateHeaderFile(out_file, errors)
    out_file.close()
    print("writing new source file: %s" % gen_sourcefile_name)
    out_file = open(gen_sourcefile_name, "w", encoding='utf8')
    generateSourceFile(out_file, errors)
    out_file.close()
    print("writing new python file: %s" % gen_pythonfile_name)
    out_file = open(gen_pythonfile_name, "w", encoding='utf8')
    generatePythonFile(out_file, errors)
    out_file.close()

if __name__ == '__main__':

    main()
