/*
   Unix SMB/CIFS implementation.
   Copyright (C) Luke Morrison <luc785@hotmail.com> 2013

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Python.h>
#include "includes.h"
#include "version.h"
#include "param/pyparam.h"
#include "pygpo.h"
#include "ads.h"

/*A Python C API module to use LIBGPO*/

#ifndef Py_RETURN_NONE
#define Py_RETURN_NONE return Py_INCREF(Py_None), Py_None
#endif

staticforward PyTypeObject PyGpExt;
staticforward PyTypeObject PyGpO;
staticforward PyTypeObject PyGpIni;
staticforward PyTypeObject PyGpLink;

/******************************************************************************************************************
*******************************************************************************************************************/

//Parameter mapping and functions for the GP_EXT struct
void initgpo(void);

//Parse raw extension string to GP_EXT structure
static PyObject *py_ads_parse_gp_ext(PyGpExtObject * self, PyObject * args)
{
	struct GP_EXT *gp_ext = pygp_ext_AsgpextContext((PyObject *) self);
	bool verify;
	const char *extension_raw;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(NULL);
	if (!PyArg_ParseTuple(args, "s", &extension_raw)) {
		return NULL;
	}
	verify = ads_parse_gp_ext(tmp_ctx, extension_raw, &gp_ext);
	if (!verify) {
		talloc_free(tmp_ctx);
		Py_RETURN_NONE;
	}
	return (PyObject *) gp_ext;
}

//Functions here
static PyMethodDef py_gp_ext_methods[] = {
	{"ads_parse_gp_ext", (PyCFunction) py_ads_parse_gp_ext, METH_VARARGS,
	 NULL},
	{NULL}
};

//Mapping here
static PyObject *py_gp_ext_get_extensions(PyGpExtObject * self)
{
	return PyString_FromString((*self->gp_ext->extensions));
}

static PyObject *py_gp_ext_get_extensions_guid(PyGpExtObject * self)
{
	return PyString_FromString((*self->gp_ext->extensions_guid));
}

static PyObject *py_gp_ext_get_snapins(PyGpExtObject * self)
{
	return PyString_FromString((*self->gp_ext->snapins));
}

static PyObject *py_gp_ext_get_snapins_guid(PyGpExtObject * self)
{
	return PyString_FromString((*self->gp_ext->snapins_guid));
}

static PyGetSetDef py_gp_ext_getset[] = {
	{discard_const_p(char, "keyval_count"),
	 (getter) py_gp_ext_get_extensions, NULL, NULL},
	{discard_const_p(char, "current_section"),
	 (getter) py_gp_ext_get_extensions_guid, NULL, NULL},
	{discard_const_p(char, "generated_filename"),
	 (getter) py_gp_ext_get_snapins, NULL, NULL},
	{discard_const_p(char, "snapins_guid"),
	 (getter) py_gp_ext_get_snapins_guid, NULL, NULL},
	{NULL}
};

static PyObject *py_gp_ext_new(PyTypeObject * type, PyObject * args,
			       PyObject * kwargs)
{
	struct GP_EXT *gp;
	TALLOC_CTX *mem_ctx;
	PyGpExtObject *py_ret;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	gp = talloc(mem_ctx, struct GP_EXT);
	if (!gp) {
		talloc_free(mem_ctx);
		PyErr_SetString(PyExc_ValueError, "unable to allocate gp");
		return NULL;
	}

	py_ret = (PyGpExtObject *) type->tp_alloc(type, 0);
	if (py_ret == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	py_ret->mem_ctx = mem_ctx;
	py_ret->gp_ext = gp;
	return (PyObject *) py_ret;
}

static void py_gp_ext_dealloc(PyGpExtObject * self)
{
	if (self->mem_ctx != NULL) {
		talloc_free(self->mem_ctx);
	}
	self->ob_type->tp_free(self);
}

static PyTypeObject PyGpExt = {
	.tp_name = "gpo.ext",
	.tp_dealloc = (destructor) py_gp_ext_dealloc,
	.tp_new = py_gp_ext_new,
	.tp_basicsize = sizeof(PyGpExtObject),
	.tp_getset = py_gp_ext_getset,
	.tp_methods = py_gp_ext_methods,
};

/*******************************************************************************************************************
*******************************************************************************************************************/

//Parameter mapping and methods for the gpi_inifile_context Struct.

//Functions here

//static PyObject *py_gp_inifile_get_string(PyGpIniObject* self)

static PyObject *py_parse_gpt_ini(PyObject * self, PyObject * args)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	char *filename;
	uint32_t *version = 0;
	NTSTATUS status;
	char **display_name = NULL;
	PyObject *result = NULL;

	if (!PyArg_ParseTuple(args, "s", &filename)) {
		return NULL;
	}
	status = parse_gpt_ini(tmp_ctx, filename, version, display_name);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}
	//Do not need to check for display name because it might not have one
	//Zero cases will be handled in python
	result = Py_BuildValue("[s,i]", display_name, version);
	return result;

}

static PyMethodDef py_gp_inifile_methods[] = {
	{"parse_gpt_ini", (PyCFunction) py_parse_gpt_ini, METH_VARARGS,
	 "Pase the local gp.ini file"},
	{NULL}
};

//Mapping Here
static PyObject *py_gp_inifile_keyval_count(PyGpIniObject * self)
{
	return PyInt_FromLong(self->gp_ini->keyval_count);
}

static PyObject *py_gp_inifile_get_current_section(PyGpIniObject * self)
{
	return PyString_FromString(self->gp_ini->current_section);
}

static PyObject *py_gp_inifile_generated_filename(PyGpIniObject * self)
{
	return PyString_FromString(self->gp_ini->generated_filename);
}

static PyGetSetDef py_gp_inifile_getset[] = {
	{discard_const_p(char, "keyval_count"),
	 (getter) py_gp_inifile_keyval_count, NULL, NULL},
	{discard_const_p(char, "current_section"),
	 (getter) py_gp_inifile_get_current_section, NULL, NULL},
	{discard_const_p(char, "generated_filename"),
	 (getter) py_gp_inifile_generated_filename, NULL, NULL},
	{NULL}
};

static PyObject *py_gp_inifile_new(PyTypeObject * type, PyObject * args,
				   PyObject * kwargs)
{
	struct gp_inifile_context *gp;
	TALLOC_CTX *mem_ctx;
	PyGpIniObject *py_ret;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	gp = talloc(mem_ctx, struct gp_inifile_context);
	if (!gp) {
		talloc_free(mem_ctx);
		PyErr_SetString(PyExc_ValueError, "unable to allocate gp");
		return NULL;
	}

	py_ret = (PyGpIniObject *) type->tp_alloc(type, 0);
	if (py_ret == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	py_ret->mem_ctx = mem_ctx;
	py_ret->gp_ini = gp;
	return (PyObject *) py_ret;
}

static void py_gp_inifile_dealloc(PyGpIniObject * self)
{
	if (self->mem_ctx != NULL) {
		talloc_free(self->mem_ctx);
	}
	self->ob_type->tp_free(self);
}

static PyTypeObject PyGpIni = {
	.tp_name = "pygpo",
	.tp_methods = py_gp_inifile_methods,
	.tp_getset = py_gp_inifile_getset,
	.tp_doc = "GPO for gp_inifile_context.",
	.tp_new = py_gp_inifile_new,
	.tp_dealloc = (destructor) py_gp_inifile_dealloc,
	.tp_basicsize = sizeof(PyGpIniObject),
};

/****************************************************************************************/
/*Parameter mapping and methods for the GROUP POLICY OBJECT Struct.*/

/*Functions here*/

static PyObject *py_gpo_get_unix_path(PyGpObject * self, PyObject * args)
{
	TALLOC_CTX *mem_ctx;
	struct GROUP_POLICY_OBJECT *gpo = pygpo_AsgpoContext((PyObject *) self);
	const char *cache_dir = NULL;
	char **unix_path = NULL;
	NTSTATUS status;
	if (!PyArg_ParseTuple(args, "s", &cache_dir)) {
		return NULL;
	}
	mem_ctx = talloc_new(NULL);
	status = gpo_get_unix_path(mem_ctx, cache_dir, gpo, unix_path);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}
	if (!unix_path) {
		return NULL;
	}
	return PyString_FromString(*unix_path);
}

static PyMethodDef py_gpo_local_methods[] = {
	{"gpo_get_unix_path", (PyCFunction) py_gpo_get_unix_path, METH_VARARGS,
	 NULL},
	{NULL}
};

/*Mapping here*/
static PyObject *py_options(PyGpObject * self)
{
	return PyInt_FromLong(self->gpo->options);
}

static PyObject *py_version(PyGpObject * self)
{
	return PyInt_FromLong(self->gpo->version);
}

static PyObject *py_ds_path(PyGpObject * self)
{
	return PyString_FromString(self->gpo->ds_path);
}

static PyObject *py_file_sys_path(PyGpObject * self)
{
	return PyString_FromString(self->gpo->file_sys_path);
}

static PyObject *py_name(PyGpObject * self)
{
	return PyString_FromString(self->gpo->name);
}

static PyObject *py_link(PyGpObject * self)
{
	return PyString_FromString(self->gpo->link);
}

static PyObject *py_user_extensions(PyGpObject * self)
{
	return PyString_FromString(self->gpo->user_extensions);
}

static PyObject *py_machine_extensions(PyGpObject * self)
{
	return PyString_FromString(self->gpo->machine_extensions);
}

static PyGetSetDef py_gpo_getset[] = {
	{discard_const_p(char, "options"), (getter) py_options, NULL, NULL},
	{discard_const_p(char, "version"), (getter) py_version, NULL, NULL},
	{discard_const_p(char, "ds_path"), (getter) py_ds_path, NULL, NULL},
	{discard_const_p(char, "file_sys_path"), (getter) py_file_sys_path,
	 NULL, NULL},
	{discard_const_p(char, "name"), (getter) py_name, NULL, NULL},
	{discard_const_p(char, "link"), (getter) py_link, NULL, NULL},
	{discard_const_p(char, "user_extensions"), (getter) py_user_extensions,
	 NULL, NULL},
	{discard_const_p(char, "machine_extensions"),
	 (getter) py_machine_extensions, NULL, NULL},
	{NULL}
};

static PyObject *py_gpo_local_new(PyTypeObject * type, PyObject * args,
				  PyObject * kwargs)
{
	struct GROUP_POLICY_OBJECT *gpo;
	TALLOC_CTX *mem_ctx;
	PyGpObject *py_ret;
	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	gpo = talloc(mem_ctx, struct GROUP_POLICY_OBJECT);
	if (!gpo) {
		talloc_free(mem_ctx);
		PyErr_SetString(PyExc_ValueError, "unable to allocate gp");
		return NULL;
	}
	py_ret = (PyGpObject *) type->tp_alloc(type, 0);
	if (py_ret == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	py_ret->mem_ctx = mem_ctx;

	return (PyObject *) py_ret;
}

static void py_gpo_local_dealloc(PyGpObject * self)
{
	if (self->mem_ctx != NULL) {
		talloc_free(self->mem_ctx);
	}
	self->ob_type->tp_free(self);
}

static PyTypeObject PyGpO = {
	.tp_name = "pygpo",
	.tp_methods = py_gpo_local_methods,
	.tp_getset = py_gpo_getset,
	.tp_doc = "GPO mapping",
	.tp_new = py_gpo_local_new,
	.tp_dealloc = (destructor) py_gpo_local_dealloc,
	.tp_basicsize = sizeof(PyGpObject),
};

/******************************************************************************************************************************
******************************************************************************************************************************/
//Parameter mapping and methods for the GP_LINK Struct.

/*Gets a GP_LINK structure from a linkdn*/

/*What is a linkdn?
how do I initialize the AD structure*/
/*
static PyObject *py_ads_get_gpo_link(PyGpLinkObject *self, PyObject* args)
{
	struct GP_LINK *gp_link = pygp_link_AsgplinkContext((PyObject*)self->gp_link);//I Think this should just be self not self->gp_link
	struct ADS_STRUCT *ads;
	PyObject *py_obj;
	TALLOC_CTX *mem_ctx;
	mem_ctx = talloc_new(NULL);
	uint32_t options;
	char *link_dn;
	PyObject *result;
	ADS_STATUS status;

	if (!PyArg_ParseTuple(args, "sO" , &link_dn, &py_obj)) {
		return NULL;
		}
	if (!link_dn){
		talloc_free(mem_ctx);
		Py_RETURN_NONE;
		}
	ads = pygpoads_AsgpoadsContext(py_obj);
	status = ads_get_gpo_link(ads, mem_ctx, link_dn, gp_link);
	if (!ADS_ERR_OK(status)) {
		printf("Status not ok, aborting!");
		Py_RETURN_NONE;
		}

	if (!gp_link){
		talloc_free(mem_ctx);
		Py_RETURN_NONE;
		printf("GP_LINK unitialized. Verify the string is valid and try again!\n");
		}
	result = Py_BuildValue("O", gp_link);
	return result;

}
*/
/*helper call to add a gp link
static PyObject py_ads_add_gpo_link(PyGpLinkObject *self, PyObject *args)
{
	ADS_STRUCT *ads;
	ads = pygplinkads_AsgplinkadsContext(self);
	TALLOC_CTX *mem_ctx;
	mem_ctx = talloc_new
	ADS_STATUS status;
	(!ADS_ERR_OK(status))

	*/

static PyMethodDef py_gp_link_methods[] = {
//{"ads_get_gpo_link", (PyCFunction)py_ads_get_gpo_link, METH_VARARGS, NULL},
	{NULL}
};

static PyObject *py_gp_link(PyGpLinkObject * self)
{
	return PyString_FromString(self->gp_link->gp_link);
}

static PyObject *py_gp_opts(PyGpLinkObject * self)
{
	return PyInt_FromLong(self->gp_link->gp_opts);
}

static PyObject *py_num_links(PyGpLinkObject * self)
{
	return PyInt_FromLong(self->gp_link->num_links);
}

static PyObject *py_link_names(PyGpLinkObject * self)
{
	return PyString_FromString((*self->gp_link->link_names));
}

static PyObject *py_link_opts(PyGpLinkObject * self)
{
	return PyInt_FromLong((*self->gp_link->link_opts));
}

static PyGetSetDef py_gp_link_getset[] = {

	{discard_const_p(char, "gp_link"), (getter) py_gp_link, NULL, NULL},
	{discard_const_p(char, "gp_opts"), (getter) py_gp_opts, NULL, NULL},
	{discard_const_p(char, "num_links"), (getter) py_num_links, NULL, NULL},
	{discard_const_p(char, "link_names"), (getter) py_link_names, NULL,
	 NULL},
	{discard_const_p(char, "link_opts"), (getter) py_link_opts, NULL, NULL},

	{NULL}
};

static PyObject *py_gp_link_new(PyTypeObject * type, PyObject * args,
				PyObject * kwargs)
{
	struct GP_LINK *gplink;
	TALLOC_CTX *mem_ctx;
	PyGpLinkObject *py_ret;
	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	gplink = talloc(mem_ctx, struct GP_LINK);
	if (!gplink) {
		talloc_free(mem_ctx);
		PyErr_SetString(PyExc_ValueError, "unable to allocate gp");
		return NULL;
	}
	py_ret = (PyGpLinkObject *) type->tp_alloc(type, 0);
	if (py_ret == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	py_ret->mem_ctx = mem_ctx;

	return (PyObject *) py_ret;
}

static void py_gpo_link_dealloc(PyGpLinkObject * self)
{
	if (self->mem_ctx != NULL) {
		talloc_free(self->mem_ctx);
	}
	self->ob_type->tp_free(self);
}

static PyTypeObject PyGpLink = {
	.tp_name = "pygpo",
	.tp_methods = py_gp_link_methods,
	.tp_getset = py_gp_link_getset,
	.tp_doc = "GPO mapping",
	.tp_new = py_gp_link_new,
	.tp_dealloc = (destructor) py_gpo_link_dealloc,
	.tp_basicsize = sizeof(PyGpLinkObject),
};

/*****************************************************************************************************************************/
/*Global methods aka do not need a special pyobject type*/

static PyObject *py_gpo_get_sysvol_gpt_version(PyObject * self, PyObject * args)
{
	TALLOC_CTX *tmp_ctx = NULL;
	NTSTATUS status;
	char *unix_path;
	char *display_name = NULL;
	uint32_t sysvol_version = 0;
	PyObject *result;

	tmp_ctx = talloc_new(NULL);

	if (!PyArg_ParseTuple(args, "s", &unix_path)) {
		return NULL;
	}
	status =
	    gpo_get_sysvol_gpt_version(tmp_ctx, unix_path, &sysvol_version,
				       &display_name);
	talloc_free(tmp_ctx);
	result = Py_BuildValue("[s,i]", display_name, sysvol_version);
	return result;
}

/*Verify that the GUID is not a client side extension*/
static PyObject *py_cse_gpo_name_to_guid_string(PyObject * self,
						PyObject * args)
{
	char *name = NULL;
	char *ret = NULL;

	if (!PyArg_ParseTuple(args, "s", &name)) {
		return NULL;
	}

	ret = cse_gpo_name_to_guid_string(name);

	return PyString_FromString(ret);
}

static PyObject *py_ads_init(PyGpObject * self, PyObject * args)
{
	const char *realm = NULL;
	const char *workgroup = NULL;
	const char *ldap_server = NULL;
	ADS_STRUCT *ads = NULL;

	printf("Before the as content statement\n");
	ads = pygpoads_AsgpoadsContext(self->ads);

	if (!PyArg_ParseTuple(args, "ss", &realm, &workgroup)) {
		return NULL;
	}
	printf("After the content statement before function \n");
	ads = ads_init(realm, workgroup, ldap_server);
	printf("After function before returning");
	if (!ads) {
		printf("did this work");
	}

	return (PyObject *) ads;
}

static PyMethodDef py_gpo_methods[] = {
	{"cse_gpo_name_to_guid_string",
	 (PyCFunction) py_cse_gpo_name_to_guid_string, METH_VARARGS, NULL},
	{"gpo_get_sysvol_gpt_version",
	 (PyCFunction) py_gpo_get_sysvol_gpt_version, METH_VARARGS, NULL},
	{"ads_init", (PyCFunction) py_ads_init, METH_VARARGS,
	 "initializing the ads structure"},
	{NULL}
};

/* will be called by python when loading this module*/
void initgpo(void)
{
	PyObject *m;

	debug_setup_talloc_log();
	/* Instanciate the types */
	m = Py_InitModule3("gpo", py_gpo_methods, "libgpo python bindings");
	if (m == NULL)
		return;
	PyModule_AddObject(m, "version",
			   PyString_FromString(SAMBA_VERSION_STRING));
	if (PyType_Ready(&PyGpO) < 0)
		return;
	if (PyType_Ready(&PyGpIni) < 0)
		return;
	if (PyType_Ready(&PyGpExt) < 0)
		return;
	if (PyType_Ready(&PyGpLink) < 0)
		return;

	Py_INCREF(&PyGpO);
	Py_INCREF(&PyGpIni);
	Py_INCREF(&PyGpExt);
	Py_INCREF(&PyGpLink);

}
