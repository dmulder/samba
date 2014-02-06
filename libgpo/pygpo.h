#include <Python.h>
#include <talloc.h>
#include "ads.h"
#include "gpo.h"
#include "gpo_ini.h"
#include "gpo_proto.h"

//#ifndef _GPEXT_H_
//#define _GPEXT_H_

typedef struct {
	PyObject_HEAD
	TALLOC_CTX * mem_ctx;
	struct GP_EXT *gp_ext;
} PyGpExtObject;
#define pygp_ext_AsgpextContext(pyobj) ((PyGpExtObject *)pyobj)->gp_ext

typedef struct {
	PyObject_HEAD
	TALLOC_CTX * mem_ctx;
	struct GROUP_POLICY_OBJECT *gpo;
	struct ADS_STRUCT *ads;
} PyGpObject;
#define pygpo_AsgpoContext(pyobj) ((PyGpObject *)pyobj)->gpo
#define pygpoads_AsgpoadsContext(pyobj) ((PyGpObject *)pyobj)->ads
typedef struct {
	PyObject_HEAD
	TALLOC_CTX * mem_ctx;
	struct GP_LINK *gp_link;
	struct ADS_STRUCT *ads;
} PyGpLinkObject;
#define pygp_link_AsgplinkContext(pyobj) ((PyGpLinkObject *)pyobj)->gp_link
#define pygplinkads_AsgplinkadsContext(pyobj) ((PyGpLinkObject *)->ads
typedef struct {
	PyObject_HEAD
	TALLOC_CTX * mem_ctx;
	struct gp_registry_entry *gp_reg;
} PyRegObject;
#define pygp_reg_AsgpregContext(pyobj) ((PyRegObject *)pyobj)->gp_reg
typedef struct {
	PyObject_HEAD
	TALLOC_CTX * mem_ctx;
	struct gp_registry_value *gp_reg_value;
} PyRegvalobject;
#define pygp_regval_AsgpregvalContext(pyobj) ((PyRegvalObject *)pyobj)->gp_reg_value

typedef struct {
	PyObject_HEAD
	TALLOC_CTX * mem_ctx;
	struct gp_inifile_context *gp_ini;
} PyGpIniObject;

#define pygp_ini_AsgpiniContext(pyobj) ((PyGpIniObject *)pyobj)->gp_ini
