#include <talloc.h>
#include "gpo_ini.h"
typedef struct {
	PyObject_HEAD Talloc_CTX * mem_ctx;
	struct gp_inifile_context *gp_ctx;
} PyGpiniObject;

#define pygpo_inifile_AsGpContext(pyobj) ((PyGpiniObect *) probj ) -> gp_ctx
