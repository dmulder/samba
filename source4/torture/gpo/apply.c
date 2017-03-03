/* 
   Unix SMB/CIFS implementation.

   Copyright (C) David Mulder 2017
   
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

#include "includes.h"
#include "param/param.h"
#include "param/loadparm.h"
#include "torture/smbtorture.h"
#include "lib/util/mkdir_p.h"
#include "dsdb/samdb/samdb.h"
#include "auth/session.h"
#include "lib/ldb/include/ldb.h"
#include "torture/gpo/proto.h"

struct torture_suite *gpo_apply_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "apply");

	torture_suite_add_simple_test(suite, "gpo_param_from_gpo", torture_gpo_system_access_policies);

	suite->description = talloc_strdup(suite, "Group Policy apply tests");

	return suite;
}

static char* convert_param(struct torture_context *tctx, struct parm_struct *parm, void *parm_ptr)
{
	switch (parm->type) {
		case P_CHAR:
			return talloc_asprintf(tctx, "%c", *(char *)parm_ptr);
		case P_STRING:
		case P_USTRING:
			return talloc_strdup(tctx, *(char **)parm_ptr);;
		case P_CMDLIST:
		case P_LIST:
		{
			int j, len = 0;
			const char **strlist = *(const char ***)parm_ptr;
			char *result = NULL;

			if (strlist == NULL)
				return NULL;

			for (j = 0; strlist[j]; j++) {
				int len_chunk = strlen(strlist[j])+1;
				result = talloc_realloc(tctx, result, char, len+len_chunk);
				memcpy(result+len, strlist[j], len_chunk);
				len += len_chunk;
				result[len-1] = ' ';
			}
			result[len-1] = '\0'; // Terminate the string
			return result;
		}
		case P_BOOL:
		case P_BOOLREV:
		case P_INTEGER:
		case P_OCTAL:
		case P_BYTES:
		case P_ENUM:
		default:
			return NULL; // TODO: implement the other types if needed
	}
	return NULL;
}

static const char* lp_get_param(struct torture_context *tctx, const char *service_name, const char *param_name)
{
	struct parm_struct *parm = NULL;
	struct loadparm_service *service;
	void *parm_ptr = NULL;

	if (service_name) {
		service = lpcfg_service(tctx->lp_ctx, service_name);
		torture_assert(tctx, service, talloc_asprintf(tctx, "Failed to find %s", service_name));
		parm = lpcfg_parm_struct(tctx->lp_ctx, param_name);
		torture_assert(tctx, parm, talloc_asprintf(tctx, "Failed to find %s %s", service_name, param_name));
		parm_ptr = lpcfg_parm_ptr(tctx->lp_ctx, service, parm);
		torture_assert(tctx, parm_ptr, talloc_asprintf(tctx, "Failed to find %s %s", service_name, param_name));
	} else {
		parm = lpcfg_parm_struct(tctx->lp_ctx, param_name);
		torture_assert(tctx, parm, talloc_asprintf(tctx, "Failed to find %s", param_name));
		parm_ptr = lpcfg_parm_ptr(tctx->lp_ctx, NULL, parm);
		torture_assert(tctx, parm, talloc_asprintf(tctx, "Failed to find %s", param_name));
	}
	return convert_param(tctx, parm, parm_ptr);
}

#define GPODIR "addom.samba.example.com/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit"
#define GPOFILE "GptTmpl.inf"
#define GPTTMPL "[System Access]\n\
MinimumPasswordAge = 2\n\
MaximumPasswordAge = 37\n\
MinimumPasswordLength = 11\n\
PasswordComplexity = 2\n\
"
#define GPTINI "addom.samba.example.com/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI"

bool torture_gpo_system_access_policies(struct torture_context *tctx)
{
	int ret, vers = 0;
	const char *gpo_update_cmd = NULL, *sysvol_path = NULL, *gpo_dir = NULL, *gpo_file = NULL, *gpt_file = NULL;
	struct ldb_context *samdb = NULL;
	struct ldb_result *result;
	const char *attrs[] = {
		"minPwdAge",
		"maxPwdAge",
		"minPwdLength",
		"pwdProperties",
		NULL
	};
	const struct ldb_val *val;
	FILE *fp = NULL;

	sysvol_path = lp_get_param(tctx, "sysvol", "path");
	torture_assert(tctx, sysvol_path, "Failed to fetch the sysvol path");
	gpo_update_cmd = lp_get_param(tctx, NULL, "gpo update command");
	torture_assert(tctx, gpo_update_cmd, "Failed to fetch the gpo update command");

	/* Write out the sysvol */
	gpo_dir = talloc_asprintf(tctx, "%s/%s", sysvol_path, GPODIR);
	mkdir_p(gpo_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	gpo_file = talloc_asprintf(tctx, "%s/%s", gpo_dir, GPOFILE);
	if ( (fp = fopen(gpo_file, "w")) ) {
		fputs(GPTTMPL, fp);
		fclose(fp);
	}

	/* Update the version in the GPT.INI */
	gpt_file = talloc_asprintf(tctx, "%s/%s", sysvol_path, GPTINI);
	if ( (fp = fopen(gpt_file, "r")) ) {
		char line[256];
		while (fgets(line, 256, fp)) {
			if (strncasecmp(line, "Version=", 8) == 0) {
				vers = atoi(line+8);
				break;
			}
		}
		fclose(fp);
	}
	if ( (fp = fopen(gpt_file, "w")) ) {
		char *data = talloc_asprintf(tctx, "[General]\nVersion=%d\n", ++vers);
		fputs(data, fp);
		fclose(fp);
	}

	/* Run the gpo update command */
	system(gpo_update_cmd);

	/* Open and read the samba db and verify the settings applied */
	samdb = samdb_connect(tctx, tctx->ev, tctx->lp_ctx, system_session(tctx->lp_ctx), 0);
	torture_assert(tctx, samdb, "Failed to connect to the samdb");

	ret = ldb_search(samdb, tctx, &result, ldb_get_default_basedn(samdb), LDB_SCOPE_BASE, attrs, NULL);
	torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1, "Searching the samdb failed");

	/* minPwdAge */
	val = ldb_msg_find_ldb_val(result->msgs[0], attrs[0]);
	torture_assert(tctx, strcmp((char*)val->data, "-1728000000000") == 0, "The minPwdAge was not applied");

	/* maxPwdAge */
	val = ldb_msg_find_ldb_val(result->msgs[0], attrs[1]);
	torture_assert(tctx, strcmp((char*)val->data, "-31968000000000") == 0, "The maxPwdAge was not applied");

	/* minPwdLength */
	val = ldb_msg_find_ldb_val(result->msgs[0], attrs[2]);
	torture_assert(tctx, atoi((char*)val->data) == 11, "The minPwdLength was not applied");

	/* pwdProperties */
	val = ldb_msg_find_ldb_val(result->msgs[0], attrs[3]);
	torture_assert(tctx, atoi((char*)val->data) == 2, "The pwdProperties were not applied");

	return true;
}

