/*
 *  Unix SMB/CIFS implementation.
 *  Group Policy Object Support
 *  Copyright (C) Guenther Deschner 2005-2006
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "system/filesys.h"
#include "../libgpo/gpo.h"
#include "../libgpo/gpo_ini.h"

#include "libgpo/gpo_proto.h"
#include "libsmb/libsmb.h"
#include "lib/policy/policy.h"
#include "param.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_internal.h"

/****************************************************************
 explode the GPO CIFS URI into their components
****************************************************************/

NTSTATUS gpo_explode_filesyspath(TALLOC_CTX *mem_ctx,
                                 const char *cache_dir,
				 const char *file_sys_path,
				 char **server,
				 char **service,
				 char **nt_path,
				 char **unix_path)
{
	char *path = NULL;

	*server = NULL;
	*service = NULL;
	*nt_path = NULL;
	*unix_path = NULL;

	if (!file_sys_path) {
		return NT_STATUS_OK;
	}

	if (!next_token_talloc(mem_ctx, &file_sys_path, server, "\\")) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	NT_STATUS_HAVE_NO_MEMORY(*server);

	if (!next_token_talloc(mem_ctx, &file_sys_path, service, "\\")) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	NT_STATUS_HAVE_NO_MEMORY(*service);

	if ((*nt_path = talloc_asprintf(mem_ctx, "\\%s", file_sys_path))
		== NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	NT_STATUS_HAVE_NO_MEMORY(*nt_path);

	if ((path = talloc_asprintf(mem_ctx,
					"%s/%s",
					cache_dir,
					file_sys_path)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	path = talloc_string_sub(mem_ctx, path, "\\", "/");
	if (!path) {
		return NT_STATUS_NO_MEMORY;
	}

	*unix_path = talloc_strdup(mem_ctx, path);
	NT_STATUS_HAVE_NO_MEMORY(*unix_path);

	talloc_free(path);
	return NT_STATUS_OK;
}

/****************************************************************
 prepare the local disc storage for "unix_path"
****************************************************************/

static NTSTATUS gpo_prepare_local_store(TALLOC_CTX *mem_ctx,
                                        const char *cache_dir,
					const char *unix_path)
{
	char *current_dir;
	char *tok;

	current_dir = talloc_strdup(mem_ctx, cache_dir);
	NT_STATUS_HAVE_NO_MEMORY(current_dir);

	if ((mkdir(cache_dir, 0644)) < 0 && errno != EEXIST) {
		return NT_STATUS_ACCESS_DENIED;
	}

	while (next_token_talloc(mem_ctx, &unix_path, &tok, "/")) {
		if (strequal(tok, GPO_CACHE_DIR)) {
			break;
		}
	}

	while (next_token_talloc(mem_ctx, &unix_path, &tok, "/")) {
		current_dir = talloc_asprintf_append_buffer(current_dir, "/%s", tok);
		NT_STATUS_HAVE_NO_MEMORY(current_dir);

		if ((mkdir(current_dir, 0644)) < 0 && errno != EEXIST) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	return NT_STATUS_OK;
}

/****************************************************************
 download a full GPO via CIFS
****************************************************************/

NTSTATUS gpo_fetch_files(TALLOC_CTX *mem_ctx,
                         ADS_STRUCT *ads,
                         const char *cache_dir,
			 const struct GROUP_POLICY_OBJECT *gpo)
{
	NTSTATUS result;
	bool ret;
	char *server, *service, *nt_path, *unix_path;
	struct gp_context *gp_ctx = NULL;

	gp_ctx = talloc_zero(mem_ctx, struct gp_context);
	if (gp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result = gpo_explode_filesyspath(mem_ctx, cache_dir, gpo->file_sys_path,
					 &server, &service, &nt_path,
					 &unix_path);
	NT_STATUS_NOT_OK_RETURN(result);

	result = gpo_prepare_local_store(mem_ctx, cache_dir, unix_path);
	NT_STATUS_NOT_OK_RETURN(result);

	gp_ctx->lp_ctx = talloc_zero(gp_ctx, struct loadparm_context);
	if (gp_ctx->lp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ret = lpcfg_load(gp_ctx->lp_ctx, ads->config.config_path);
	if (!ret) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	gp_ctx->credentials = talloc_zero(gp_ctx, struct cli_credentials);
	if (gp_ctx->credentials == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	ret = cli_credentials_set_username(gp_ctx->credentials,
					   ads->auth.user_name,
					   CRED_CALLBACK_RESULT);
	if (!ret) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	ret = cli_credentials_set_password(gp_ctx->credentials,
					   ads->auth.password,
					   CRED_CALLBACK_RESULT);
	if (!ret) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Fetch the files */
	result = gp_fetch_files(gp_ctx, nt_path, unix_path);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	return NT_STATUS_OK;
}

/****************************************************************
 get the locally stored gpt.ini version number
****************************************************************/

NTSTATUS gpo_get_sysvol_gpt_version(TALLOC_CTX *mem_ctx,
				    const char *unix_path,
				    uint32_t *sysvol_version,
				    char **display_name)
{
	NTSTATUS status;
	uint32_t version = 0;
	char *local_path = NULL;
	char *name = NULL;

	if (!unix_path) {
		return NT_STATUS_OK;
	}

	local_path = talloc_asprintf(mem_ctx, "%s/%s", unix_path, GPT_INI);
	NT_STATUS_HAVE_NO_MEMORY(local_path);

	status = parse_gpt_ini(mem_ctx, local_path, &version, &name);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("gpo_get_sysvol_gpt_version: "
			"failed to parse ini [%s]: %s\n",
			local_path, nt_errstr(status)));
		return status;
	}

	if (sysvol_version) {
		*sysvol_version = version;
	}

	if (name && *display_name) {
		*display_name = talloc_strdup(mem_ctx, name);
		NT_STATUS_HAVE_NO_MEMORY(*display_name);
	}

	return NT_STATUS_OK;
}
