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
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

struct torture_suite *gpo_apply_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "apply");

	torture_suite_add_simple_test(suite, "gpo_system_access_policies",
				      torture_gpo_system_access_policies);
	torture_suite_add_simple_test(suite, "gpo_disable_policies",
				      torture_gpo_disable_policies);
	torture_suite_add_simple_test(suite,
				      "gpo_environment_variables_policies",
				   torture_gpo_environment_variables_policies);
	torture_suite_add_simple_test(suite, "gpo_bad_env_var",
				      torture_gpo_bad_env_var);
	torture_suite_add_simple_test(suite, "torture_gpo_user_proxy_policy",
				      torture_gpo_user_proxy_policy);

	suite->description = talloc_strdup(suite, "Group Policy apply tests");

	return suite;
}

static int exec_wait(char **cmd)
{
	int ret;
	pid_t pid = fork();
	switch (pid) {
		case 0:
			execv(cmd[0], &(cmd[1]));
			ret = -1;
			break;
		case -1:
			ret = errno;
			break;
		default:
			if (waitpid(pid, &ret, 0) < 0)
				ret = errno;
			break;
	}
	return ret;
}

static int unix2nttime(const char *sval)
{
	return (strtoll(sval, NULL, 10) * -1 / 60 / 60 / 24 / 10000000);
}

#define GPODIR "addom.samba.example.com/Policies/"\
	       "{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/"\
	       "Windows NT/SecEdit"
#define GPOFILE "GptTmpl.inf"
#define GPTTMPL "[System Access]\n\
MinimumPasswordAge = %d\n\
MaximumPasswordAge = %d\n\
MinimumPasswordLength = %d\n\
PasswordComplexity = %d\n\
"
#define GPTINI "addom.samba.example.com/Policies/"\
	       "{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI"

#define ENVPATH "addom.samba.example.com/Policies/"\
		"{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/"\
		"Preferences/EnvironmentVariables"
#define ENVXML "EnvironmentVariables.xml"
#define ENVTMPL "\
<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<EnvironmentVariables clsid=\"{BF141A63-327B-438a-B9BF-2C188F13B7AD}\">\
<EnvironmentVariable clsid=\"{78570023-8373-4a19-BA80-2F150738EA19}\"\
	name=\"PATH\" status=\"PATH = %s\" image=\"2\"\
	uid=\"{B048DE7E-9B24-497C-B798-17708F7B33C5}\">\
<Properties action=\"%s\" name=\"PATH\" value=\"%s\" user=\"0\"\
	partial=\"%s\"/>\
</EnvironmentVariable>\
</EnvironmentVariables>\
"
#define RESENV "#\n\
# Samba GPO Section\n\
# These settings are applied via GPO\n\
#\n\
PATH=%s\n\
#\n\
# End Samba GPO Section\n\
#"

static void increment_gpt_ini(TALLOC_CTX *ctx, const char *gpt_file)
{
	FILE *fp = NULL;
	int vers = 0;

	/* Update the version in the GPT.INI */
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
		char *data = talloc_asprintf(ctx,
					     "[General]\nVersion=%d\n",
					     ++vers);
		fputs(data, fp);
		fclose(fp);
	}
}

static bool exec_gpo_update_command(struct torture_context *tctx, bool machine,
				    const char *user, const char *pass)
{
	TALLOC_CTX *ctx = talloc_new(tctx);
	char **gpo_cmd;
	const char **gpo_update_cmd;
	int gpo_update_len = 0;
	const char **itr;
	int ret = 0, i;

	/* Get the gpo update command */
	gpo_update_cmd = lpcfg_gpo_update_command(tctx->lp_ctx);
	torture_assert(tctx, gpo_update_cmd && gpo_update_cmd[0],
		       "Failed to fetch the gpo update command");

	for (itr = gpo_update_cmd; *itr != NULL; itr++) {
		gpo_update_len++;
	}
	gpo_cmd = talloc_array(ctx, char*, gpo_update_len+3);
	for (i = 0; i < gpo_update_len; i++) {
		gpo_cmd[i] = talloc_strdup(gpo_cmd,
					   gpo_update_cmd[i]);
	}
	if (machine) {
		gpo_cmd[i] = talloc_asprintf(gpo_cmd, "--machine");
		gpo_cmd[i+1] = NULL;
	} else {
		gpo_cmd[i] = talloc_asprintf(gpo_cmd, "--username=%s", user);
		gpo_cmd[i+1] = talloc_asprintf(gpo_cmd,
					       "--password=%s", pass);
		gpo_cmd[i+2] = NULL;
	}

	/* Run the gpo update command */
	ret = exec_wait(gpo_cmd);
	torture_assert(tctx, ret == 0,
		       "Failed to execute the gpo update command");

	talloc_free(ctx);
	return true;
}

static bool exec_gpo_unapply_command(struct torture_context *tctx,
				     bool machine,
				     const char *user, const char *pass)
{
	TALLOC_CTX *ctx = talloc_new(tctx);
	char **gpo_cmd;
	const char **gpo_update_cmd;
	int gpo_update_len = 0;
	const char **itr;
	int ret = 0, i;

	/* Get the gpo update command */
	gpo_update_cmd = lpcfg_gpo_update_command(tctx->lp_ctx);
	torture_assert(tctx, gpo_update_cmd && gpo_update_cmd[0],
		       "Failed to fetch the gpo update command");

	for (itr = gpo_update_cmd; *itr != NULL; itr++) {
		gpo_update_len++;
	}
	gpo_cmd = talloc_array(ctx, char*, gpo_update_len+4);
	for (i = 0; i < gpo_update_len; i++) {
		gpo_cmd[i] = talloc_strdup(gpo_cmd, gpo_update_cmd[i]);
	}
	if (machine) {
		gpo_cmd[i] = talloc_asprintf(gpo_cmd, "--machine");
		gpo_cmd[i+1] = talloc_asprintf(gpo_cmd, "--unapply");
		gpo_cmd[i+2] = NULL;
	} else {
		gpo_cmd[i] = talloc_asprintf(gpo_cmd, "--unapply");
		gpo_cmd[i+1] = talloc_asprintf(gpo_cmd,
					       "--username=%s", user);
		gpo_cmd[i+2] = talloc_asprintf(gpo_cmd,
					       "--password=%s", pass);
		gpo_cmd[i+3] = NULL;
	}
	ret = exec_wait(gpo_cmd);
	torture_assert(tctx, ret == 0,
		       "Failed to execute the gpo unapply command");

	talloc_free(ctx);
	return true;
}

bool torture_gpo_system_access_policies(struct torture_context *tctx)
{
	TALLOC_CTX *ctx = talloc_new(tctx);
	int ret, i;
	const char *sysvol_path = NULL, *gpo_dir = NULL;
	const char *gpo_file = NULL, *gpt_file = NULL;
	struct ldb_context *samdb = NULL;
	struct ldb_result *result;
	const char *attrs[] = {
		"minPwdAge",
		"maxPwdAge",
		"minPwdLength",
		"pwdProperties",
		NULL
	};
	FILE *fp = NULL;
	int minpwdcases[] = { 0, 1, 998 };
	int maxpwdcases[] = { 0, 1, 999 };
	int pwdlencases[] = { 0, 1, 14 };
	int pwdpropcases[] = { 0, 1, 1 };
	struct ldb_message *old_message = NULL;

	sysvol_path = lpcfg_path(lpcfg_service(tctx->lp_ctx, "sysvol"),
				 lpcfg_default_service(tctx->lp_ctx), tctx);
	torture_assert(tctx, sysvol_path, "Failed to fetch the sysvol path");

	/* Ensure the sysvol path exists */
	gpo_dir = talloc_asprintf(ctx, "%s/%s", sysvol_path, GPODIR);
	mkdir_p(gpo_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	gpo_file = talloc_asprintf(ctx, "%s/%s", gpo_dir, GPOFILE);

	/* Open and read the samba db and store the initial password settings */
	samdb = samdb_connect(ctx, tctx->ev, tctx->lp_ctx,
			      system_session(tctx->lp_ctx), 0);
	torture_assert(tctx, samdb, "Failed to connect to the samdb");

	ret = ldb_search(samdb, ctx, &result, ldb_get_default_basedn(samdb),
			 LDB_SCOPE_BASE, attrs, NULL);
	torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1,
		       "Searching the samdb failed");

	old_message = result->msgs[0];

	for (i = 0; i < 3; i++) {
		/* Write out the sysvol */
		if ( (fp = fopen(gpo_file, "w")) ) {
			fputs(talloc_asprintf(ctx, GPTTMPL, minpwdcases[i],
					      maxpwdcases[i], pwdlencases[i],
					      pwdpropcases[i]), fp);
			fclose(fp);
		}

		gpt_file = talloc_asprintf(ctx, "%s/%s", sysvol_path, GPTINI);
		increment_gpt_ini(ctx, gpt_file);

		exec_gpo_update_command(tctx, true, NULL, NULL);

		ret = ldb_search(samdb, ctx, &result,
				 ldb_get_default_basedn(samdb),
				 LDB_SCOPE_BASE, attrs, NULL);
		torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1,
			       "Searching the samdb failed");

		/* minPwdAge */
		torture_assert_int_equal(tctx, unix2nttime(
						ldb_msg_find_attr_as_string(
							result->msgs[0],
							attrs[0],
							"")), minpwdcases[i],
			       "The minPwdAge was not applied");

		/* maxPwdAge */
		torture_assert_int_equal(tctx, unix2nttime(
						ldb_msg_find_attr_as_string(
							result->msgs[0],
							attrs[1],
							"")), maxpwdcases[i],
			       "The maxPwdAge was not applied");

		/* minPwdLength */
		torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
							result->msgs[0],
							attrs[2],
							-1),
					       pwdlencases[i],
				"The minPwdLength was not applied");

		/* pwdProperties */
		torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
							result->msgs[0],
							attrs[3],
							-1),
					       pwdpropcases[i],
			       "The pwdProperties were not applied");
	}

	/* Unapply the settings and verify they are removed */
	exec_gpo_unapply_command(tctx, true, NULL, NULL);

	ret = ldb_search(samdb, ctx, &result, ldb_get_default_basedn(samdb),
			 LDB_SCOPE_BASE, attrs, NULL);
	torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1,
		       "Searching the samdb failed");
	/* minPwdAge */
	torture_assert_int_equal(tctx, unix2nttime(ldb_msg_find_attr_as_string(
						result->msgs[0],
						attrs[0],
						"")),
		       unix2nttime(ldb_msg_find_attr_as_string(old_message,
							       attrs[0],
							       "")
				  ),
		       "The minPwdAge was not unapplied");
	/* maxPwdAge */
	torture_assert_int_equal(tctx, unix2nttime(ldb_msg_find_attr_as_string(
						result->msgs[0],
						attrs[1],
						"")),
		       unix2nttime(ldb_msg_find_attr_as_string(old_message,
							       attrs[1],
							       "")
				  ),
		       "The maxPwdAge was not unapplied");
	/* minPwdLength */
	torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
						result->msgs[0],
						attrs[2],
						-1),
				       ldb_msg_find_attr_as_int(
						old_message,
						attrs[2],
						-2),
			"The minPwdLength was not unapplied");
	/* pwdProperties */
	torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
						result->msgs[0],
						attrs[3],
						-1),
					ldb_msg_find_attr_as_int(
						old_message,
						attrs[3],
						-2),
			"The pwdProperties were not unapplied");

	talloc_free(ctx);
	return true;
}

bool torture_gpo_disable_policies(struct torture_context *tctx)
{
	TALLOC_CTX *ctx = talloc_new(tctx);
	int ret, i;
	const char *sysvol_path = NULL, *gpo_dir = NULL;
	const char *gpo_file = NULL, *gpt_file = NULL;
	struct ldb_context *samdb = NULL;
	struct ldb_result *result;
	const char *attrs[] = {
		"minPwdAge",
		"maxPwdAge",
		"minPwdLength",
		"pwdProperties",
		NULL
	};
	FILE *fp = NULL;
	int minpwdcases[] = { 0, 1, 998 };
	int maxpwdcases[] = { 0, 1, 999 };
	int pwdlencases[] = { 0, 1, 14 };
	int pwdpropcases[] = { 0, 1, 1 };
	struct ldb_message *old_message = NULL;
	const char *disable_file = "bin/python/samba/gp_sec_ext.py.disabled";

	sysvol_path = lpcfg_path(lpcfg_service(tctx->lp_ctx, "sysvol"),
				 lpcfg_default_service(tctx->lp_ctx), tctx);
	torture_assert(tctx, sysvol_path, "Failed to fetch the sysvol path");

	/* Ensure the sysvol path exists */
	gpo_dir = talloc_asprintf(ctx, "%s/%s", sysvol_path, GPODIR);
	mkdir_p(gpo_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	gpo_file = talloc_asprintf(ctx, "%s/%s", gpo_dir, GPOFILE);

	/* Open and read the samba db and store the initial password settings */
	samdb = samdb_connect(ctx, tctx->ev, tctx->lp_ctx,
			      system_session(tctx->lp_ctx), 0);
	torture_assert(tctx, samdb, "Failed to connect to the samdb");

	ret = ldb_search(samdb, ctx, &result, ldb_get_default_basedn(samdb),
			 LDB_SCOPE_BASE, attrs, NULL);
	torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1,
		       "Searching the samdb failed");

	old_message = result->msgs[0];

	/* Disable the policy */
	open(disable_file, O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK, 0666);

	for (i = 0; i < 3; i++) {
		/* Write out the sysvol */
		if ( (fp = fopen(gpo_file, "w")) ) {
			fputs(talloc_asprintf(ctx, GPTTMPL, minpwdcases[i],
					      maxpwdcases[i], pwdlencases[i],
					      pwdpropcases[i]), fp);
			fclose(fp);
		}

		gpt_file = talloc_asprintf(ctx, "%s/%s", sysvol_path, GPTINI);
		increment_gpt_ini(ctx, gpt_file);

		exec_gpo_update_command(tctx, true, NULL, NULL);

		ret = ldb_search(samdb, ctx, &result,
				 ldb_get_default_basedn(samdb),
				 LDB_SCOPE_BASE, attrs, NULL);
		torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1,
			       "Searching the samdb failed");
		/* minPwdAge */
		torture_assert_int_equal(tctx, unix2nttime(
			ldb_msg_find_attr_as_string(
				result->msgs[0],
				attrs[0],
				"")
			),
			unix2nttime(ldb_msg_find_attr_as_string(old_message,
				attrs[0],
				"")
			),
			"The minPwdAge should not have been applied");
		/* maxPwdAge */
		torture_assert_int_equal(tctx, unix2nttime(
			ldb_msg_find_attr_as_string(
				result->msgs[0],
				attrs[1],
				"")
			),
			unix2nttime(ldb_msg_find_attr_as_string(old_message,
				attrs[1],
				"")
			),
			"The maxPwdAge should not have been applied");
		/* minPwdLength */
		torture_assert_int_equal(tctx,
			ldb_msg_find_attr_as_int(
				result->msgs[0],
				attrs[2],
				-1
			),
			ldb_msg_find_attr_as_int(
				old_message,
				attrs[2],
				-2
			),
			"The minPwdLength should not have been applied");
		/* pwdProperties */
		torture_assert_int_equal(tctx,
			ldb_msg_find_attr_as_int(
				result->msgs[0],
				attrs[3],
				-1
			),
			ldb_msg_find_attr_as_int(
				old_message,
				attrs[3],
				-2
			),
			"The pwdProperties should not have been applied");
	}

	/* Unapply the settings and verify they are removed */
	exec_gpo_unapply_command(tctx, true, NULL, NULL);

	/* Re-enable the policy */
	remove(disable_file);

	talloc_free(ctx);
	return true;
}

bool torture_gpo_environment_variables_policies(struct torture_context *tctx)
{
	TALLOC_CTX *ctx = talloc_new(tctx);
	const char *env_dir = NULL, *env_xml = NULL, *smbconf = NULL;
	const char *sysvol_path = NULL, *gpt_file = NULL;
	char *profile = NULL;
	const char *envcases[][4] = {
		{ "", "D", "0" },
		{ "/bin", "U", "0" },
		{ "/bin", "U", "1" },
	};
	const char *envres[] = {
		"",
		"/bin",
		"$PATH:/bin",
		NULL,
	};
	char *envexpected = NULL, *envreturned = NULL;
	size_t envlen = 0;
	int fd, i;
	FILE *fp = NULL;

	/* Ensure the sysvol path exists */
	sysvol_path = lpcfg_path(lpcfg_service(tctx->lp_ctx, "sysvol"),
				 lpcfg_default_service(tctx->lp_ctx), tctx);
	torture_assert(tctx, sysvol_path, "Failed to fetch the sysvol path");
	env_dir = talloc_asprintf(ctx, "%s/%s", sysvol_path, ENVPATH);
	mkdir_p(env_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	env_xml = talloc_asprintf(ctx, "%s/%s", env_dir, ENVXML);

	smbconf = lpcfg_configfile(tctx->lp_ctx);
	profile = talloc_strndup(ctx, smbconf, strlen(smbconf)-8);
	profile = talloc_strdup_append(profile, "profile");

	for (i = 0; i < 3; i++) {
		if ( (fp = fopen(env_xml, "w")) ) {
			fputs(talloc_asprintf(ctx, ENVTMPL, envcases[i][0],
					      envcases[i][1], envcases[i][0],
					      envcases[i][2]), fp);
			fclose(fp);
		}
		gpt_file = talloc_asprintf(ctx, "%s/%s", sysvol_path, GPTINI);
		increment_gpt_ini(ctx, gpt_file);

		exec_gpo_update_command(tctx, true, NULL, NULL);

		/* Machine env var policy */
		envexpected = talloc_asprintf(ctx, RESENV, envres[i]);
		fd = open(profile, O_RDONLY);
		envlen = strlen(envexpected);
		torture_assert(tctx, lseek(fd, -envlen,
					   SEEK_END) != -1,
			      "Failed to seek to start position in profile");
		envreturned = talloc_array(ctx, char, envlen);
		torture_assert(tctx, read(fd, envreturned, envlen) == envlen,
				"Failed to read from profile");
		torture_assert(tctx, strncmp(envexpected, envreturned, envlen)\
				     == 0,
				"Environment variable policy was not applied");
	}

	/* Unapply the settings and verify they are removed */
	exec_gpo_unapply_command(tctx, true, NULL, NULL);

	/* Machine env var policy */
	fd = open(profile, O_RDONLY);
	if (lseek(fd, -envlen, SEEK_END) != -1) {
		if (read(fd, envreturned, envlen) == envlen) {
			torture_assert(tctx, strncmp(envexpected, envreturned,
						     envlen) != 0,
			    "Environment variable policy was not unapplied");
		}
	}

	talloc_free(ctx);
	return true;
}

bool torture_gpo_bad_env_var(struct torture_context *tctx)
{
	TALLOC_CTX *ctx = talloc_new(tctx);
	const char *env_dir = NULL, *env_xml = NULL, *smbconf = NULL;
	const char *sysvol_path = NULL, *gpt_file = NULL;
	char *profile = NULL;
	const char *envcases[][4] = {
		{ "C:\\WINDOWS\\system32", "U", "0" },
		{ "\%USERPROFILE\%\\bin", "U", "0" },
		{ "/foo;/bar", "U", "0" },
	};
	int i;
	FILE *fp = NULL;
	struct stat *finfo = talloc_zero(ctx, struct stat);

	/* Ensure the sysvol path exists */
	sysvol_path = lpcfg_path(lpcfg_service(tctx->lp_ctx, "sysvol"),
				 lpcfg_default_service(tctx->lp_ctx), tctx);
	torture_assert(tctx, sysvol_path, "Failed to fetch the sysvol path");
	env_dir = talloc_asprintf(ctx, "%s/%s", sysvol_path, ENVPATH);
	mkdir_p(env_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	env_xml = talloc_asprintf(ctx, "%s/%s", env_dir, ENVXML);

	smbconf = lpcfg_configfile(tctx->lp_ctx);
	profile = talloc_strndup(ctx, smbconf, strlen(smbconf)-8);
	profile = talloc_strdup_append(profile, "profile");

	for (i = 0; i < 3; i++) {
		if ( (fp = fopen(env_xml, "w")) ) {
			fputs(talloc_asprintf(ctx, ENVTMPL, envcases[i][0],
					      envcases[i][1], envcases[i][0],
					      envcases[i][2]), fp);
			fclose(fp);
		}
		gpt_file = talloc_asprintf(ctx, "%s/%s", sysvol_path, GPTINI);
		increment_gpt_ini(ctx, gpt_file);

		exec_gpo_update_command(tctx, true, NULL, NULL);

		/* Make sure the profile is either not there, or empty */
		if (access(profile, F_OK) == 0) {
			if (stat(profile, finfo) == 0) {
				torture_assert_int_equal(tctx,
					finfo->st_size, 0,
					"The profile was not zero bytes");
			}
		}
	}

	/* Unapply the settings */
	exec_gpo_unapply_command(tctx, true, NULL, NULL);

	talloc_free(ctx);
	return true;
}

#define PROXYPATH "addom.samba.example.com/Policies/"\
		  "{31B2F340-016D-11D2-945F-00C04FB984F9}/USER/"\
		  "MICROSOFT/IEAK"
#define PROXYFILE "install.ins"

#define PROXYTMPL "[Proxy]\n\
Proxy_Enable=%s\n\
HTTP_Proxy_Server=%s\n\
Use_Same_Proxy=%s\n\
%s\
"
#define PROXYTMPLEXT "\
FTP_Proxy_Server=%s\n\
Secure_Proxy_Server=%s\n\
"
#define TESTUSER "alice"
#define TESTPASS "Secret007"

bool torture_gpo_user_proxy_policy(struct torture_context *tctx)
{
	TALLOC_CTX *ctx = talloc_new(tctx);
	int ret, i;
	const char *sysvol_path = NULL, *proxy_dir = NULL;
	const char *proxy_file = NULL, *gpt_file = NULL;
	FILE *fp = NULL;
	const char *use_same[] = {
		"proxy2.example.com:8080",
		"proxy3.example.com:8080"
	};
	const char *proxycases[][4] = {
		{ "1", "proxy.example.com:8080", "1", "" },
		{ "1", "proxy.example.com:8080", "0",
		  talloc_asprintf(ctx, PROXYTMPLEXT,
				  use_same[0],
				  use_same[1]) },
		{ "1", "proxy.example.com:8080", "1",
		  talloc_asprintf(ctx, PROXYTMPLEXT,
				  use_same[0],
				  use_same[1]) },
		{ "0", "proxy.example.com:8080", "0",
		  talloc_asprintf(ctx, PROXYTMPLEXT,
				  use_same[0],
				  use_same[1]) },
		{ "0", "proxy.example.com:8080", "1", "" },
	};
	char *profile = NULL;
	struct stat *finfo = talloc_zero(ctx, struct stat);
	struct passwd *pwd = NULL;
	char *profile_data = NULL;

	/* Ensure the sysvol path exists */
	sysvol_path = lpcfg_path(lpcfg_service(tctx->lp_ctx, "sysvol"),
				 lpcfg_default_service(tctx->lp_ctx), tctx);
	torture_assert(tctx, sysvol_path, "Failed to fetch the sysvol path");
	proxy_dir = talloc_asprintf(ctx, "%s/%s", sysvol_path, PROXYPATH);
	mkdir_p(proxy_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	proxy_file = talloc_asprintf(ctx, "%s/%s", proxy_dir, PROXYFILE);

	pwd = getpwnam(TESTUSER);
	mkdir_p(pwd->pw_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	profile = talloc_asprintf(ctx, "%s/.profile", pwd->pw_dir);

	for (i = 0; i < sizeof(proxycases)/sizeof(proxycases[0]); i++) {
		if ( (fp = fopen(proxy_file, "w")) ) {
			fputs(talloc_asprintf(ctx, PROXYTMPL,
					      proxycases[i][0],
					      proxycases[i][1],
					      proxycases[i][2],
					      proxycases[i][3]), fp);
			fclose(fp);
		}
		gpt_file = talloc_asprintf(ctx, "%s/%s", sysvol_path, GPTINI);
		increment_gpt_ini(ctx, gpt_file);

		exec_gpo_update_command(tctx, false, TESTUSER, TESTPASS);

		/* test that things are applied here */
		torture_assert(tctx, access(profile, F_OK) == 0,
			       "The profile does not exist");
		torture_assert(tctx, stat(profile, finfo) == 0,
			       "Failed to stat the profile");
		profile_data = talloc_zero_size(ctx, finfo->st_size);
		fp = fopen(profile, "rb");
		fread(profile_data, 1, finfo->st_size, fp);

		if (atoi(proxycases[i][0]) == 1) {
			torture_assert(tctx, strstr(profile_data,
				       talloc_asprintf(ctx, "http_proxy=%s",
						       proxycases[i][1]))
				       != NULL,
				       "Failed to find http_proxy in profile");
			if (atoi(proxycases[i][2]) == 0) {
				torture_assert(tctx, strstr(profile_data,
					talloc_asprintf(ctx, "ftp_proxy=%s",
							use_same[0]))
					!= NULL,
					"Failed to find ftp_proxy in profile");
				torture_assert(tctx, strstr(profile_data,
					talloc_asprintf(ctx, "https_proxy=%s",
							use_same[1]))
					!= NULL,
				"Failed to find https_proxy in profile");
			} else {
				torture_assert(tctx, strstr(profile_data,
					talloc_asprintf(ctx, "ftp_proxy=%s",
							use_same[0]))
					== NULL,
					"ftp_proxy should NOT have been set");
				torture_assert(tctx, strstr(profile_data,
					talloc_asprintf(ctx, "https_proxy=%s",
							use_same[1]))
					== NULL,
				"https_proxy should NOT have been set");
			}
		} else {
			torture_assert(tctx, strstr(profile_data,
				       talloc_asprintf(ctx, "http_proxy=%s",
						       proxycases[i][1]))
				       == NULL,
				       "http_proxy should NOT have been set");
			torture_assert(tctx, strstr(profile_data,
				       talloc_asprintf(ctx, "ftp_proxy=%s",
						       use_same[0]))
				       == NULL,
				       "ftp_proxy should NOT have been set");
			torture_assert(tctx, strstr(profile_data,
				       talloc_asprintf(ctx, "https_proxy=%s",
						       use_same[1]))
				       == NULL,
				       "https_proxy should NOT have been set");
		}
	}

	exec_gpo_unapply_command(tctx, false, TESTUSER, TESTPASS);

	/* Make sure the profile is either not there, or empty */
	if (access(profile, F_OK) == 0) {
		if (stat(profile, finfo) == 0) {
			if (finfo->st_size != 0) {
				torture_assert(tctx, strstr(profile_data,
					talloc_asprintf(ctx, "http_proxy=%s",
							proxycases[i][1]))
					== NULL,
					"http_proxy should NOT have been set");
				torture_assert(tctx, strstr(profile_data,
					talloc_asprintf(ctx, "ftp_proxy=%s",
							use_same[0]))
					== NULL,
					"ftp_proxy should NOT have been set");
				torture_assert(tctx, strstr(profile_data,
					talloc_asprintf(ctx, "https_proxy=%s",
							use_same[1]))
					== NULL,
				"https_proxy should NOT have been set");
				torture_assert(tctx, strstr(profile_data,
					       "use_same_proxy=") == NULL,
				"use_same_proxy should NOT have been set");
				torture_assert(tctx, strstr(profile_data,
					       "proxy_enable=") == NULL,
				"proxy_enable should NOT have been set");
			}
		}
	}

	talloc_free(ctx);
	return true;
}
