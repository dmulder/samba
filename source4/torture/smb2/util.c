/* 
   Unix SMB/CIFS implementation.

   helper functions for SMB2 test suite

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/security/security_descriptor.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/cmdline/popt_common.h"
#include "system/time.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"
#include "lib/util/tevent_ntstatus.h"

#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "source4/torture/util.h"
#include "libcli/smb_composite/smb_composite.h"


/*
  write to a file on SMB2
*/
NTSTATUS smb2_util_write(struct smb2_tree *tree,
			 struct smb2_handle handle, 
			 const void *buf, off_t offset, size_t size)
{
	struct smb2_write w;

	ZERO_STRUCT(w);
	w.in.file.handle = handle;
	w.in.offset      = offset;
	w.in.data        = data_blob_const(buf, size);

	return smb2_write(tree, &w);
}

/*
  create a complex file/dir using the SMB2 protocol
*/
static NTSTATUS smb2_create_complex(struct torture_context *tctx,
				    struct smb2_tree *tree,
				    const char *fname,
				    struct smb2_handle *handle,
				    bool dir)
{
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	char buf[7] = "abc";
	struct smb2_create io;
	union smb_setfileinfo setfile;
	union smb_fileinfo fileinfo;
	time_t t = (time(NULL) & ~1);
	NTSTATUS status;

	smb2_util_unlink(tree, fname);
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = fname;
	if (dir) {
		io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
		io.in.share_access &= ~NTCREATEX_SHARE_ACCESS_DELETE;
		io.in.file_attributes   = FILE_ATTRIBUTE_DIRECTORY;
		io.in.create_disposition = NTCREATEX_DISP_CREATE;
	}

	/* it seems vista is now fussier about alignment? */
	if (strchr(fname, ':') == NULL) {
		/* setup some EAs */
		io.in.eas.num_eas = 2;
		io.in.eas.eas = talloc_array(tmp_ctx, struct ea_struct, 2);
		io.in.eas.eas[0].flags = 0;
		io.in.eas.eas[0].name.s = "EAONE";
		io.in.eas.eas[0].value = data_blob_talloc(tmp_ctx, "VALUE1", 6);
		io.in.eas.eas[1].flags = 0;
		io.in.eas.eas[1].name.s = "SECONDEA";
		io.in.eas.eas[1].value = data_blob_talloc(tmp_ctx, "ValueTwo", 8);
	}

	status = smb2_create(tree, tmp_ctx, &io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_EAS_NOT_SUPPORTED)) {
		torture_comment(
			tctx, "EAs not supported, creating: %s\n", fname);
		io.in.eas.num_eas = 0;
		status = smb2_create(tree, tmp_ctx, &io);
	}

	talloc_free(tmp_ctx);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.file.handle;

	if (!dir) {
		status = smb2_util_write(tree, *handle, buf, 0, sizeof(buf));
		NT_STATUS_NOT_OK_RETURN(status);
	}

	/* make sure all the timestamps aren't the same, and are also 
	   in different DST zones*/
	setfile.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	setfile.generic.in.file.handle = *handle;

	unix_to_nt_time(&setfile.basic_info.in.create_time, t + 9*30*24*60*60);
	unix_to_nt_time(&setfile.basic_info.in.access_time, t + 6*30*24*60*60);
	unix_to_nt_time(&setfile.basic_info.in.write_time,  t + 3*30*24*60*60);
	unix_to_nt_time(&setfile.basic_info.in.change_time, t + 1*30*24*60*60);
	setfile.basic_info.in.attrib      = FILE_ATTRIBUTE_NORMAL;

	status = smb2_setinfo_file(tree, &setfile);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to setup file times - %s\n", nt_errstr(status));
		return status;
	}

	/* make sure all the timestamps aren't the same */
	fileinfo.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	fileinfo.generic.in.file.handle = *handle;

	status = smb2_getinfo_file(tree, tree, &fileinfo);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to query file times - %s\n", nt_errstr(status));
		return status;
		
	}

#define CHECK_TIME(field) do {\
	if (setfile.basic_info.in.field != fileinfo.all_info2.out.field) { \
		torture_comment(tctx, "(%s) " #field " not setup correctly: %s(%llu) => %s(%llu)\n", \
			__location__, \
			nt_time_string(tree, setfile.basic_info.in.field), \
			(unsigned long long)setfile.basic_info.in.field, \
			nt_time_string(tree, fileinfo.basic_info.out.field), \
			(unsigned long long)fileinfo.basic_info.out.field); \
		status = NT_STATUS_INVALID_PARAMETER; \
	} \
} while (0)

	CHECK_TIME(create_time);
	CHECK_TIME(access_time);
	CHECK_TIME(write_time);
	CHECK_TIME(change_time);

	return status;
}

/*
  create a complex file using the SMB2 protocol
*/
NTSTATUS smb2_create_complex_file(struct torture_context *tctx,
				  struct smb2_tree *tree, const char *fname,
				  struct smb2_handle *handle)
{
	return smb2_create_complex(tctx, tree, fname, handle, false);
}

/*
  create a complex dir using the SMB2 protocol
*/
NTSTATUS smb2_create_complex_dir(struct torture_context *tctx,
				 struct smb2_tree *tree, const char *fname,
				 struct smb2_handle *handle)
{
	return smb2_create_complex(tctx, tree, fname, handle, true);
}

/*
  show lots of information about a file
*/
void torture_smb2_all_info(struct torture_context *tctx,
			   struct smb2_tree *tree, struct smb2_handle handle)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	union smb_fileinfo io;

	io.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	io.generic.in.file.handle = handle;

	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("getinfo failed - %s\n", nt_errstr(status)));
		talloc_free(tmp_ctx);
		return;
	}

	torture_comment(tctx, "all_info for '%s'\n", io.all_info2.out.fname.s);
	torture_comment(tctx, "\tcreate_time:    %s\n", nt_time_string(tmp_ctx, io.all_info2.out.create_time));
	torture_comment(tctx, "\taccess_time:    %s\n", nt_time_string(tmp_ctx, io.all_info2.out.access_time));
	torture_comment(tctx, "\twrite_time:     %s\n", nt_time_string(tmp_ctx, io.all_info2.out.write_time));
	torture_comment(tctx, "\tchange_time:    %s\n", nt_time_string(tmp_ctx, io.all_info2.out.change_time));
	torture_comment(tctx, "\tattrib:         0x%x\n", io.all_info2.out.attrib);
	torture_comment(tctx, "\tunknown1:       0x%x\n", io.all_info2.out.unknown1);
	torture_comment(tctx, "\talloc_size:     %llu\n", (long long)io.all_info2.out.alloc_size);
	torture_comment(tctx, "\tsize:           %llu\n", (long long)io.all_info2.out.size);
	torture_comment(tctx, "\tnlink:          %u\n", io.all_info2.out.nlink);
	torture_comment(tctx, "\tdelete_pending: %u\n", io.all_info2.out.delete_pending);
	torture_comment(tctx, "\tdirectory:      %u\n", io.all_info2.out.directory);
	torture_comment(tctx, "\tfile_id:        %llu\n", (long long)io.all_info2.out.file_id);
	torture_comment(tctx, "\tea_size:        %u\n", io.all_info2.out.ea_size);
	torture_comment(tctx, "\taccess_mask:    0x%08x\n", io.all_info2.out.access_mask);
	torture_comment(tctx, "\tposition:       0x%llx\n", (long long)io.all_info2.out.position);
	torture_comment(tctx, "\tmode:           0x%llx\n", (long long)io.all_info2.out.mode);

	/* short name, if any */
	io.generic.level = RAW_FILEINFO_ALT_NAME_INFORMATION;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	if (NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "\tshort name:     '%s'\n", io.alt_name_info.out.fname.s);
	}

	/* the EAs, if any */
	io.generic.level = RAW_FILEINFO_SMB2_ALL_EAS;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	if (NT_STATUS_IS_OK(status)) {
		int i;
		for (i=0;i<io.all_eas.out.num_eas;i++) {
			torture_comment(tctx, "\tEA[%d] flags=%d len=%d '%s'\n", i,
				 io.all_eas.out.eas[i].flags,
				 (int)io.all_eas.out.eas[i].value.length,
				 io.all_eas.out.eas[i].name.s);
		}
	}

	/* streams, if available */
	io.generic.level = RAW_FILEINFO_STREAM_INFORMATION;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	if (NT_STATUS_IS_OK(status)) {
		int i;
		for (i=0;i<io.stream_info.out.num_streams;i++) {
			torture_comment(tctx, "\tstream %d:\n", i);
			torture_comment(tctx, "\t\tsize       %ld\n",
				 (long)io.stream_info.out.streams[i].size);
			torture_comment(tctx, "\t\talloc size %ld\n",
				 (long)io.stream_info.out.streams[i].alloc_size);
			torture_comment(tctx, "\t\tname       %s\n", io.stream_info.out.streams[i].stream_name.s);
		}
	}	

	if (DEBUGLVL(1)) {
		/* the security descriptor */
		io.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
		io.query_secdesc.in.secinfo_flags = 
			SECINFO_OWNER|SECINFO_GROUP|
			SECINFO_DACL;
		status = smb2_getinfo_file(tree, tmp_ctx, &io);
		if (NT_STATUS_IS_OK(status)) {
			NDR_PRINT_DEBUG(security_descriptor, io.query_secdesc.out.sd);
		}
	}

	talloc_free(tmp_ctx);	
}

/*
  get granted access of a file handle
*/
NTSTATUS torture_smb2_get_allinfo_access(struct smb2_tree *tree,
					 struct smb2_handle handle,
					 uint32_t *granted_access)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	union smb_fileinfo io;

	io.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	io.generic.in.file.handle = handle;

	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("getinfo failed - %s\n", nt_errstr(status)));
		goto out;
	}

	*granted_access = io.all_info2.out.access_mask;

out:
	talloc_free(tmp_ctx);
	return status;
}

/**
 * open a smb2 tree connect
 */
bool torture_smb2_tree_connect(struct torture_context *tctx,
			       struct smb2_session *session,
			       TALLOC_CTX *mem_ctx,
			       struct smb2_tree **_tree)
{
	NTSTATUS status;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	const char *unc;
	struct smb2_tree *tree;
	struct tevent_req *subreq;
	uint32_t timeout_msec;

	unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	torture_assert(tctx, unc != NULL, "talloc_asprintf");

	tree = smb2_tree_init(session, mem_ctx, false);
	torture_assert(tctx, tree != NULL, "smb2_tree_init");

	timeout_msec = session->transport->options.request_timeout * 1000;

	subreq = smb2cli_tcon_send(tree, tctx->ev,
				   session->transport->conn,
				   timeout_msec,
				   session->smbXcli,
				   tree->smbXcli,
				   0, /* flags */
				   unc);
	torture_assert(tctx, subreq != NULL, "smb2cli_tcon_send");

	torture_assert(tctx,
		       tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
		       "tevent_req_poll_ntstatus");

	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	torture_assert_ntstatus_ok(tctx, status, "smb2cli_tcon_recv");

	*_tree = tree;

	return true;
}

/**
 * do a smb2 session setup (without a tree connect)
 */
bool torture_smb2_session_setup(struct torture_context *tctx,
				struct smb2_transport *transport,
				uint64_t previous_session_id,
				TALLOC_CTX *mem_ctx,
				struct smb2_session **_session)
{
	NTSTATUS status;
	struct smb2_session *session;

	session = smb2_session_init(transport,
				    lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				    mem_ctx);

	if (session == NULL) {
		return false;
	}

	status = smb2_session_setup_spnego(session,
					   popt_get_cmdline_credentials(),
					   previous_session_id);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "session setup failed: %s\n", nt_errstr(status));
		talloc_free(session);
		return false;
	}

	*_session = session;

	return true;
}

/*
  open a smb2 connection
*/
bool torture_smb2_connection_ext(struct torture_context *tctx,
				 uint64_t previous_session_id,
				 const struct smbcli_options *options,
				 struct smb2_tree **tree)
{
	NTSTATUS status;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	const char *p = torture_setting_string(tctx, "unclist", NULL);
	TALLOC_CTX *mem_ctx = NULL;
	bool ok;

	if (p != NULL) {
		char *host2 = NULL;
		char *share2 = NULL;

		mem_ctx = talloc_new(tctx);
		if (mem_ctx == NULL) {
			return false;
		}

		ok = torture_get_conn_index(tctx->conn_index++, mem_ctx, tctx,
					    &host2, &share2);
		if (!ok) {
			TALLOC_FREE(mem_ctx);
			return false;
		}

		host = host2;
		share = share2;
	}

	status = smb2_connect_ext(tctx,
				  host,
				  lpcfg_smb_ports(tctx->lp_ctx),
				  share,
				  lpcfg_resolve_context(tctx->lp_ctx),
				  popt_get_cmdline_credentials(),
				  previous_session_id,
				  tree,
				  tctx->ev,
				  options,
				  lpcfg_socket_options(tctx->lp_ctx),
				  lpcfg_gensec_settings(tctx, tctx->lp_ctx)
				  );
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to connect to SMB2 share \\\\%s\\%s - %s\n",
		       host, share, nt_errstr(status));
		TALLOC_FREE(mem_ctx);
		return false;
	}

	TALLOC_FREE(mem_ctx);
	return true;
}

bool torture_smb2_connection(struct torture_context *tctx, struct smb2_tree **tree)
{
	bool ret;
	struct smbcli_options options;

	lpcfg_smbcli_options(tctx->lp_ctx, &options);

	ret = torture_smb2_connection_ext(tctx, 0, &options, tree);

	return ret;
}

/**
 * SMB2 connect with share from soption
 **/
bool torture_smb2_con_sopt(struct torture_context *tctx,
			   const char *soption,
			   struct smb2_tree **tree)
{
	struct smbcli_options options;
	NTSTATUS status;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, soption, NULL);

	lpcfg_smbcli_options(tctx->lp_ctx, &options);

	if (share == NULL) {
		torture_comment(tctx, "No share for option %s\n", soption);
		return false;
	}

	status = smb2_connect_ext(tctx,
				  host,
				  lpcfg_smb_ports(tctx->lp_ctx),
				  share,
				  lpcfg_resolve_context(tctx->lp_ctx),
				  popt_get_cmdline_credentials(),
				  0,
				  tree,
				  tctx->ev,
				  &options,
				  lpcfg_socket_options(tctx->lp_ctx),
				  lpcfg_gensec_settings(tctx, tctx->lp_ctx)
				  );
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to connect to SMB2 share \\\\%s\\%s - %s\n",
		       host, share, nt_errstr(status));
		return false;
	}
	return true;
}

/*
  create and return a handle to a test file
  with a specific access mask
*/
NTSTATUS torture_smb2_testfile_access(struct smb2_tree *tree, const char *fname,
				      struct smb2_handle *handle,
				      uint32_t desired_access)
{
	struct smb2_create io;
	NTSTATUS status;

	ZERO_STRUCT(io);
	io.in.oplock_level = 0;
	io.in.desired_access = desired_access;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = fname;

	status = smb2_create(tree, tree, &io);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.file.handle;

	return NT_STATUS_OK;
}

/*
  create and return a handle to a test file
*/
NTSTATUS torture_smb2_testfile(struct smb2_tree *tree, const char *fname,
			       struct smb2_handle *handle)
{
	return torture_smb2_testfile_access(tree, fname, handle,
					    SEC_RIGHTS_FILE_ALL);
}

/*
  create and return a handle to a test file
  with a specific access mask
*/
NTSTATUS torture_smb2_open(struct smb2_tree *tree,
			   const char *fname,
			   uint32_t desired_access,
			   struct smb2_handle *handle)
{
	struct smb2_create io;
	NTSTATUS status;

	io = (struct smb2_create) {
		.in.fname = fname,
		.in.desired_access = desired_access,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
	};

	status = smb2_create(tree, tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*handle = io.out.file.handle;

	return NT_STATUS_OK;
}

/*
  create and return a handle to a test directory
  with specific desired access
*/
NTSTATUS torture_smb2_testdir_access(struct smb2_tree *tree, const char *fname,
				     struct smb2_handle *handle,
				     uint32_t desired_access)
{
	struct smb2_create io;
	NTSTATUS status;

	ZERO_STRUCT(io);
	io.in.oplock_level = 0;
	io.in.desired_access = desired_access;
	io.in.file_attributes   = FILE_ATTRIBUTE_DIRECTORY;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.fname = fname;

	status = smb2_create(tree, tree, &io);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.file.handle;

	return NT_STATUS_OK;
}

/*
  create and return a handle to a test directory
*/
NTSTATUS torture_smb2_testdir(struct smb2_tree *tree, const char *fname,
			      struct smb2_handle *handle)
{
	return torture_smb2_testdir_access(tree, fname, handle,
					   SEC_RIGHTS_DIR_ALL);
}

/*
  create a simple file using the SMB2 protocol
*/
NTSTATUS smb2_create_simple_file(struct torture_context *tctx,
				 struct smb2_tree *tree, const char *fname,
				 struct smb2_handle *handle)
{
	char buf[7] = "abc";
	NTSTATUS status;

	smb2_util_unlink(tree, fname);
	status = torture_smb2_testfile_access(tree,
					      fname, handle,
					      SEC_FLAG_MAXIMUM_ALLOWED);
	NT_STATUS_NOT_OK_RETURN(status);

	status = smb2_util_write(tree, *handle, buf, 0, sizeof(buf));
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}

/*
  create a simple file using SMB2.
*/
NTSTATUS torture_setup_simple_file(struct torture_context *tctx,
				   struct smb2_tree *tree, const char *fname)
{
	struct smb2_handle handle;
	NTSTATUS status = smb2_create_simple_file(tctx, tree, fname, &handle);
	NT_STATUS_NOT_OK_RETURN(status);
	return smb2_util_close(tree, handle);
}

/*
  create a complex file using SMB2, to make it easier to
  find fields in SMB2 getinfo levels
*/
NTSTATUS torture_setup_complex_file(struct torture_context *tctx,
				    struct smb2_tree *tree, const char *fname)
{
	struct smb2_handle handle;
	NTSTATUS status = smb2_create_complex_file(tctx, tree, fname, &handle);
	NT_STATUS_NOT_OK_RETURN(status);
	return smb2_util_close(tree, handle);
}


/*
  create a complex dir using SMB2, to make it easier to
  find fields in SMB2 getinfo levels
*/
NTSTATUS torture_setup_complex_dir(struct torture_context *tctx,
				   struct smb2_tree *tree, const char *fname)
{
	struct smb2_handle handle;
	NTSTATUS status = smb2_create_complex_dir(tctx, tree, fname, &handle);
	NT_STATUS_NOT_OK_RETURN(status);
	return smb2_util_close(tree, handle);
}


/*
  return a handle to the root of the share
*/
NTSTATUS smb2_util_roothandle(struct smb2_tree *tree, struct smb2_handle *handle)
{
	struct smb2_create io;
	NTSTATUS status;

	ZERO_STRUCT(io);
	io.in.oplock_level = 0;
	io.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_DIR_READ_ATTRIBUTE | SEC_DIR_LIST;
	io.in.file_attributes   = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options = NTCREATEX_OPTIONS_ASYNC_ALERT;
	io.in.fname = "";

	status = smb2_create(tree, tree, &io);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.file.handle;

	return NT_STATUS_OK;
}

/* Comparable to torture_setup_dir, but for SMB2. */
bool smb2_util_setup_dir(struct torture_context *tctx, struct smb2_tree *tree,
    const char *dname)
{
	NTSTATUS status;

	/* XXX: smb_raw_exit equivalent?
	smb_raw_exit(cli->session); */
	if (smb2_deltree(tree, dname) == -1) {
		torture_result(tctx, TORTURE_ERROR, "Unable to deltree when setting up %s.\n", dname);
		return false;
	}

	status = smb2_util_mkdir(tree, dname);
	if (NT_STATUS_IS_ERR(status)) {
		torture_result(tctx, TORTURE_ERROR, "Unable to mkdir when setting up %s - %s\n", dname,
		    nt_errstr(status));
		return false;
	}

	return true;
}

/*
  create a directory, returning a handle to it
*/
NTSTATUS smb2_create_directory_handle(struct smb2_tree *tree,
				      const char *dname,
				      struct smb2_handle *handle)
{
	NTSTATUS status;
	struct smb2_create io;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_named_const(tree, 0, "smb2_create_directory_handle");

	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = dname;

	status = smb2_create(tree, mem_ctx, &io);
	talloc_free(mem_ctx);

	if (NT_STATUS_IS_OK(status)) {
		memcpy(handle, &io.out.file.handle, sizeof(struct smb2_handle));
	}

	return status;
}

/**
  check that a wire string matches the flags specified
  not 100% accurate, but close enough for testing
*/
bool smb2_wire_bad_flags(struct smb_wire_string *str, int flags,
			 struct smb2_transport *transport)
{
	bool server_unicode;
	int len;
	if (!str || !str->s) return true;
	len = strlen(str->s);
	if (flags & STR_TERMINATE) len++;

	server_unicode = smbXcli_conn_use_unicode(transport->conn);

	if ((flags & STR_UNICODE) || server_unicode) {
		len *= 2;
	} else if (flags & STR_TERMINATE_ASCII) {
		len++;
	}
	if (str->private_length != len) {
		printf("Expected wire_length %d but got %d for '%s'\n",
		       len, str->private_length, str->s);
		return true;
	}
	return false;
}

/*
  set a attribute on a file
*/
bool torture_smb2_set_file_attribute(struct smb2_tree *tree, const char *fname,
				     uint16_t attrib)
{
	union smb_setfileinfo sfinfo;
	NTSTATUS status;

	ZERO_STRUCT(sfinfo.basic_info.in);
	sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION;
	sfinfo.basic_info.in.file.path = fname;
	sfinfo.basic_info.in.attrib = attrib;
	status = smb2_composite_setpathinfo(tree, &sfinfo);
	return NT_STATUS_IS_OK(status);
}

/*
  set a file descriptor as sparse
*/
NTSTATUS torture_smb2_set_sparse(struct smb2_tree *tree,
				 struct smb2_handle *handle)
{
	struct smb2_ioctl nt;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_named_const(tree, 0, "torture_smb2_set_sparse");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	nt.level = RAW_IOCTL_NTIOCTL;
	nt.in.function = FSCTL_SET_SPARSE;
	memcpy(&nt.in.file.handle, handle, sizeof(struct smb2_handle));

	status = smb2_ioctl(tree, mem_ctx, &nt);

	talloc_free(mem_ctx);

	return status;
}

/*
  check that an EA has the right value
*/
NTSTATUS torture_smb2_check_ea(struct smb2cli_state *cli,
			       const char *fname, const char *eaname,
			       const char *value)
{
	union smb_fileinfo info;
	NTSTATUS status;
	struct ea_name ea;
	TALLOC_CTX *mem_ctx = talloc_new(cli);

	info.ea_list.level = RAW_FILEINFO_EA_LIST;
	info.ea_list.in.file.path = fname;
	info.ea_list.in.num_names = 1;
	info.ea_list.in.ea_names = &ea;

	ea.name.s = eaname;

	status = smb2_getinfo_file(cli->tree, mem_ctx, &info);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return status;
	}

	if (info.ea_list.out.num_eas != 1) {
		printf("Expected 1 ea in ea_list\n");
		talloc_free(mem_ctx);
		return NT_STATUS_EA_CORRUPT_ERROR;
	}

	if (strcasecmp_m(eaname, info.ea_list.out.eas[0].name.s) != 0) {
		printf("Expected ea '%s' not '%s' in ea_list\n",
		       eaname, info.ea_list.out.eas[0].name.s);
		talloc_free(mem_ctx);
		return NT_STATUS_EA_CORRUPT_ERROR;
	}

	if (value == NULL) {
		if (info.ea_list.out.eas[0].value.length != 0) {
			printf("Expected zero length ea for %s\n", eaname);
			talloc_free(mem_ctx);
			return NT_STATUS_EA_CORRUPT_ERROR;
		}
		talloc_free(mem_ctx);
		return NT_STATUS_OK;
	}

	if (strlen(value) == info.ea_list.out.eas[0].value.length &&
	    memcmp(value, info.ea_list.out.eas[0].value.data,
		   info.ea_list.out.eas[0].value.length) == 0) {
		talloc_free(mem_ctx);
		return NT_STATUS_OK;
	}

	printf("Expected value '%s' not '%*.*s' for ea %s\n",
	       value,
	       (int)info.ea_list.out.eas[0].value.length,
	       (int)info.ea_list.out.eas[0].value.length,
	       info.ea_list.out.eas[0].value.data,
	       eaname);

	talloc_free(mem_ctx);

	return NT_STATUS_EA_CORRUPT_ERROR;
}

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

/*
 * Helper function to verify a security descriptor, by querying
 * and comparing against the passed in sd.
 */
bool smb2_util_verify_sd(TALLOC_CTX *tctx, struct smb2_tree *tree,
    struct smb2_handle handle, struct security_descriptor *sd)
{
	NTSTATUS status;
	bool ret = true;
	union smb_fileinfo q = {};

	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags =
	    SECINFO_OWNER |
	    SECINFO_GROUP |
	    SECINFO_DACL;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (!security_acl_equal(
	    q.query_secdesc.out.sd->dacl, sd->dacl)) {
		torture_warning(tctx, "%s: security descriptors don't match!\n",
		    __location__);
		torture_warning(tctx, "got:\n");
		NDR_PRINT_DEBUG(security_descriptor,
		    q.query_secdesc.out.sd);
		torture_warning(tctx, "expected:\n");
		NDR_PRINT_DEBUG(security_descriptor, sd);
		ret = false;
	}

 done:
	return ret;
}

/*
 * Helper function to verify attributes, by querying
 * and comparing against the passed in attrib.
 */
bool smb2_util_verify_attrib(TALLOC_CTX *tctx, struct smb2_tree *tree,
    struct smb2_handle handle, uint32_t attrib)
{
	NTSTATUS status;
	bool ret = true;
	union smb_fileinfo q = {};

	q.standard.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	q.standard.in.file.handle = handle;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	q.all_info2.out.attrib &= ~(FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NONINDEXED);

	if (q.all_info2.out.attrib != attrib) {
		torture_warning(tctx, "%s: attributes don't match! "
		    "got %x, expected %x\n", __location__,
		    (uint32_t)q.standard.out.attrib,
		    (uint32_t)attrib);
		ret = false;
	}

 done:
	return ret;
}


uint32_t smb2_util_lease_state(const char *ls)
{
	uint32_t val = 0;
	int i;

	for (i = 0; i < strlen(ls); i++) {
		switch (ls[i]) {
		case 'R':
			val |= SMB2_LEASE_READ;
			break;
		case 'H':
			val |= SMB2_LEASE_HANDLE;
			break;
		case 'W':
			val |= SMB2_LEASE_WRITE;
			break;
		}
	}

	return val;
}


uint32_t smb2_util_share_access(const char *sharemode)
{
	uint32_t val = NTCREATEX_SHARE_ACCESS_NONE; /* 0 */
	int i;

	for (i = 0; i < strlen(sharemode); i++) {
		switch(sharemode[i]) {
		case 'R':
			val |= NTCREATEX_SHARE_ACCESS_READ;
			break;
		case 'W':
			val |= NTCREATEX_SHARE_ACCESS_WRITE;
			break;
		case 'D':
			val |= NTCREATEX_SHARE_ACCESS_DELETE;
			break;
		}
	}

	return val;
}

uint8_t smb2_util_oplock_level(const char *op)
{
	uint8_t val = SMB2_OPLOCK_LEVEL_NONE;
	int i;

	for (i = 0; i < strlen(op); i++) {
		switch (op[i]) {
		case 's':
			return SMB2_OPLOCK_LEVEL_II;
		case 'x':
			return SMB2_OPLOCK_LEVEL_EXCLUSIVE;
		case 'b':
			return SMB2_OPLOCK_LEVEL_BATCH;
		default:
			continue;
		}
	}

	return val;
}

/**
 * Helper functions to fill a smb2_create struct for several
 * open scenarios.
 */
void smb2_generic_create_share(struct smb2_create *io, struct smb2_lease *ls,
			       bool dir, const char *name, uint32_t disposition,
			       uint32_t share_access,
			       uint8_t oplock, uint64_t leasekey,
			       uint32_t leasestate)
{
	ZERO_STRUCT(*io);
	io->in.security_flags		= 0x00;
	io->in.oplock_level		= oplock;
	io->in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	io->in.create_flags		= 0x00000000;
	io->in.reserved			= 0x00000000;
	io->in.desired_access		= SEC_RIGHTS_FILE_ALL;
	io->in.file_attributes		= FILE_ATTRIBUTE_NORMAL;
	io->in.share_access		= share_access;
	io->in.create_disposition	= disposition;
	io->in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	io->in.fname			= name;

	if (dir) {
		io->in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
		io->in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
		io->in.create_disposition = NTCREATEX_DISP_CREATE;
	}

	if (ls) {
		ZERO_STRUCTPN(ls);
		ls->lease_key.data[0] = leasekey;
		ls->lease_key.data[1] = ~leasekey;
		ls->lease_state = leasestate;
		io->in.lease_request = ls;
	}
}

void smb2_generic_create(struct smb2_create *io, struct smb2_lease *ls,
			 bool dir, const char *name, uint32_t disposition,
			 uint8_t oplock, uint64_t leasekey,
			 uint32_t leasestate)
{
	smb2_generic_create_share(io, ls, dir, name, disposition,
				  smb2_util_share_access("RWD"),
				  oplock,
				  leasekey, leasestate);
}

void smb2_lease_create_share(struct smb2_create *io, struct smb2_lease *ls,
			     bool dir, const char *name, uint32_t share_access,
			     uint64_t leasekey, uint32_t leasestate)
{
	smb2_generic_create_share(io, ls, dir, name, NTCREATEX_DISP_OPEN_IF,
				  share_access, SMB2_OPLOCK_LEVEL_LEASE,
				  leasekey, leasestate);
}

void smb2_lease_create(struct smb2_create *io, struct smb2_lease *ls,
		       bool dir, const char *name, uint64_t leasekey,
		       uint32_t leasestate)
{
	smb2_lease_create_share(io, ls, dir, name,
				smb2_util_share_access("RWD"),
				leasekey, leasestate);
}

void smb2_lease_v2_create_share(struct smb2_create *io,
				struct smb2_lease *ls,
				bool dir,
				const char *name,
				uint32_t share_access,
				uint64_t leasekey,
				const uint64_t *parentleasekey,
				uint32_t leasestate,
				uint16_t lease_epoch)
{
	smb2_generic_create_share(io, NULL, dir, name, NTCREATEX_DISP_OPEN_IF,
				  share_access, SMB2_OPLOCK_LEVEL_LEASE, 0, 0);

	if (ls) {
		ZERO_STRUCT(*ls);
		ls->lease_key.data[0] = leasekey;
		ls->lease_key.data[1] = ~leasekey;
		ls->lease_state = leasestate;
		if (parentleasekey != NULL) {
			ls->lease_flags |= SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET;
			ls->parent_lease_key.data[0] = *parentleasekey;
			ls->parent_lease_key.data[1] = ~(*parentleasekey);
		}
		ls->lease_epoch = lease_epoch;
		io->in.lease_request_v2 = ls;
	}
}

void smb2_lease_v2_create(struct smb2_create *io,
			  struct smb2_lease *ls,
			  bool dir,
			  const char *name,
			  uint64_t leasekey,
			  const uint64_t *parentleasekey,
			  uint32_t leasestate,
			  uint16_t lease_epoch)
{
	smb2_lease_v2_create_share(io, ls, dir, name,
				   smb2_util_share_access("RWD"),
				   leasekey, parentleasekey,
				   leasestate, lease_epoch);
}


void smb2_oplock_create_share(struct smb2_create *io, const char *name,
			      uint32_t share_access, uint8_t oplock)
{
	smb2_generic_create_share(io, NULL, false, name, NTCREATEX_DISP_OPEN_IF,
				  share_access, oplock, 0, 0);
}
void smb2_oplock_create(struct smb2_create *io, const char *name, uint8_t oplock)
{
	smb2_oplock_create_share(io, name, smb2_util_share_access("RWD"),
				 oplock);
}

bool torture_smb2_open_connection_share(TALLOC_CTX *mem_ctx,
					struct smb2cli_state *c,
					struct torture_context *tctx,
					const char *hostname,
					const char *sharename,
					struct tevent_context *ev)
{
	NTSTATUS status;

	struct smbcli_options options;
	struct smbcli_session_options session_options;

	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	lpcfg_smbcli_session_options(tctx->lp_ctx, &session_options);

	options.use_oplocks = torture_setting_bool(tctx, "use_oplocks", true);
	options.use_level2_oplocks = torture_setting_bool(tctx, "use_level2_oplocks", true);

	status = smb2_connect(mem_ctx, hostname, lpcfg_smb_ports(tctx->lp_ctx),
			      sharename, lpcfg_resolve_context(tctx->lp_ctx),
			      popt_get_cmdline_credentials(), &(c->tree),
			      ev, &options, lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open connection - %s\n", nt_errstr(status));
		return false;
	}

	return true;
}

bool torture_smb2_open_connection_ev(struct smb2cli_state *c,
				     int conn_index,
				     struct torture_context *tctx,
				     struct tevent_context *ev)
{
	char *host, *share;
	bool ret;

	if (!torture_get_conn_index(conn_index, ev, tctx, &host, &share)) {
		return false;
	}

	ret = torture_smb2_open_connection_share(NULL, c, tctx, host, share, ev);
	talloc_free(host);
	talloc_free(share);

	return ret;
}

bool torture_smb2_open_connection(struct smb2cli_state *c,
					   struct torture_context *tctx,
					   int conn_index)
{
	return torture_smb2_open_connection_ev(c, conn_index, tctx, tctx->ev);
}



bool torture_smb2_close_connection(struct smb2cli_state *c)
{
	NTSTATUS status;
	bool ret = true;
	if (!c) return true;
	status = smb2_tdis(c->tree);
	if (NT_STATUS_IS_ERR(status)) {
		printf("tdis failed (%s)\n", nt_errstr(status));
		ret = false;
	}
	talloc_free(c);
	return ret;
}


static struct smb2cli_state *current_cli;
static int procnum; /* records process count number when forking */

static void sigcont(int sig)
{
}

struct child_status {
	pid_t pid;
	bool start;
	enum torture_result result;
	char reason[1024];
};

double torture_smb2_create_procs(struct torture_context *tctx,
	bool (*fn)(struct torture_context *, struct smb2cli_state *, int),
	bool *result)
{
	int status;
	size_t i;
	struct child_status *child_status;
	size_t synccount;
	size_t tries = 8;
	size_t torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	double start_time_limit = 10 + (torture_nprocs * 1.5);
	struct timeval tv;

	*result = true;

	synccount = 0;

	signal(SIGCONT, sigcont);

	child_status = (struct child_status *)anonymous_shared_allocate(
				sizeof(struct child_status)*torture_nprocs);
	if (child_status == NULL) {
		printf("Failed to setup shared memory\n");
		return -1;
	}

	for (i = 0; i < torture_nprocs; i++) {
		ZERO_STRUCT(child_status[i]);
	}

	tv = timeval_current();

	for (i=0;i<torture_nprocs;i++) {
		procnum = i;
		if (fork() == 0) {
			char *myname;
			bool ok;

			pid_t mypid = getpid();
			srandom(((int)mypid) ^ ((int)time(NULL)));

			if (asprintf(&myname, "CLIENT%zu", i) == -1) {
				printf("asprintf failed\n");
				return -1;
			}
			lpcfg_set_cmdline(tctx->lp_ctx, "netbios name", myname);
			free(myname);


			while (1) {
				if (torture_smb2_open_connection(current_cli, tctx, i)) {
					break;
				}
				if (tries-- == 0) {
					printf("pid %d failed to start\n", (int)getpid());
					_exit(1);
				}
				smb_msleep(100);
			}

			child_status[i].pid = getpid();

			pause();

			if (!child_status[i].start) {
				child_status[i].result = TORTURE_ERROR;
				printf("Child %zu failed to start!\n", i);
				_exit(1);
			}

			ok = fn(tctx, current_cli, i);
			if (!ok) {
				if (tctx->last_result == TORTURE_OK) {
					torture_result(tctx, TORTURE_ERROR,
						"unknown error: missing "
						"torture_result call?\n");
				}

				child_status[i].result = tctx->last_result;

				if (strlen(tctx->last_reason) > 1023) {
					/* note: reason already contains \n */
					torture_comment(tctx,
						"child %zu (pid %u) failed: %s",
						i,
						(unsigned)child_status[i].pid,
						tctx->last_reason);
				}

				snprintf(child_status[i].reason,
					 1024, "child %zu (pid %u) failed: %s",
					 i, (unsigned)child_status[i].pid,
					 tctx->last_reason);
				/* ensure proper "\n\0" termination: */
				if (child_status[i].reason[1022] != '\0') {
					child_status[i].reason[1022] = '\n';
					child_status[i].reason[1023] = '\0';
				}
			}
			_exit(0);
		}
	}

	do {
		synccount = 0;
		for (i=0;i<torture_nprocs;i++) {
			if (child_status[i].pid != 0) {
				synccount++;
			}
		}
		if (synccount == torture_nprocs) {
			break;
		}
		smb_msleep(100);
	} while (timeval_elapsed(&tv) < start_time_limit);

	if (synccount != torture_nprocs) {
		printf("FAILED TO START %zu CLIENTS (started %zu)\n", torture_nprocs, synccount);

		/* cleanup child processes */
		for (i = 0; i < torture_nprocs; i++) {
			if (child_status[i].pid != 0) {
				kill(child_status[i].pid, SIGTERM);
			}
		}

		*result = false;
		return timeval_elapsed(&tv);
	}

	printf("Starting %zu clients\n", torture_nprocs);

	/* start the client load */
	tv = timeval_current();
	for (i=0;i<torture_nprocs;i++) {
		child_status[i].start = true;
	}

	printf("%zu clients started\n", torture_nprocs);

	kill(0, SIGCONT);

	for (i=0;i<torture_nprocs;i++) {
		int ret;
		while ((ret=waitpid(0, &status, 0)) == -1 && errno == EINTR) /* noop */ ;
		if (ret == -1 || WEXITSTATUS(status) != 0) {
			*result = false;
		}
	}

	printf("\n");

	for (i=0;i<torture_nprocs;i++) {
		if (child_status[i].result != TORTURE_OK) {
			*result = false;
			torture_result(tctx, child_status[i].result,
				       "%s", child_status[i].reason);
		}
	}

	return timeval_elapsed(&tv);
}

static bool wrap_smb2_multi_test(struct torture_context *torture,
				 struct torture_tcase *tcase,
				 struct torture_test *test)
{
	bool (*fn)(struct torture_context *, struct smb2cli_state *, int ) = test->fn;
	bool result;

	torture_smb2_create_procs(torture, fn, &result);

	return result;
}

struct torture_test *torture_suite_add_smb2_multi_test(
					struct torture_suite *suite,
					const char *name,
					bool (*run) (struct torture_context *,
						struct smb2cli_state *,
						int i))
{
	struct torture_test *test;
	struct torture_tcase *tcase;

	tcase = torture_suite_add_tcase(suite, name);

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_smb2_multi_test;
	test->fn = run;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test);

	return test;

}


NTSTATUS torture_smb2_second_tcon(TALLOC_CTX *mem_ctx,
				  struct smb2_session *session,
				  const char *sharename,
				  struct smb2_tree **res)
{
	struct smb2_tree_connect tcon;
	struct smb2_tree *result;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;

	if ((tmp_ctx = talloc_new(mem_ctx)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result = smb2_tree_init(session, tmp_ctx, false);
	if (result == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	tcon.level = RAW_TCON_SMB2;
	tcon.in.path = sharename;

	status = smb2_tcon(result, tmp_ctx, &tcon);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	*res = talloc_steal(mem_ctx, result);
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/*
   a wrapper around smblsa_sid_check_privilege, that tries to take
   account of the fact that the lsa privileges calls don't expand
   group memberships, using an explicit check for administrator. There
   must be a better way ...
 */
NTSTATUS torture_smb2_check_privilege(struct smb2cli_state *cli,
				      const char *sid_str,
				      const char *privilege)
{
	struct dom_sid *sid;
	TALLOC_CTX *tmp_ctx = talloc_new(cli);
	uint32_t rid;
	NTSTATUS status;

	sid = dom_sid_parse_talloc(tmp_ctx, sid_str);
	if (sid == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_SID;
	}

	status = dom_sid_split_rid(tmp_ctx, sid, NULL, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	if (rid == DOMAIN_RID_ADMINISTRATOR) {
		/* assume the administrator has them all */
		return NT_STATUS_OK;
	}

	talloc_free(tmp_ctx);

	return smb2lsa_sid_check_privilege(cli, sid_str, privilege);
}
