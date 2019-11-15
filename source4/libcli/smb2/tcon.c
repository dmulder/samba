/* 
   Unix SMB/CIFS implementation.

   SMB2 client tree handling

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
#include <tevent.h>
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "../libcli/smb/smbXcli_base.h"

/*
  initialise a smb2_session structure
 */
struct smb2_tree *smb2_tree_init(struct smb2_session *session,
				 TALLOC_CTX *parent_ctx, bool primary)
{
	struct smb2_tree *tree;

	tree = talloc_zero(parent_ctx, struct smb2_tree);
	if (!session) {
		return NULL;
	}
	if (primary) {
		tree->session = talloc_steal(tree, session);
	} else {
		tree->session = talloc_reference(tree, session);
	}

	tree->smbXcli = smbXcli_tcon_create(tree);
	if (tree->smbXcli == NULL) {
		talloc_free(tree);
		return NULL;
	}

	return tree;
}

NTSTATUS smb2_tcon(struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
		      struct smb2_tree_connect *parms)
{
	struct tevent_req *subreq;
	NTSTATUS status;
	bool ok;
	uint32_t timeout_msec;
	TALLOC_CTX *frame = talloc_stackframe();

	if (frame == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	subreq = smb2cli_tcon_send(frame,
				   tree->session->transport->ev,
				   tree->session->transport->conn,
				   timeout_msec,
				   tree->session->smbXcli,
				   tree->smbXcli,
				   0, /* flags */
				   parms->in.path);
	if (subreq == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ok = tevent_req_poll(subreq, tree->session->transport->ev);
	if (!ok) {
		status = map_nt_error_from_unix_common(errno);
		TALLOC_FREE(frame);
		return status;
	}

	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
