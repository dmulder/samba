/*
   Unix SMB/CIFS implementation.

   endpoint server for the frstrans pipe

   Copyright (C) YOUR NAME HERE YEAR

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
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_frstrans.h"
#include "rpc_server/common/common.h"
#include "librpc/gen_ndr/frstrans.h"

#define DCESRV_INTERFACE_FRSTRANS_BIND(call, iface) \
	dcesrv_interface_frstrans_bind(call, iface)
static NTSTATUS dcesrv_interface_frstrans_bind(struct dcesrv_call_state *dce_call,
					     const struct dcesrv_interface *iface)
{
	return dcesrv_interface_bind_require_privacy(dce_call, iface);
}

/*
  frstrans_CheckConnectivity
*/
static WERROR dcesrv_frstrans_CheckConnectivity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_CheckConnectivity *r)
{
	r->out.result = WERR_OK;
	return r->out.result;
}

/*
  frstrans_EstablishConnection
*/
static WERROR dcesrv_frstrans_EstablishConnection(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_EstablishConnection *r)
{
	r->out.upstream_protocol_version = talloc_zero(mem_ctx, enum frstrans_ProtocolVersion);
	*(r->out.upstream_protocol_version) = FRSTRANS_PROTOCOL_VERSION_W2K3R2;
	r->out.upstream_flags = talloc_zero(mem_ctx, uint32_t);
	*(r->out.upstream_flags) = 0;
	r->out.result = WERR_OK;
	return r->out.result;
}


/*
  frstrans_EstablishSession
*/
static WERROR dcesrv_frstrans_EstablishSession(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_EstablishSession *r)
{
	r->out.result = WERR_OK;
	return r->out.result;
}


/*
  frstrans_RequestUpdates
*/
static WERROR dcesrv_frstrans_RequestUpdates(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RequestUpdates *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_RequestVersionVector
*/
static WERROR dcesrv_frstrans_RequestVersionVector(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RequestVersionVector *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_AsyncPoll
*/
static WERROR dcesrv_frstrans_AsyncPoll(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_AsyncPoll *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_REQUEST_RECORDS
*/
static void dcesrv_FRSTRANS_REQUEST_RECORDS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_REQUEST_RECORDS *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_UPDATE_CANCEL
*/
static void dcesrv_FRSTRANS_UPDATE_CANCEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_UPDATE_CANCEL *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_RawGetFileData
*/
static WERROR dcesrv_frstrans_RawGetFileData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RawGetFileData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_RDC_GET_SIGNATURES
*/
static void dcesrv_FRSTRANS_RDC_GET_SIGNATURES(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_RDC_GET_SIGNATURES *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_RDC_PUSH_SOURCE_NEEDS
*/
static void dcesrv_FRSTRANS_RDC_PUSH_SOURCE_NEEDS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_RDC_PUSH_SOURCE_NEEDS *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_RDC_GET_FILE_DATA
*/
static void dcesrv_FRSTRANS_RDC_GET_FILE_DATA(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_RDC_GET_FILE_DATA *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_RDC_CLOSE
*/
static WERROR dcesrv_frstrans_RdcClose(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RdcClose *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_InitializeFileTransferAsync
*/
static WERROR dcesrv_frstrans_InitializeFileTransferAsync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_InitializeFileTransferAsync *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE
*/
static void dcesrv_FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_RawGetFileDataAsync
*/
static WERROR dcesrv_frstrans_RawGetFileDataAsync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RawGetFileDataAsync *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_RdcGetFileDataAsync
*/
static WERROR dcesrv_frstrans_RdcGetFileDataAsync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RdcGetFileDataAsync *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_frstrans_s.c"
