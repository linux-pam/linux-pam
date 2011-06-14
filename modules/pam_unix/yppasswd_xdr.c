/*
 * yppasswdd
 * Copyright 1994, 1995, 1996 Olaf Kirch, <okir@lst.de>
 *
 * This program is covered by the GNU General Public License, version 2
 * or later. It is provided in the hope that it is useful. However, the author
 * disclaims ALL WARRANTIES, expressed or implied. See the GPL for details.
 *
 * This file was generated automatically by rpcgen from yppasswd.x, and
 * editied manually.
 */

#include "config.h"

#ifdef HAVE_RPC_RPC_H

#include <rpc/rpc.h>
#include "yppasswd.h"

bool_t
xdr_xpasswd(XDR * xdrs, xpasswd * objp)
{
	return xdr_string(xdrs, &objp->pw_name, ~0)
	    && xdr_string(xdrs, &objp->pw_passwd, ~0)
	    && xdr_int(xdrs, &objp->pw_uid)
	    && xdr_int(xdrs, &objp->pw_gid)
	    && xdr_string(xdrs, &objp->pw_gecos, ~0)
	    && xdr_string(xdrs, &objp->pw_dir, ~0)
	    && xdr_string(xdrs, &objp->pw_shell, ~0);
}


bool_t
xdr_yppasswd(XDR * xdrs, yppasswd * objp)
{
	return xdr_string(xdrs, &objp->oldpass, ~0)
	    && xdr_xpasswd(xdrs, &objp->newpw);
}

#endif
