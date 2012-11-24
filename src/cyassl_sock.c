/*
 * SSL/TLS transport layer over SOCK_STREAM sockets
 *
 * Copyright (C) 2012 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Acknowledgement:
 *   We'd like to specially thank the Stud project authors for a very clean
 *   and well documented code which helped us understand how the OpenSSL API
 *   ought to be used in non-blocking mode. This is one difficult part which
 *   is not easy to get from the OpenSSL doc, and reading the Stud code made
 *   it much more obvious than the examples in the OpenSSL package. Keep up
 *   the good works, guys !
 *
 *   Stud is an extremely efficient and scalable SSL/TLS proxy which combines
 *   particularly well with haproxy. For more info about this project, visit :
 *       https://github.com/bumptech/stud
 *
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <cyassl/ssl.h>

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/errors.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <ebsttree.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/frontend.h>
#include <proto/listener.h>
#include <proto/server.h>
#include <proto/log.h>
#include <proto/proxy.h>
#include <proto/cyassl_sock.h>
#include <proto/task.h>

static int sslconns = 0;

#define SSL_SOCK_ST_FL_VERIFY_DONE   0x00000001
#define SSL_SOCK_ST_FL_VERIFY_ERROR  0x00000002

/* Callback is called for each certificate of the chain during a verify
   ok is set to 1 if preverify detect no error on current certificate.
   Returns 0 to break the handshake, 1 otherwise. */
int cyassl_sock_verifycbk(int ok, CYASSL_X509_STORE_CTX *x_store)
{
	CYASSL *ssl;

	ssl = CyaSSL_X509_STORE_CTX_get_ex_data(x_store, CyaSSL_get_ex_data_X509_STORE_CTX_idx());
	if (ssl) {
		struct connection *conn = (struct connection *)CyaSSL_get_ex_data(ssl, 0);
		if (conn) {
			if (CyaSSL_get_peer_certificate(ssl))
				conn->xprt_st |= SSL_SOCK_ST_FL_VERIFY_DONE;

			if (!ok)
				conn->xprt_st |= SSL_SOCK_ST_FL_VERIFY_ERROR;

			if (objt_listener(conn->target)->bind_conf->crt_ignerr) /* ignore all errors */
				return 1;
		}
	}

	if (ok) /* no errors */
		return ok;


	return 0;
}

static int cyassl_sock_load_cert_file(const char *path, struct bind_conf *bind_conf, struct proxy *curproxy, char **err)
{
	int ret;
	CYASSL_CTX *ctx;

	ctx = CyaSSL_CTX_new(CyaSSLv23_server_method());
	if (!ctx) {
		memprintf(err, "%sunable to allocate SSL context for cert '%s'.\n",
		          err && *err ? *err : "", path);
		return 1;
	}

	if (CyaSSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM) <= 0) {
		memprintf(err, "%sunable to load SSL private key from PEM file '%s'.\n",
		          err && *err ? *err : "", path);
		CyaSSL_CTX_free(ctx);
		return 1;
	}

	ret = CyaSSL_CTX_use_certificate_chain_file(ctx, path);
	if (ret <= 0) {
		ret = CyaSSL_CTX_use_certificate_file(ctx, path, SSL_FILETYPE_PEM);
		if (ret <= 0) {
			memprintf(err, "%sunable to load SSL certificate from PEM file '%s'.\n",
			          err && *err ? *err : "", path);
			if (ret < 0) /* serious error, must do that ourselves */
				CyaSSL_CTX_free(ctx);
			return 1;
		}
	}

	if (CyaSSL_CTX_check_private_key(ctx) <= 0) {
		memprintf(err, "%sinconsistencies between private key and certificate loaded from PEM file '%s'.\n",
		          err && *err ? *err : "", path);
		return 1;
	}

	CyaSSL_CTX_SetTmpDH_file(ctx, path, SSL_FILETYPE_PEM);

	if (bind_conf->default_ctx) {
		memprintf(err, "%sthis version of cyassl cannot load multiple SSL certificates.\n",
		          err && *err ? *err : "");
		return 1;
	}

	if (!bind_conf->default_ctx)
		bind_conf->default_ctx = ctx;

	return 0;
}

int cyassl_sock_load_cert(char *path, struct bind_conf *bind_conf, struct proxy *curproxy, char **err)
{
	struct dirent *de;
	DIR *dir;
	struct stat buf;
	int pathlen = 0;
	char *end, *fp;
	int cfgerr = 0;

	if (!(dir = opendir(path)))
		return cyassl_sock_load_cert_file(path, bind_conf, curproxy, err);

	/* strip trailing slashes, including first one */
	for (end = path + strlen(path) - 1; end >= path && *end == '/'; end--)
		*end = 0;

	if (end >= path)
		pathlen = end + 1 - path;
	fp = malloc(pathlen + 1 + NAME_MAX + 1);

	while ((de = readdir(dir))) {
		snprintf(fp, pathlen + 1 + NAME_MAX + 1, "%s/%s", path, de->d_name);
		if (stat(fp, &buf) != 0) {
			memprintf(err, "%sunable to stat SSL certificate from file '%s' : %s.\n",
			          err && *err ? *err : "", fp, strerror(errno));
			cfgerr++;
			continue;
		}
		if (!S_ISREG(buf.st_mode))
			continue;
		cfgerr += cyassl_sock_load_cert_file(fp, bind_conf, curproxy, err);
	}
	free(fp);
	closedir(dir);
	return cfgerr;
}

int cyassl_sock_prepare_ctx(struct bind_conf *bind_conf, CYASSL_CTX *ctx, struct proxy *curproxy)
{
	int cfgerr = 0;
	int sslmode = SSL_MODE_ENABLE_PARTIAL_WRITE;

	CyaSSL_CTX_set_mode(ctx, sslmode);

	CyaSSL_CTX_set_verify(ctx, bind_conf->verify ? bind_conf->verify : SSL_VERIFY_NONE, cyassl_sock_verifycbk);
	if (bind_conf->verify & SSL_VERIFY_PEER) {
		if (bind_conf->ca_file) {
			/* load CAfile to verify */
			if (!CyaSSL_CTX_load_verify_locations(ctx, bind_conf->ca_file, NULL)) {
				Alert("Proxy '%s': unable to load CA file '%s' for bind '%s' at [%s:%d].\n",
				      curproxy->id, bind_conf->ca_file, bind_conf->arg, bind_conf->file, bind_conf->line);
				cfgerr++;
			}
		}
	}

	if (global.tune.ssllifetime)
		CyaSSL_CTX_set_timeout(ctx, global.tune.ssllifetime);

	if (bind_conf->ciphers &&
	    !CyaSSL_CTX_set_cipher_list(ctx, bind_conf->ciphers)) {
		Alert("Proxy '%s': unable to set SSL cipher list to '%s' for bind '%s' at [%s:%d].\n",
		curproxy->id, bind_conf->ciphers, bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr++;
	}

	return cfgerr;
}

/* prepare ssl context from servers options. Returns an error count */
int cyassl_sock_prepare_srv_ctx(struct server *srv, struct proxy *curproxy)
{
	int cfgerr = 0;
	int mode = SSL_MODE_ENABLE_PARTIAL_WRITE;

	 /* Initiate SSL context for current server */
	srv->ssl_ctx.reused_sess = NULL;
	if (srv->use_ssl)
		srv->xprt = &cyassl_sock;
	if (srv->check.use_ssl)
		srv->check.xprt = &cyassl_sock;

	srv->ssl_ctx.ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
	if (!srv->ssl_ctx.ctx) {
		Alert("config : %s '%s', server '%s': unable to allocate ssl context.\n",
		      proxy_type_str(curproxy), curproxy->id,
		      srv->id);
		cfgerr++;
		return cfgerr;
	}

	if (srv->ssl_ctx.client_crt) {
		if (CyaSSL_CTX_use_PrivateKey_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt, SSL_FILETYPE_PEM) <= 0) {
			Alert("config : %s '%s', server '%s': unable to load SSL private key from PEM file '%s'.\n",
			      proxy_type_str(curproxy), curproxy->id,
			      srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
		else if ((CyaSSL_CTX_use_certificate_chain_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt) > 0)
				|| (CyaSSL_CTX_use_certificate_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt, SSL_FILETYPE_PEM) > 0)) {
			if (CyaSSL_CTX_check_private_key(srv->ssl_ctx.ctx) <= 0) {
				Alert("config : %s '%s', server '%s': inconsistencies between private key and certificate loaded from PEM file '%s'.\n",
				      proxy_type_str(curproxy), curproxy->id,
				      srv->id, srv->ssl_ctx.client_crt);
				cfgerr++;
			}
		}
		else {
			Alert("config : %s '%s', server '%s': unable to load ssl certificate from PEM file '%s'.\n",
			      proxy_type_str(curproxy), curproxy->id,
			      srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
	}

	CyaSSL_CTX_set_mode(srv->ssl_ctx.ctx, mode);
	CyaSSL_CTX_set_verify(srv->ssl_ctx.ctx, SSL_VERIFY_NONE, NULL);
	CyaSSL_CTX_set_verify(srv->ssl_ctx.ctx, srv->ssl_ctx.verify ? srv->ssl_ctx.verify : SSL_VERIFY_NONE, NULL);
	if (srv->ssl_ctx.verify & SSL_VERIFY_PEER) {
		if (srv->ssl_ctx.ca_file) {
			/* load CAfile to verify */
			if (!CyaSSL_CTX_load_verify_locations(srv->ssl_ctx.ctx, srv->ssl_ctx.ca_file, NULL)) {
				Alert("Proxy '%s', server '%s' |%s:%d] unable to load CA file '%s'.\n",
				      curproxy->id, srv->id,
				      srv->conf.file, srv->conf.line, srv->ssl_ctx.ca_file);
				cfgerr++;
			}
		}
	}

	if (global.tune.ssllifetime)
		CyaSSL_CTX_set_timeout(srv->ssl_ctx.ctx, global.tune.ssllifetime);

	if (srv->ssl_ctx.ciphers &&
		!CyaSSL_CTX_set_cipher_list(srv->ssl_ctx.ctx, srv->ssl_ctx.ciphers)) {
		Alert("Proxy '%s', server '%s' [%s:%d] : unable to set SSL cipher list to '%s'.\n",
		      curproxy->id, srv->id,
		      srv->conf.file, srv->conf.line, srv->ssl_ctx.ciphers);
		cfgerr++;
	}

	return cfgerr;
}

/* Walks down the two trees in bind_conf and prepares all certs. The pointer may
 * be NULL, in which case nothing is done. Returns the number of errors
 * encountered.
 */
int cyassl_sock_prepare_all_ctx(struct bind_conf *bind_conf, struct proxy *px)
{
	int err = 0;

	if (!bind_conf || !bind_conf->is_ssl)
		return 0;

	err += cyassl_sock_prepare_ctx(bind_conf, bind_conf->default_ctx, px);
	return err;
}

/* Walks down the two trees in bind_conf and frees all the certs. The pointer may
 * be NULL, in which case nothing is done. The default_ctx is nullified too.
 */
void cyassl_sock_free_all_ctx(struct bind_conf *bind_conf)
{
	if (!bind_conf || !bind_conf->is_ssl)
		return;

	CyaSSL_CTX_free(bind_conf->default_ctx);
	bind_conf->default_ctx = NULL;
}

/*
 * This function is called if SSL * context is not yet allocated. The function
 * is designed to be called before any other data-layer operation and sets the
 * handshake flag on the connection. It is safe to call it multiple times.
 * It returns 0 on success and -1 in error case.
 */
static int cyassl_sock_init(struct connection *conn)
{
	/* already initialized */
	if (conn->xprt_ctx)
		return 0;

	if (global.maxsslconn && sslconns >= global.maxsslconn)
		return -1;

	/* If it is in client mode initiate SSL session
	   in connect state otherwise accept state */
	if (objt_server(conn->target)) {
		/* Alloc a new SSL session ctx */
		conn->xprt_ctx = CyaSSL_new(objt_server(conn->target)->ssl_ctx.ctx);
		if (!conn->xprt_ctx)
			return -1;
		if (objt_server(conn->target)->ssl_ctx.options & SRV_SSL_O_USE_SSLV3)
			CyaSSL_SetVersion(conn->xprt_ctx, CYASSL_SSLV3);
		else if (objt_server(conn->target)->ssl_ctx.options & SRV_SSL_O_USE_TLSV10)
			CyaSSL_SetVersion(conn->xprt_ctx, CYASSL_TLSV1);
		else if (objt_server(conn->target)->ssl_ctx.options & SRV_SSL_O_USE_TLSV11)
			CyaSSL_SetVersion(conn->xprt_ctx, CYASSL_TLSV1_1);
		else if (objt_server(conn->target)->ssl_ctx.options & SRV_SSL_O_USE_TLSV12)
			CyaSSL_SetVersion(conn->xprt_ctx, CYASSL_TLSV1_2);

		CyaSSL_set_ex_data(conn->xprt_ctx, 0, conn);

		CyaSSL_set_connect_state(conn->xprt_ctx);
		if (objt_server(conn->target)->ssl_ctx.reused_sess)
			CyaSSL_set_session(conn->xprt_ctx, objt_server(conn->target)->ssl_ctx.reused_sess);

		/* set fd on SSL session context */
		CyaSSL_set_fd(conn->xprt_ctx, conn->t.sock.fd);

		/* leave init state and start handshake */
		conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;

		sslconns++;
		return 0;
	}
	else if (objt_listener(conn->target)) {
		/* Alloc a new SSL session ctx */
		conn->xprt_ctx = CyaSSL_new(objt_listener(conn->target)->bind_conf->default_ctx);
		if (!conn->xprt_ctx)
			return -1;
		if (objt_listener(conn->target)->bind_conf->ssl_options & BC_SSL_O_USE_SSLV3)
			CyaSSL_SetVersion(conn->xprt_ctx, CYASSL_SSLV3);
		else if (objt_listener(conn->target)->bind_conf->ssl_options & BC_SSL_O_USE_TLSV10)
			CyaSSL_SetVersion(conn->xprt_ctx, CYASSL_TLSV1);
		else if (objt_listener(conn->target)->bind_conf->ssl_options & BC_SSL_O_USE_TLSV11)
			CyaSSL_SetVersion(conn->xprt_ctx, CYASSL_TLSV1_1);
		else if (objt_listener(conn->target)->bind_conf->ssl_options & BC_SSL_O_USE_TLSV12)
			CyaSSL_SetVersion(conn->xprt_ctx, CYASSL_TLSV1_2);

		CyaSSL_set_ex_data(conn->xprt_ctx, 0, conn);

		CyaSSL_set_accept_state(conn->xprt_ctx);

		/* set fd on SSL session context */
		CyaSSL_set_fd(conn->xprt_ctx, conn->t.sock.fd);

		/* leave init state and start handshake */
		conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;

		sslconns++;
		return 0;
	}
	/* don't know how to handle such a target */
	return -1;
}


/* This is the callback which is used when an SSL handshake is pending. It
 * updates the FD status if it wants some polling before being called again.
 * It returns 0 if it fails in a fatal way or needs to poll to go further,
 * otherwise it returns non-zero and removes itself from the connection's
 * flags (the bit is provided in <flag> by the caller).
 */
int cyassl_sock_handshake(struct connection *conn, unsigned int flag)
{
	int ret;

	if (!conn->xprt_ctx)
		goto out_error;

	ret = CyaSSL_negotiate(conn->xprt_ctx);
	if (ret != 0) {
		/* handshake did not complete, let's find why */
		ret = CyaSSL_get_error(conn->xprt_ctx, ret);
		if (ret == SSL_ERROR_WANT_WRITE) {
			/* SSL handshake needs to write, L4 connection may not be ready */
			__conn_sock_stop_recv(conn);
			__conn_sock_poll_send(conn);
			return 0;
		}
		else if (ret == SSL_ERROR_WANT_READ) {
			/* SSL handshake needs to read, L4 connection is ready */
			if (conn->flags & CO_FL_WAIT_L4_CONN)
				conn->flags &= ~CO_FL_WAIT_L4_CONN;
			__conn_sock_stop_send(conn);
			__conn_sock_poll_recv(conn);
			return 0;
		}
		else if (ret == SSL_ERROR_SYSCALL) {
			/* if errno is null, then connection was successfully established */
			if (!errno && conn->flags & CO_FL_WAIT_L4_CONN)
				conn->flags &= ~CO_FL_WAIT_L4_CONN;
			goto out_error;
		}
		else {
			/* Fail on all other handshake errors */
			/* Note: OpenSSL may leave unread bytes in the socket's
			 * buffer, causing an RST to be emitted upon close() on
			 * TCP sockets. We first try to drain possibly pending
			 * data to avoid this as much as possible.
			 */
			ret = recv(conn->t.sock.fd, trash.str, trash.size, MSG_NOSIGNAL|MSG_DONTWAIT);
			goto out_error;
		}
	}

	/* Handshake succeeded */
	if (objt_server(conn->target)) {
		if (!CyaSSL_session_reused(conn->xprt_ctx)) {
			objt_server(conn->target)->ssl_ctx.reused_sess = CyaSSL_get_session(conn->xprt_ctx);
		}
	}

	/* The connection is now established at both layers, it's time to leave */
	conn->flags &= ~(flag | CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN);
	return 1;

 out_error:
	/* free resumed session if exists */
	if (objt_server(conn->target) && objt_server(conn->target)->ssl_ctx.reused_sess) {
		objt_server(conn->target)->ssl_ctx.reused_sess = NULL;
	}

	/* Fail on all other handshake errors */
	conn->flags |= CO_FL_ERROR;
	conn->flags &= ~flag;
	return 0;
}

/* Receive up to <count> bytes from connection <conn>'s socket and store them
 * into buffer <buf>. The caller must ensure that <count> is always smaller
 * than the buffer's size. Only one call to recv() is performed, unless the
 * buffer wraps, in which case a second call may be performed. The connection's
 * flags are updated with whatever special event is detected (error, read0,
 * empty). The caller is responsible for taking care of those events and
 * avoiding the call if inappropriate. The function does not call the
 * connection's polling update function, so the caller is responsible for this.
 */
static int cyassl_sock_to_buf(struct connection *conn, struct buffer *buf, int count)
{
	int ret, done = 0;
	int try = count;

	if (!conn->xprt_ctx)
		goto out_error;

	if (conn->flags & CO_FL_HANDSHAKE)
		/* a handshake was requested */
		return 0;

	/* compute the maximum block size we can read at once. */
	if (buffer_empty(buf)) {
		/* let's realign the buffer to optimize I/O */
		buf->p = buf->data;
	}
	else if (buf->data + buf->o < buf->p &&
		 buf->p + buf->i < buf->data + buf->size) {
		/* remaining space wraps at the end, with a moving limit */
		if (try > buf->data + buf->size - (buf->p + buf->i))
			try = buf->data + buf->size - (buf->p + buf->i);
	}

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (try) {
		ret = CyaSSL_read(conn->xprt_ctx, bi_end(buf), try);
		if (ret > 0) {
			buf->i += ret;
			done += ret;
			if (ret < try)
				break;
			count -= ret;
			try = count;
		}
		else if (ret == 0) {
			goto read0;
		}
		else {
			ret = CyaSSL_get_error(conn->xprt_ctx, ret);
			if (ret == SSL_ERROR_WANT_READ) {
				/* we need to poll for retry a read later */
				__conn_data_poll_recv(conn);
				break;
			}
			/* otherwise it's a real error */
			goto out_error;
		}
	}
	return done;

 read0:
	conn_sock_read0(conn);
	return done;
 out_error:
	conn->flags |= CO_FL_ERROR;
	return done;
}


/* Send all pending bytes from buffer <buf> to connection <conn>'s socket.
 * <flags> may contain MSG_MORE to make the system hold on without sending
 * data too fast, but this flag is ignored at the moment.
 * Only one call to send() is performed, unless the buffer wraps, in which case
 * a second call may be performed. The connection's flags are updated with
 * whatever special event is detected (error, empty). The caller is responsible
 * for taking care of those events and avoiding the call if inappropriate. The
 * function does not call the connection's polling update function, so the caller
 * is responsible for this.
 */
static int cyassl_sock_from_buf(struct connection *conn, struct buffer *buf, int flags)
{
	int ret, try, done;

	done = 0;

	if (!conn->xprt_ctx)
		goto out_error;

	if (conn->flags & CO_FL_HANDSHAKE)
		/* a handshake was requested */
		return 0;

	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (buf->o) {
		try = buf->o;
		/* outgoing data may wrap at the end */
		if (buf->data + try > buf->p)
			try = buf->data + try - buf->p;

		ret = CyaSSL_write(conn->xprt_ctx, bo_ptr(buf), try);
		if (ret > 0) {
			buf->o -= ret;
			done += ret;

			if (likely(!buffer_len(buf)))
				/* optimize data alignment in the buffer */
				buf->p = buf->data;

			/* if the system buffer is full, don't insist */
			if (ret < try)
				break;
		}
		else {
			ret = CyaSSL_get_error(conn->xprt_ctx, ret);
			if (ret == SSL_ERROR_WANT_WRITE) {
				/* we need to poll to retry a write later */
				__conn_data_poll_send(conn);
				break;
			}
			goto out_error;
		}
	}
	return done;

 out_error:
	conn->flags |= CO_FL_ERROR;
	return done;
}


static void cyassl_sock_close(struct connection *conn) {

	if (conn->xprt_ctx) {
		CyaSSL_free(conn->xprt_ctx);
		conn->xprt_ctx = NULL;
		sslconns--;
	}
}

/* This function tries to perform a clean shutdown on an SSL connection, and in
 * any case, flags the connection as reusable if no handshake was in progress.
 */
static void cyassl_sock_shutw(struct connection *conn, int clean)
{
	if (conn->flags & CO_FL_HANDSHAKE)
		return;
	/* no handshake was in progress, try a clean ssl shutdown */
	if (clean)
		CyaSSL_shutdown(conn->xprt_ctx);
}

/* used for logging, may be changed for a sample fetch later */
const char *cyassl_sock_get_cipher_name(struct connection *conn)
{
	if (!conn->xprt && !conn->xprt_ctx)
		return NULL;
	return CyaSSL_get_cipher(conn->xprt_ctx);
}

/* used for logging, may be changed for a sample fetch later */
const char *cyassl_sock_get_proto_version(struct connection *conn)
{
	if (!conn->xprt && !conn->xprt_ctx)
		return NULL;
	return CyaSSL_get_version(conn->xprt_ctx);
}

/***** Below are some sample fetching functions for ACL/patterns *****/

static int
smp_fetch_ssl_c_i_dn(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                     const struct arg *args, struct sample *smp)
{
	CYASSL_X509 *crt = NULL;
	CYASSL_X509_NAME *name;
	int ret = 0;
	struct chunk *smp_trash;

	if (!l4 || l4->si[0].conn->xprt != &cyassl_sock)
		return 0;

	if (!(l4->si[0].conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	/* SSL_get_peer_certificate, it increase X509 * ref count */
	crt = CyaSSL_get_peer_certificate(l4->si[0].conn->xprt_ctx);
	if (!crt)
		goto out;

	name = CyaSSL_X509_get_issuer_name(crt);
	if (!name)
		goto out;

	smp_trash = sample_get_trash_chunk();
	smp_trash->str = CyaSSL_X509_NAME_oneline(name,  smp_trash->str,  smp_trash->size);
	if (!smp_trash->str)
		goto out;

	smp_trash->len = strlen(smp_trash->str);

	smp->type = SMP_T_STR;
	smp->data.str = *smp_trash;
	ret = 1;
out:
	return ret;
}

static int
smp_fetch_ssl_c_s_dn(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                     const struct arg *args, struct sample *smp)
{
	CYASSL_X509 *crt = NULL;
	CYASSL_X509_NAME *name;
	int ret = 0;
	struct chunk *smp_trash;

	if (!l4 || l4->si[0].conn->xprt != &cyassl_sock)
		return 0;

	if (!(l4->si[0].conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	crt = CyaSSL_get_peer_certificate(l4->si[0].conn->xprt_ctx);
	if (!crt)
		goto out;

	name = CyaSSL_X509_get_subject_name(crt);
	if (!name)
		goto out;

	smp_trash = sample_get_trash_chunk();
	smp_trash->str = CyaSSL_X509_NAME_oneline(name,  smp_trash->str,  smp_trash->size);
	if (!smp_trash->str)
		goto out;

	smp_trash->len = strlen(smp_trash->str);

	smp->type = SMP_T_STR;
	smp->data.str = *smp_trash;
	ret = 1;
out:
	return ret;
}

/* bin, returns serial in a binary chunk */
static int
smp_fetch_ssl_c_serial(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	CYASSL_X509 *crt = NULL;
	int ret = 0;
	struct chunk *smp_trash;

	if (!l4 || l4->si[0].conn->xprt != &cyassl_sock)
		return 0;

	if (!(l4->si[0].conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	crt = CyaSSL_get_peer_certificate(l4->si[0].conn->xprt_ctx);
	if (!crt)
		goto out;

	smp_trash = sample_get_trash_chunk();
	smp_trash->len = smp_trash->size;
	if (CyaSSL_X509_get_serial_number(crt, (unsigned char *)smp_trash->str, &smp_trash->len) != 0)
		goto out;

	smp->data.str = *smp_trash;
	smp->type = SMP_T_BIN;
	ret = 1;
out:

	return ret;
}

/* integer, returns the verify result on client cert */
static int
smp_fetch_ssl_c_verify(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	if (!l4 || l4->si[0].conn->xprt != &cyassl_sock)
		return 0;

	if (!(l4->si[0].conn->flags & CO_FL_CONNECTED)) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	if (!l4->si[0].conn->xprt_ctx)
		return 0;

	smp->type = SMP_T_UINT;
	smp->data.uint = (l4->si[0].conn->xprt_st & SSL_SOCK_ST_FL_VERIFY_ERROR) ? 1 : 0;
	smp->flags = 0;

        return 1;
}

/* boolean, returns true if front conn. transport layer is SSL */
static int
smp_fetch_ssl_fc(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                 const struct arg *args, struct sample *smp)
{
	smp->type = SMP_T_BOOL;
	smp->data.uint = (l4->si[0].conn->xprt == &cyassl_sock);
	return 1;
}
static int
smp_fetch_ssl_fc_cipher(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                        const struct arg *args, struct sample *smp)
{
	smp->flags = 0;

	if (!l4 || !l4->si[0].conn->xprt_ctx || l4->si[0].conn->xprt != &cyassl_sock)
	return 0;

	smp->data.str.str = (char *)CyaSSL_get_cipher(l4->si[0].conn->xprt_ctx);
	if (!smp->data.str.str)
		return 0;

	smp->type = SMP_T_CSTR;
	smp->data.str.len = strlen(smp->data.str.str);

	return 1;
}

/* boolean, returns true if client cert was present */
static int
smp_fetch_ssl_fc_has_crt(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                         const struct arg *args, struct sample *smp)
{
	if (!l4 || l4->si[0].conn->xprt != &cyassl_sock)
		return 0;

	if (!(l4->si[0].conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->flags = 0;
	smp->type = SMP_T_BOOL;
	smp->data.uint = SSL_SOCK_ST_FL_VERIFY_DONE & l4->si[0].conn->xprt_st ? 1 : 0;

	return 1;
}

static int
smp_fetch_ssl_fc_protocol(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                          const struct arg *args, struct sample *smp)
{
	smp->flags = 0;

	if (!l4 || !l4->si[0].conn->xprt_ctx || l4->si[0].conn->xprt != &cyassl_sock)
		return 0;

	smp->data.str.str = (char *)CyaSSL_get_version(l4->si[0].conn->xprt_ctx);
	if (!smp->data.str.str)
		return 0;

	smp->type = SMP_T_CSTR;
	smp->data.str.len = strlen(smp->data.str.str);

	return 1;
}

static int
smp_fetch_ssl_fc_session_id(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                            const struct arg *args, struct sample *smp)
{
	CYASSL_SESSION *sess;

	smp->flags = 0;
	smp->type = SMP_T_CBIN;

	if (!l4 || !l4->si[0].conn->xprt_ctx || l4->si[0].conn->xprt != &cyassl_sock)
		return 0;

	sess = CyaSSL_get_session(l4->si[0].conn->xprt_ctx);
	if (!sess)
		return 0;

	smp->data.str.str = (char *)CyaSSL_get_sessionID(sess);
	if (!smp->data.str.str)
		return 0;

	smp->data.str.len = SSL_MAX_SSL_SESSION_ID_LENGTH;

	return 1;
}

/* parse the "ca-file" bind keyword */
static int bind_parse_ca_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CAfile path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/') && global.ca_base)
		memprintf(&conf->ca_file, "%s/%s", global.ca_base, args[cur_arg + 1]);
	else
		memprintf(&conf->ca_file, "%s", args[cur_arg + 1]);
	return 0;
}

/* parse the "ciphers" bind keyword */
static int bind_parse_ciphers(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->ciphers);
	conf->ciphers = strdup(args[cur_arg + 1]);
	return 0;
}

/* parse the "crt" bind keyword */
static int bind_parse_crt(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char path[PATH_MAX];
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing certificate location", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/' ) && global.crt_base) {
		if ((strlen(global.crt_base) + 1 + strlen(args[cur_arg + 1]) + 1) > PATH_MAX) {
			memprintf(err, "'%s' : path too long", args[cur_arg]);
			return ERR_ALERT | ERR_FATAL;
		}

		sprintf(path, "%s/%s",  global.crt_base, args[cur_arg + 1]);
		if (cyassl_sock_load_cert(path, conf, px, err) > 0)
			return ERR_ALERT | ERR_FATAL;

		return 0;
	}

	if (cyassl_sock_load_cert(args[cur_arg + 1], conf, px, err) > 0)
		return ERR_ALERT | ERR_FATAL;

	return 0;
}

/* parse the "crt_ignerr" and "ca_ignerr" bind keywords */
static int bind_parse_ignore_err(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char *p = args[cur_arg + 1];
	unsigned long long *ignerr = &conf->crt_ignerr;

	if (!*p) {
		if (err)
			memprintf(err, "'%s' : missing error IDs list", args[cur_arg]);
			return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(p, "all") == 0) {
		*ignerr = ~0ULL;
		return 0;
	}
	memprintf(err, "'%s' : only value all is supported using cyassl", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
}

/* parse the "force-sslv3" bind keyword */
static int bind_parse_force_sslv3(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_USE_SSLV3;
	return 0;
}

/* parse the "force-tlsv10" bind keyword */
static int bind_parse_force_tlsv10(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_USE_TLSV10;
	return 0;
}

/* parse the "force-tlsv11" bind keyword */
static int bind_parse_force_tlsv11(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_USE_TLSV11;
	return 0;
}

/* parse the "force-tlsv12" bind keyword */
static int bind_parse_force_tlsv12(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (err)
		memprintf(err, "'%s' : library does not support protocol TLSv1.2", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
}

/* parse the "ssl" bind keyword */
static int bind_parse_ssl(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	conf->is_ssl = 1;

	if (global.listen_default_ciphers && !conf->ciphers)
		conf->ciphers = strdup(global.listen_default_ciphers);

	list_for_each_entry(l, &conf->listeners, by_bind)
		l->xprt = &cyassl_sock;

	return 0;
}

/* parse the "verify" bind keyword */
static int bind_parse_verify(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing verify method", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[cur_arg + 1], "none") == 0)
		conf->verify = SSL_VERIFY_NONE;
	else if (strcmp(args[cur_arg + 1], "optional") == 0)
		conf->verify = SSL_VERIFY_PEER;
	else if (strcmp(args[cur_arg + 1], "required") == 0)
		conf->verify = SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	else {
		if (err)
			memprintf(err, "'%s' : unknown verify method '%s', only 'none', 'optional', and 'required' are supported\n",
		args[cur_arg], args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}


/************** "server" keywords ****************/

/* parse the "ca-file" server keyword */
static int srv_parse_ca_file(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CAfile path", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[*cur_arg + 1] != '/') && global.ca_base)
		memprintf(&newsrv->ssl_ctx.ca_file, "%s/%s", global.ca_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.ca_file, "%s", args[*cur_arg + 1]);

	return 0;
}

/* parse the "check-ssl" server keyword */
static int srv_parse_check_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->check.use_ssl = 1;
	if (global.connect_default_ciphers && !newsrv->ssl_ctx.ciphers)
		newsrv->ssl_ctx.ciphers = strdup(global.connect_default_ciphers);
	return 0;
}

/* parse the "ciphers" server keyword */
static int srv_parse_ciphers(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->ssl_ctx.ciphers);
	newsrv->ssl_ctx.ciphers = strdup(args[*cur_arg + 1]);
	return 0;
}

/* parse the "crt" server keyword */
static int srv_parse_crt(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing certificate file path", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[*cur_arg + 1] != '/') && global.crt_base)
		memprintf(&newsrv->ssl_ctx.client_crt, "%s/%s", global.ca_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.client_crt, "%s", args[*cur_arg + 1]);

	return 0;
}

/* parse the "force-sslv3" server keyword */
static int srv_parse_force_sslv3(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_USE_SSLV3;
	return 0;
}

/* parse the "force-tlsv10" server keyword */
static int srv_parse_force_tlsv10(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_USE_TLSV10;
	return 0;
}

/* parse the "force-tlsv11" server keyword */
static int srv_parse_force_tlsv11(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_USE_TLSV11;
	return 0;
}

/* parse the "force-tlsv12" server keyword */
static int srv_parse_force_tlsv12(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_USE_TLSV12;
	return 0;
}

/* parse the "ssl" server keyword */
static int srv_parse_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->use_ssl = 1;
	if (global.connect_default_ciphers && !newsrv->ssl_ctx.ciphers)
		newsrv->ssl_ctx.ciphers = strdup(global.connect_default_ciphers);
	return 0;
}

static int srv_parse_verify(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing verify method", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[*cur_arg + 1], "none") == 0)
		newsrv->ssl_ctx.verify = SSL_VERIFY_NONE;
	else if (strcmp(args[*cur_arg + 1], "required") == 0)
		newsrv->ssl_ctx.verify = SSL_VERIFY_PEER;
	else {
		if (err)
			memprintf(err, "'%s' : unknown verify method '%s', only 'none' and 'required' are supported\n",
			          args[*cur_arg], args[*cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {{ },{
	{ "ssl_c_i_dn",             smp_fetch_ssl_c_i_dn,         0,    NULL,    SMP_T_STR,  SMP_CAP_REQ|SMP_CAP_RES },
	{ "ssl_c_s_dn",             smp_fetch_ssl_c_s_dn,         0,    NULL,    SMP_T_STR,  SMP_CAP_REQ|SMP_CAP_RES },
	{ "ssl_c_serial",           smp_fetch_ssl_c_serial,       0,    NULL,    SMP_T_BIN,  SMP_CAP_REQ|SMP_CAP_RES },
	{ "ssl_c_verify",           smp_fetch_ssl_c_verify,       0,    NULL,    SMP_T_UINT, SMP_CAP_REQ|SMP_CAP_RES },
	{ "ssl_fc",                 smp_fetch_ssl_fc,             0,    NULL,    SMP_T_BOOL, SMP_CAP_REQ|SMP_CAP_RES },
	{ "ssl_fc_cipher",          smp_fetch_ssl_fc_cipher,      0,    NULL,    SMP_T_CSTR, SMP_CAP_REQ|SMP_CAP_RES },
	{ "ssl_fc_has_crt",         smp_fetch_ssl_fc_has_crt,     0,    NULL,    SMP_T_BOOL, SMP_CAP_REQ|SMP_CAP_RES },
	{ "ssl_fc_protocol",        smp_fetch_ssl_fc_protocol,    0,    NULL,    SMP_T_CSTR, SMP_CAP_REQ|SMP_CAP_RES },
	{ "ssl_fc_session_id",      smp_fetch_ssl_fc_session_id,  0,    NULL,    SMP_T_CBIN, SMP_CAP_REQ|SMP_CAP_RES },
	{ NULL, NULL, 0, 0, 0 },
}};

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {{ },{
	{ "ssl_c_i_dn",             acl_parse_str, smp_fetch_ssl_c_i_dn,         acl_match_str,     ACL_USE_L6REQ_PERMANENT|ACL_MAY_LOOKUP, 0 },
	{ "ssl_c_s_dn",             acl_parse_str, smp_fetch_ssl_c_s_dn,         acl_match_str,     ACL_USE_L6REQ_PERMANENT|ACL_MAY_LOOKUP, 0 },
	{ "ssl_c_verify",           acl_parse_int, smp_fetch_ssl_c_verify,       acl_match_int,     ACL_USE_L6REQ_PERMANENT|ACL_MAY_LOOKUP, 0 },
	{ "ssl_c_serial",           acl_parse_bin, smp_fetch_ssl_c_serial,       acl_match_bin,     ACL_USE_L6REQ_PERMANENT|ACL_MAY_LOOKUP, 0 },
	{ "ssl_fc",                 acl_parse_int, smp_fetch_ssl_fc,             acl_match_nothing, ACL_USE_L6REQ_PERMANENT|ACL_MAY_LOOKUP, 0 },
	{ "ssl_fc_cipher",          acl_parse_str, smp_fetch_ssl_fc_cipher,      acl_match_str,     ACL_USE_L6REQ_PERMANENT|ACL_MAY_LOOKUP, 0 },
	{ "ssl_fc_has_crt",         acl_parse_int, smp_fetch_ssl_fc_has_crt,     acl_match_nothing, ACL_USE_L6REQ_PERMANENT, 0 },
	{ "ssl_fc_protocol",        acl_parse_str, smp_fetch_ssl_fc_protocol,    acl_match_str,     ACL_USE_L6REQ_PERMANENT|ACL_MAY_LOOKUP, 0 },
	{ NULL, NULL, NULL, NULL },
}};

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct bind_kw_list bind_kws = { "SSL", { }, {
	{ "ca-file",               bind_parse_ca_file,        1 }, /* set CAfile to process verify on client cert */
	{ "ciphers",               bind_parse_ciphers,        1 }, /* set SSL cipher suite */
	{ "crt",                   bind_parse_crt,            1 }, /* load SSL certificates from this location */
	{ "crt-ignore-err",        bind_parse_ignore_err,     1 }, /* set to all to ignore verify error  */
	{ "force-sslv3",           bind_parse_force_sslv3,    0 }, /* force SSLv3 */
	{ "force-tlsv10",          bind_parse_force_tlsv10,   0 }, /* force TLSv10 */
	{ "force-tlsv11",          bind_parse_force_tlsv11,   0 }, /* force TLSv11 */
	{ "force-tlsv12",          bind_parse_force_tlsv12,   0 }, /* force TLSv12 */
	{ "ssl",                   bind_parse_ssl,            0 }, /* enable SSL processing */
	{ "verify",                bind_parse_verify,         1 }, /* client cert verify */
	{ NULL, NULL, 0 },
}};

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct srv_kw_list srv_kws = { "SSL", { }, {
	{ "ca-file",               srv_parse_ca_file,        1, 0 }, /* set CAfile to process verify on server cert */
	{ "check-ssl",             srv_parse_check_ssl,      0, 0 }, /* enable SSL for health checks */
	{ "ciphers",               srv_parse_ciphers,        1, 0 }, /* select the cipher suite */
	{ "crt",                   srv_parse_crt,            1, 0 }, /* set client certificate */
	{ "force-sslv3",           srv_parse_force_sslv3,    0, 0 }, /* force SSLv3 */
	{ "force-tlsv10",          srv_parse_force_tlsv10,   0, 0 }, /* force TLSv10 */
	{ "force-tlsv11",          srv_parse_force_tlsv11,   0, 0 }, /* force TLSv11 */
	{ "force-tlsv12",          srv_parse_force_tlsv12,   0, 0 }, /* force TLSv12 */
	{ "ssl",                   srv_parse_ssl,            0, 0 }, /* enable SSL processing */
	{ "verify",                srv_parse_verify,         1, 0 }, /* server cert verify */
	{ NULL, NULL, 0, 0 },
}};

/* transport-layer operations for SSL sockets */
struct xprt_ops cyassl_sock = {
	.snd_buf  = cyassl_sock_from_buf,
	.rcv_buf  = cyassl_sock_to_buf,
	.rcv_pipe = NULL,
	.snd_pipe = NULL,
	.shutr    = NULL,
	.shutw    = cyassl_sock_shutw,
	.close    = cyassl_sock_close,
	.init     = cyassl_sock_init,
};

__attribute__((constructor))
static void __cyassl_sock_init(void)
{
	CyaSSL_library_init();
	sample_register_fetches(&sample_fetch_keywords);
	acl_register_keywords(&acl_kws);
	bind_register_keywords(&bind_kws);
	srv_register_keywords(&srv_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
