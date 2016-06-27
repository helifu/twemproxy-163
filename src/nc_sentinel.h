
#ifndef _NC_SENTINEL_H_
#define _NC_SENTINEL_H_

#include <nc_core.h>


rstatus_t sentinel_init(struct array *server, struct array *conf_server, struct server_pool *sp);
void sentinel_deinit(struct array *server);
struct conn *sentinel_conn(struct server *server);
rstatus_t sentinel_connect(struct server_pool *sp);
void sentinel_close(struct context *ctx, struct conn *conn);

rstatus_t sentinel_swallow_addr_rsp(struct context *ctx, struct conn *conn, struct msg *msg);
rstatus_t sentinel_swallow_psub_rsp(struct context *ctx, struct conn *conn, struct msg *msg);
rstatus_t sentinel_swallow_recv_pub(struct context *ctx, struct conn *conn, struct msg *msg);
rstatus_t sentinel_swallow_psub_pub(struct context *ctx, struct conn *conn, struct msg *msg);

#endif
