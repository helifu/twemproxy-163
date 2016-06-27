
#include <ctype.h>

#include <nc_core.h>
#include <nc_proto.h>


void
sentinel_parse_req(struct msg *r)
{
    return;
}

void
sentinel_parse_rsp(struct msg *r)
{
    redis_parse_rsp(r);
    return;
}

void
sentinel_post_connect(struct context *ctx, struct conn *conn, struct server *server)
{
    return;
}

void
sentinel_swallow_msg(struct conn *conn, struct msg *pmsg, struct msg *msg)
{
    struct server *server;
    struct server_pool *pool;
    struct context *ctx;
    rstatus_t status;

    server = conn->owner;
    pool = server->owner;
    ctx = pool->ctx;

    switch (pool->state)
    {
    case STATE_WAITING_ADDR_RSP:
        status = sentinel_swallow_addr_rsp(ctx, conn, msg);
        break;
    case STATE_WAITING_PSUB_RSP:
        status = sentinel_swallow_psub_rsp(ctx, conn, msg);
        break;
    case STATE_WAITING_RECV_PUB:
        status = sentinel_swallow_psub_pub(ctx, conn, msg);
        break;
    case STATE_UNINITLIAZED:
    case STATE_WAITING_ROLE_RSP:
    default:
        log_warn("recv message fm sentinel with type: %d while state: %d", 
                 msg->type, pool->state);
        status = NC_ERROR;
        break;
    }

    if (status != NC_OK) {
        log_error("sentinel's response error, close sentinel conn.");
        conn->done = 1;
    }

    return;
}
