

#include <nc_core.h>
#include <nc_sentinel.h>
#include <nc_conf.h>


#define STRING_SENTINEL "sentinel"

static rstatus_t
sentinel_each_set_owner(void *elem, void *data)
{
    struct server *s = elem;
    struct server_pool *sp = data;

    s->owner = sp;

    return NC_OK;
}

rstatus_t
sentinel_init(struct array *server, struct array *conf_server,
              struct server_pool *sp)
{
    rstatus_t status;
    uint32_t nserver;

    nserver = array_n(conf_server);
    ASSERT(nserver != 0);
    ASSERT(array_n(server) == 0);

    status = array_init(server, nserver, sizeof(struct server));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf server to server */
    status = array_each(conf_server, conf_sentinel_each_transform, server);
    if (status != NC_OK) {
        sentinel_deinit(server);
        return status;
    }
    ASSERT(array_n(server) == nserver);

    status = array_each(server, sentinel_each_set_owner, sp);
    if (status != NC_OK) {
        sentinel_deinit(server);
        return status;
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" sentinels in pool %"PRIu32" '%.*s'",
              nserver, sp->idx, sp->name.len, sp->name.data);

    return NC_OK;
}

void
sentinel_deinit(struct array *server)
{
    uint32_t i, nserver;

    for (i = 0, nserver = array_n(server); i < nserver; i++) {
        struct server *s;

        s = array_pop(server);
        if (s->timer) {
            msg_put(s->timer);
        }

        ASSERT(TAILQ_EMPTY(&s->s_conn_q) && s->ns_conn_q == 0);
    }
    array_deinit(server);
}

static struct server *
sentinel_get(struct server_pool *sp)
{
    struct server *server;

    server = sp->sentinel;
    if (server == NULL) {
        server = array_get(&sp->sentinels, 0);
    } else {
        /* close curr and switch to next ... */
        server_close(sp->ctx, sentinel_conn(server));
        server = array_get(&sp->sentinels, (server->idx+1)%array_n(&sp->sentinels));
    }

    sp->sentinel = server;
    return server;
}

struct conn *
sentinel_conn(struct server *server)
{
    struct conn* conn;

    if (server->ns_conn_q == 0) {
        return conn_get_sentinel(server);
    }
    ASSERT(server->ns_conn_q == 1);

    conn = TAILQ_FIRST(&server->s_conn_q);
    ASSERT(conn->sentinel);

    return conn;
}

rstatus_t
sentinel_connect(struct server_pool *sp) 
{
    rstatus_t status;

    uint32_t i;
    struct msg *msg;
    struct conn *conn;
    struct server *server, *s;

    server = sentinel_get(sp);
    if (server == NULL) {
        log_debug(LOG_ERR, "failed to get sentinel");
        return NC_ERROR;
    }
    server->weight = 0; /* Special use: index of 'groups' ^_^ */

    conn = sentinel_conn(server);
    if (conn == NULL) {
        log_debug(LOG_ERR, "failed to get sentinel conn");
        return NC_ERROR;
    }

    status = server_connect(sp->ctx, server, conn);
    if(status != NC_OK) {
        sentinel_close(sp->ctx, conn);
        return NC_ERROR;
    }

    status = req_sentinel_send_get_master_addr(sp->ctx, conn);
    if (status != NC_OK) {
        sentinel_close(sp->ctx, conn);
        return status;
    }

    /* clear status of every server */
    for (i = 0; i < array_n(&sp->server); ++i) {
        s = array_get(&sp->server, i);
        s->status = 0;
    }

    msg = server->timer;
    msg_tmo_delete(msg);
    msg->type = MSG_SENTINEL_TIMER_RECONN;
    msg_timer(msg, sp->sentinel_heartbeat, server);

    sp->state = STATE_WAITING_ADDR_RSP;
    return NC_OK;
}

void
sentinel_close(struct context *ctx, struct conn *conn)
{
    struct server *server;
    struct server_pool *sp;
    struct msg *msg;

    server = conn->owner;
    sp = server->owner;
    msg = server->timer;

    server->status = 0;
    sp->state = STATE_UNINITLIAZED;

    msg_tmo_delete(msg);
    msg->type = MSG_SENTINEL_TIMER_RECONN;
    msg_timer(msg, sp->sentinel_heartbeat, server);

    server_close(ctx, conn);
}

rstatus_t
sentinel_swallow_addr_rsp(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rstatus_t status;
    struct server *sentinel, *s;
    struct server_pool *sp;
    struct mbuf *mbuf;

    int32_t i;
    uint8_t *pos, *ip, *port;
    uint8_t ipport[32];

    sentinel = conn->owner;
    sp = sentinel->owner;
    log_debug(LOG_NOTICE, "recv 'get-master-addr-by-name' rsp from '%.*s'", 
              sentinel->pname.len, sentinel->pname.data);

    /*  request : sentinel get-master-addr-by-name mymaster1
        response:
                 *2\r\n               *-1\r\n    -ERR ...   i->0
                 $13\r\n                                    i->1
                 10.180.156.16\r\n                          i->2
                 $4\r\n                                     i->3
                 6380\r\n                                   i->4
     */
    mbuf = STAILQ_FIRST(&msg->mhdr);
    pos = mbuf->start;
    ip = NULL;
    port = NULL;

    for (i = 0; i < 5; ++i) {
        pos = nc_strchr(pos, mbuf->last, CR);
        if (pos == NULL) {
            log_error("ADDR rsp error: %.*s", mbuf->last-mbuf->start, mbuf->start);
            return NC_ERROR;
        }

        if (i == 1) {
            ip = pos + 2;
        } else if (i == 2) {
            *pos = '\0';
        } else if (i == 3) {
            port = pos + 2;
        } else if (i == 4) {
            *pos = '\0';
        }
        pos += 1;
    }

    if (ip == NULL || port == NULL) {
        log_error("ADDR rsp invalid: %.*s", mbuf->last-mbuf->start, mbuf->start);
        return NC_ERROR;
    }

    /* Special use: index of 'groups', mapping to 'pool->server' */
    s = array_get(&sp->server, sentinel->weight);
    if (s->idx != sentinel->weight) {
        log_error("ADDR rsp sequence is out of order");
        return NC_ERROR;
    }
    sentinel->weight++;

    nc_snprintf(ipport, sizeof(ipport), "%s:%s", ip, port);
    if (string_empty(&s->pname) || 
        0 != nc_strncmp(ipport, s->pname.data, s->pname.len)) {
        /* assign real ipport to every group */
        status = server_reset(s, ip, port);
        if (status != NC_OK) return status;
    } else {
        log_debug(LOG_NOTICE, "master of group '%.*s' is the same: '%.*s'", 
                  s->name.len, s->name.data, s->pname.len, s->pname.data);
    }

    /* trigger next flow */
    if (sentinel->weight == array_n(&sp->groups)) {
        server_pool_connect(ctx, sp);
        sp->state = STATE_WAITING_ROLE_RSP;
    }

    return NC_OK;
}

rstatus_t
sentinel_swallow_psub_rsp(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct server *sentinel;
    struct server_pool *sp;
    struct mbuf *mbuf;

    int32_t i;
    uint8_t *pos, *psub, *channel, *value;

    sentinel = conn->owner;
    sp = sentinel->owner;
    log_debug(LOG_NOTICE, "recv 'psubscribe +switch-master' rsp from '%.*s'", 
              sentinel->pname.len, sentinel->pname.data);

    /*  request : psubscribe +switch-master
        response:
                 *3                 ->0
                 $10                ->1
                 psubscribe         ->2
                 $14                ->3
                 +switch-master     ->4
                 :1                 ->5
     */
    mbuf = STAILQ_FIRST(&msg->mhdr);
    pos = mbuf->start;
    psub = NULL;
    channel = NULL;
    value = NULL;

    for (i = 0; i < 6; ++i) {
        pos = nc_strchr(pos, mbuf->last, CR);
        if (pos == NULL) {
            log_error("PSUB rsp error: %.*s", mbuf->last-mbuf->start, mbuf->start);
            return NC_ERROR;
        }

        if (i == 1) {
            psub = pos + 2;
        } else if (i == 3) {
            channel = pos + 2;
        }
        pos += 1;
    }
    value = pos - 2;

    if (psub == NULL || channel == NULL || value == NULL) {
        log_error("PSUB rsp invalid: %.*s", mbuf->last-mbuf->start, mbuf->start);
        return NC_ERROR;
    }

    if ((nc_strncmp(psub, MARK_PSUBSCB, nc_strlen(MARK_PSUBSCB)) != 0) 
        || (nc_strncmp(channel, MARK_CHANNEL, nc_strlen(MARK_CHANNEL)) != 0))
    {
        log_error("PSUB rsp invalid: %.*s", mbuf->last-mbuf->start, mbuf->start);
        return NC_ERROR;
    }

    if ('1' != *value) {
        log_warn("PSUBSCRIBE failed on %.*s | %.*s", sp->name.len, 
                 sp->name.data, sentinel->pname.len, sentinel->pname.data);
        return NC_ERROR;
    }

    /* trigger next flow */
    if (sp->state == STATE_WAITING_PSUB_RSP) {
        msg_tmo_delete(sentinel->timer);
        sentinel->timer->type = MSG_SENTINEL_TIMER_HEARTB;
        msg_timer(sentinel->timer, sp->sentinel_heartbeat, sentinel);

        sp->state = STATE_WAITING_RECV_PUB;
        loga("all right, pool '%.*s'is ready, here we go!", sp->name.len, sp->name.data);
    }

    return NC_OK;
}

rstatus_t
sentinel_swallow_recv_pub(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct server *sentinel, *s;
    struct server_pool *sp;
    struct mbuf *mbuf;

    uint32_t i;
    uint8_t *pos, *pmsg, *channel, *event, *info;
    uint8_t *group, *oldip, *oldport, *newip, *newport;
    uint16_t oldport_;

    bool exist;
    struct string *name;
    uint8_t old_ipport[32];

    sentinel = conn->owner;
    sp = sentinel->owner;
    log_debug(LOG_NOTICE, "recv 'pmessage' msg fm '%.*s'", 
              sentinel->pname.len, sentinel->pname.data);

    /*  publish message format:
        *4                                              ->0
        $8                                              ->1
        pmessage                                        ->2
        $14                                             ->3
        +switch-master                                  ->4
        $14                                             ->5
        +switch-master                                  ->6
        $47                                             ->7
        mymaster2 10.180.156.16 6381 10.180.156.16 6382 ->8
     */
    mbuf = STAILQ_FIRST(&msg->mhdr);
    pos = mbuf->start;
    pmsg = NULL;
    channel = NULL;
    event = NULL;
    info = NULL;

    for (i = 0; i < 9; ++i) {
        pos = nc_strchr(pos, mbuf->last, CR);
        if (pos == NULL) {
            log_error("PUB msg error: %.*s", mbuf->last-mbuf->start, mbuf->start);
            return NC_ERROR;
        }

        if (i == 1) {
            pmsg = pos + 2;
        } else if (i == 3) {
            channel = pos + 2;
        } else if (i == 5) {
            event = pos + 2;
        } else if (i == 7) {
            info = pos + 2;
        } else if (i == 8) {
            *pos = '\0';
        }
        pos += 1;
    }

    if (pmsg == NULL || channel == NULL || event == NULL || info == NULL) {
        log_error("PUB msg invalid: %.*s", mbuf->last-mbuf->start, mbuf->start);
        return NC_ERROR;
    }

    if ((nc_strncmp(pmsg, MARK_PMESSAGE, nc_strlen(MARK_PMESSAGE)) != 0) 
        || (nc_strncmp(channel, MARK_CHANNEL, nc_strlen(MARK_CHANNEL)) != 0)
        || (nc_strncmp(event, MARK_EVENT, nc_strlen(MARK_EVENT)) != 0))
    {
        log_error("PUB msg invalid: %.*s", mbuf->last-mbuf->start, mbuf->start);
        return NC_ERROR;
    }

    /* mymaster2 10.180.156.16 6381 10.180.156.16 6382 */
    group = info;
    oldip = NULL;
    oldport = NULL;
    newip = NULL;
    newport = NULL;
    for (i = 0; i < 4; ++i) {
        info = nc_strchr(info, pos, (uint8_t)0x20);
        if (info == NULL) {
            log_error("PUB msg error: %.*s", mbuf->last-mbuf->start, mbuf->start);
            return NC_ERROR;
        }
        *info = '\0';

        if (i == 0) {
            oldip = info + 1;
        } else if (i == 1) {
            oldport = info + 1;
        } else if (i == 2) {
            newip = info + 1;
        } else if (i == 3) {
            newport = info + 1;
        }
        pos += 1;
    }
    oldport_ = (uint16_t)nc_atoi(oldport, nc_strlen(oldport));

    exist = false;
    for (i = 0; i < array_n(&sp->groups); ++i) {
        name = array_get(&sp->groups, i);
        if (0 == nc_strncmp(group, name->data, name->len)) {
            exist = true;
            break;
        }
    }
    if (!exist) {
        log_warn("+switch-master group: [%s] is not in cluster", group);
        return NC_OK;
    }

    nc_snprintf(old_ipport, sizeof(old_ipport), "%s:%s", oldip, oldport);
    s = array_get(&sp->server, i);
    if (0 != nc_strncmp(group, s->name.data, s->name.len)
        || 0 != nc_strncmp(old_ipport, s->pname.data, s->pname.len) 
        || oldport_ != s->port) {
        log_error("master info mismatch: %.*s - %s", s->name.len, s->pname.data, old_ipport);
        return NC_ERROR;
    }

    server_reset(s, newip, newport);
    stats_server_incr(ctx, s, server_failover);
    return NC_OK;
}

rstatus_t
sentinel_swallow_psub_pub(struct context *ctx, struct conn *conn, struct msg *msg)
{
    int32_t i;
    uint8_t *pos, *mark;
    struct mbuf *mbuf;

    /* psubscribe rsp & publish msg 
       *x       -> 0
       $y       -> 1
       zz       -> 2
     */
    mbuf = STAILQ_FIRST(&msg->mhdr);
    pos = mbuf->start;
    mark = NULL;

    for (i = 0; i < 3; ++i) {
        pos = nc_strchr(pos, mbuf->last, CR);
        if (pos == NULL) {
            log_error("PSUB&PUB error: %.*s", mbuf->last-mbuf->start, mbuf->start);
            return NC_ERROR;
        }

        if (i == 1) {
            mark = pos + 2;
            if (nc_strncmp(mark, MARK_PSUBSCB, nc_strlen(MARK_PSUBSCB)) == 0) {
                return sentinel_swallow_psub_rsp(ctx, conn, msg);
            } else if (nc_strncmp(mark, MARK_PMESSAGE, nc_strlen(MARK_PMESSAGE)) == 0) {
                return sentinel_swallow_recv_pub(ctx, conn, msg);
            } else {
                log_error("PSUB&PUB error: %.*s", mbuf->last-mbuf->start, mbuf->start);
                break;
            }
        }
        pos += 1;
    }

    return NC_ERROR;
}

static bool
sentinel_rsp_filter(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct msg *pmsg;

    ASSERT(!conn->client && !conn->proxy);

    if (msg_empty(msg)) {
        ASSERT(conn->rmsg == NULL);
        log_debug(LOG_VERB, "filter empty rsp %"PRIu64" on s %d", msg->id,
                  conn->sd);
        rsp_put(msg);
        return true;
    }

    /* psub VS psub_rsp & pmessage */
    pmsg = TAILQ_FIRST(&conn->omsg_q);
    if (pmsg == NULL) {
        log_debug(LOG_WARN, "filter stray rsp %"PRIu64" len %"PRIu32" on s %d",
                  msg->id, msg->mlen, conn->sd);
        conn->swallow_msg(conn, NULL, msg);

        rsp_put(msg);
        return true;
    }
    ASSERT(pmsg->peer == NULL);
    ASSERT(pmsg->request && !pmsg->done);

    if (pmsg->swallow) {
        conn->swallow_msg(conn, pmsg, msg);

        conn->dequeue_outq(ctx, conn, pmsg);
        pmsg->done = 1;

        log_debug(LOG_INFO, "swallow rsp %"PRIu64" len %"PRIu32" of req "
                  "%"PRIu64" on s %d", msg->id, msg->mlen, pmsg->id,
                  conn->sd);

        rsp_put(msg);
        req_put(pmsg);
        return true;
    }

    return false;
}

static void
sentinel_rsp_forward(struct context *ctx, struct conn *conn, struct msg *msg)
{
    return;
}

void rsp_sentinel_recv_done(struct context *ctx, struct conn *conn, struct msg *msg, struct msg *nmsg)
{
    ASSERT(!conn->client && conn->sentinel);
    ASSERT(msg != NULL && conn->rmsg == msg);
    ASSERT(!msg->request);
    ASSERT(msg->owner == conn);
    ASSERT(nmsg == NULL || !nmsg->request);

    /* enqueue next message (response), if any */
    conn->rmsg = nmsg;

    if (sentinel_rsp_filter(ctx, conn, msg)) {
        return;
    }

    sentinel_rsp_forward(ctx, conn, msg);
}
