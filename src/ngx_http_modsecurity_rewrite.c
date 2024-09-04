/*
 * ModSecurity connector for nginx, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif

#include "ngx_http_modsecurity_common.h"

void ngx_http_modsecurity_rewrite_task(void *data, ngx_log_t *log)
{
    ngx_http_modsecurity_task_ctx_t *task_ctx = data;
    ngx_http_modsecurity_ctx_t *ctx = task_ctx->ctx;
    ngx_http_request_t *r = task_ctx->request;

    if (ctx == NULL)
    {
        ctx = ngx_http_modsecurity_create_ctx(r);
        if (ctx == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0, "Failed to create ModSecurity context");
            task_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        task_ctx->ctx = ctx;
        int client_port = ngx_inet_get_port(r->connection->sockaddr);
        int server_port = ngx_inet_get_port(r->connection->local_sockaddr);
        const char *client_addr = ngx_str_to_char(r->connection->addr_text, r->pool);

        if (client_addr == (char *)-1)
        {
            task_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        ngx_str_t s;
        u_char addr[NGX_SOCKADDR_STRLEN];
        s.len = NGX_SOCKADDR_STRLEN;
        s.data = addr;

        if (ngx_connection_local_sockaddr(r->connection, &s, 0) != NGX_OK)
        {
            task_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        const char *server_addr = ngx_str_to_char(s, r->pool);
        if (server_addr == (char *)-1)
        {
            task_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        ngx_pool_t *old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
        int ret = msc_process_connection(ctx->modsec_transaction, client_addr, client_port, server_addr, server_port);
        ngx_http_modsecurity_pcre_malloc_done(old_pool);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "Processing connection intervention: %d", ret);
        int ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 1);

        if (ret > 0)
        {
            ctx->intervention_triggered = 1;
            task_ctx->status = ret;
            return;
        }

        const char *http_version;
        switch (r->http_version)
        {
            case NGX_HTTP_VERSION_9:
                http_version = "0.9";
                break;
            case NGX_HTTP_VERSION_10:
                http_version = "1.0";
                break;
            case NGX_HTTP_VERSION_11:
                http_version = "1.1";
                break;
#if defined(nginx_version) && nginx_version >= 1009005
            case NGX_HTTP_VERSION_20:
                http_version = "2.0";
                break;
#endif
            default:
                http_version = ngx_str_to_char(r->http_protocol, r->pool);
                if (http_version == (char *)-1)
                {
                    task_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    return;
                }
                http_version = (strncmp("HTTP/", http_version, 5) == 0) ? http_version + 5 : "1.0";
                break;
        }

        const char *uri = ngx_str_to_char(r->unparsed_uri, r->pool);
        const char *method = ngx_str_to_char(r->method_name, r->pool);

        if (uri == (char *)-1 || method == (char *)-1)
        {
            task_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
        msc_process_uri(ctx->modsec_transaction, uri, method, http_version);
        ngx_http_modsecurity_pcre_malloc_done(old_pool);

        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 1);
        if (ret > 0)
        {
            ctx->intervention_triggered = 1;
            task_ctx->status = ret;
            return;
        }

        ngx_list_part_t *part = &r->headers_in.headers.part;
        ngx_table_elt_t *data = part->elts;

        for (ngx_uint_t i = 0; /* void */; i++)
        {
            if (i >= part->nelts)
            {
                if (part->next == NULL) break;
                part = part->next;
                data = part->elts;
                i = 0;
            }

            ngx_log_error(NGX_LOG_DEBUG, log, 0, "Adding request header: %.*s with value %.*s",
                (int)data[i].key.len, data[i].key.data, (int)data[i].value.len, data[i].value.data);

            msc_add_n_request_header(ctx->modsec_transaction,
                (const unsigned char *)data[i].key.data, data[i].key.len,
                (const unsigned char *)data[i].value.data, data[i].value.len);
        }

        old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
        msc_process_request_headers(ctx->modsec_transaction);
        ngx_http_modsecurity_pcre_malloc_done(old_pool);

        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 1);
        if (!r->error_page && ret > 0)
        {
            ctx->intervention_triggered = 1;
            task_ctx->status = ret;
            return;
        }
    }

    task_ctx->status = NGX_DECLINED;
}

void ngx_http_modsecurity_rewrite_finish(ngx_event_t *ev)
{
    ngx_http_modsecurity_task_ctx_t *task_ctx = ev->data;
    ngx_http_core_main_conf_t *cmcf = ngx_http_get_module_main_conf(task_ctx->request, ngx_http_core_module);

    task_ctx->request->aio = 0;
    task_ctx->request->main->blocked--;

    switch (task_ctx->status)
    {
        case NGX_OK:
            task_ctx->request->phase_handler = cmcf->phase_engine.handlers->next;
            ngx_http_core_run_phases(task_ctx->request);
            break;
        case NGX_DECLINED:
            task_ctx->request->phase_handler++;
            ngx_http_core_run_phases(task_ctx->request);
            break;
        case NGX_AGAIN:
        case NGX_DONE:
            break;
        default:
            ngx_http_discard_request_body(task_ctx->request);
            ngx_http_finalize_request(task_ctx->request, task_ctx->status);
            break;
    }

    ngx_http_run_posted_requests(task_ctx->request->connection);
}

ngx_int_t ngx_http_modsecurity_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_modsecurity_conf_t *mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf == NULL || mcf->enable != 1) return NGX_DECLINED;

    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    ngx_thread_task_t *task = ngx_thread_task_alloc(r->pool, sizeof(ngx_http_modsecurity_task_ctx_t));

    if (task == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate thread task for ModSecurity");
        return NGX_ERROR;
    }

    ngx_http_modsecurity_task_ctx_t *task_ctx = task->ctx;
    task_ctx->request = r;
    task_ctx->ctx = ctx;
    task_ctx->status = NGX_DECLINED;

    task->handler = ngx_http_modsecurity_rewrite_task;
    task->event.handler = ngx_http_modsecurity_rewrite_finish;
    task->event.data = task_ctx;

    if (ngx_thread_task_post(mcf->thread_pool, task) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to post rewrite task for ModSecurity");
        return NGX_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;

    return NGX_DONE;
}
