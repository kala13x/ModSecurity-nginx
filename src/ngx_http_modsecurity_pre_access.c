/*
 * connector for nginx, http://www.modsecurity.org/
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

#include "ngx_http_modsecurity_common.h"

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif

void ngx_http_modsecurity_request_read(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif

    if (ctx->waiting_more_body)
    {
        ctx->waiting_more_body = 0;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
    }
}

void ngx_http_modsecurity_pre_access_task(void *data, ngx_log_t *log)
{
    ngx_http_modsecurity_task_ctx_t *task_ctx = data;
    ngx_http_modsecurity_ctx_t *ctx = task_ctx->ctx;
    ngx_http_request_t *r = task_ctx->request;

    ngx_int_t ret, already_inspected = 0, have_body = 0;
    ngx_chain_t *chain = r->request_body->bufs;

    if (r->request_body->temp_file != NULL)
    {
        ngx_str_t file_path = r->request_body->temp_file->file.name;
        const char *file_name = ngx_str_to_char(file_path, r->pool);

        if (file_name == (char *)-1)
        {
            task_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "Inspecting request body from file: %s", file_name);
        have_body = msc_request_body_from_file(ctx->modsec_transaction, file_name);
        already_inspected = 1;
    }
    else
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "Inspecting request body in memory.");
    }

    while (chain && !already_inspected)
    {
        u_char *data = chain->buf->pos;
        msc_append_request_body(ctx->modsec_transaction, data, chain->buf->last - data);
        have_body = 1;

        if (chain->buf->last_buf) break;
        chain = chain->next;
    }

    if (!have_body)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "No request body data to inspect.");
        task_ctx->status = NGX_DECLINED;
        return;
    }

    msc_process_request_body(ctx->modsec_transaction);
    ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);

    if (r->error_page)
    {
        task_ctx->status = NGX_DECLINED;
        return;
    }

    if (ret > 0)
    {
        task_ctx->status = ret;
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "Body inspection completed, no interventions.");
    task_ctx->status = NGX_DECLINED;
}

void ngx_http_modsecurity_pre_access_finish(ngx_event_t *ev)
{
    ngx_http_modsecurity_task_ctx_t *task_ctx = ev->data;
    ngx_http_request_t *r = task_ctx->request;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_get_module_main_conf(task_ctx->request, ngx_http_core_module);
    r->main->blocked--;
    r->aio = 0;

    switch (task_ctx->status)
    {
        case NGX_OK:
            r->phase_handler = cmcf->phase_engine.handlers->next;
            ngx_http_core_run_phases(r);
            break;
        case NGX_DECLINED:
            r->phase_handler++;
            ngx_http_core_run_phases(r);
            break;
        default:
            ngx_http_discard_request_body(r);
            ngx_http_finalize_request(r, task_ctx->status);
    }

    ngx_http_run_posted_requests(r->connection);
}

ngx_int_t ngx_http_modsecurity_pre_access_handler(ngx_http_request_t *r)
{
    ngx_http_modsecurity_conf_t *mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf == NULL || mcf->enable != 1) return NGX_DECLINED;

    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    if (ctx == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ctx->intervention_triggered) return NGX_DECLINED;

    if (ctx->waiting_more_body)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "Waiting for more body data, count: %d", r->main->count);

        return NGX_DONE;
    }

    if (!ctx->body_requested)
    {
        ngx_int_t rc = NGX_OK;
        ctx->body_requested = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "Requesting body data, count: %d", r->main->count);

        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;

        if (!r->request_body_in_file_only)
        {
            r->request_body_in_clean_file = 1;
        }

        rc = ngx_http_read_client_request_body(r, ngx_http_modsecurity_request_read);
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE)
        {
#if (nginx_version < 1002006) || (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
#endif
            return rc;
        }

        if (rc == NGX_AGAIN)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Waiting for more data.");
            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
    }

    if (!ctx->waiting_more_body)
    {
        ngx_thread_task_t *task = ngx_thread_task_alloc(r->pool, sizeof(ngx_http_modsecurity_task_ctx_t));
        if (task == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate task.");
            return NGX_ERROR;
        }

        ngx_http_modsecurity_task_ctx_t *task_ctx = task->ctx;
        task_ctx->request = r;
        task_ctx->ctx = ctx;
        task_ctx->status = NGX_DECLINED;

        task->handler = ngx_http_modsecurity_pre_access_task;
        task->event.handler = ngx_http_modsecurity_pre_access_finish;
        task->event.data = task_ctx;

        if (ngx_thread_task_post(mcf->thread_pool, task) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "Failed to post task to thread pool.");

            return NGX_ERROR;
        }

        r->main->blocked++;
        r->aio = 1;
        return NGX_DONE;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "No intervention required, continuing.");

    return NGX_DECLINED;
}
