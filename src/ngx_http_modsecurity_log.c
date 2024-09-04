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

#include "ngx_http_modsecurity_common.h"

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif

void ngx_http_modsecurity_log(void *log, const void *data)
{
    if (log == NULL || data == NULL) return;
    const char *msg = (const char *) data;
    ngx_log_error(NGX_LOG_INFO, (ngx_log_t *) log, 0, "%s", msg);
}

ngx_int_t ngx_http_modsecurity_log_handler(ngx_http_request_t *r)
{
    ngx_http_modsecurity_conf_t *mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf == NULL || mcf->enable != 1)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ModSecurity not enabled, skipping log handler.");
        return NGX_OK;
    }

    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    if (ctx == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ModSecurity context is null, cannot log.");
        return NGX_ERROR;
    }

    if (ctx->logged)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Request already logged.");
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "Logging request with ModSecurity, transaction: %p", ctx);

    ngx_pool_t *old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_logging(ctx->modsec_transaction);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    ctx->logged = 1;
    return NGX_OK;
}
