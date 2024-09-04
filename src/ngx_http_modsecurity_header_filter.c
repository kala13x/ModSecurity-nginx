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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_modsecurity_common.h"

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t ngx_http_modsecurity_resolv_header_server(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_date(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_content_length(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_content_type(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_last_modified(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_connection(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_transfer_encoding(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_vary(ngx_http_request_t *r, ngx_str_t name, off_t offset);

ngx_http_modsecurity_header_out_t ngx_http_modsecurity_headers_out[] = {
    { ngx_string("Server"), offsetof(ngx_http_headers_out_t, server), ngx_http_modsecurity_resolv_header_server },
    { ngx_string("Date"), offsetof(ngx_http_headers_out_t, date), ngx_http_modsecurity_resolv_header_date },
    { ngx_string("Content-Length"), offsetof(ngx_http_headers_out_t, content_length_n), ngx_http_modsecurity_resolv_header_content_length },
    { ngx_string("Content-Type"), offsetof(ngx_http_headers_out_t, content_type), ngx_http_modsecurity_resolv_header_content_type },
    { ngx_string("Last-Modified"), offsetof(ngx_http_headers_out_t, last_modified), ngx_http_modsecurity_resolv_header_last_modified },
    { ngx_string("Connection"), 0, ngx_http_modsecurity_resolv_header_connection },
    { ngx_string("Transfer-Encoding"), 0, ngx_http_modsecurity_resolv_header_transfer_encoding },
    { ngx_string("Vary"), 0, ngx_http_modsecurity_resolv_header_vary },
    { ngx_null_string, 0, 0 }
};

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
int ngx_http_modsecurity_store_ctx_header(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value)
{
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    if (ctx == NULL || ctx->sanity_headers_out == NULL) return NGX_ERROR;

    ngx_http_modsecurity_conf_t *mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf == NULL || mcf->sanity_checks_enabled == NGX_CONF_UNSET) return NGX_OK;

    ngx_http_modsecurity_header_t *hdr = ngx_array_push(ctx->sanity_headers_out);
    if (hdr == NULL) return NGX_ERROR;

    hdr->name.data = ngx_pnalloc(r->pool, name->len);
    hdr->value.data = ngx_pnalloc(r->pool, value->len);
    if (hdr->name.data == NULL || hdr->value.data == NULL) return NGX_ERROR;

    ngx_memcpy(hdr->name.data, name->data, name->len);
    hdr->name.len = name->len;
    ngx_memcpy(hdr->value.data, value->data, value->len);
    hdr->value.len = value->len;

    return NGX_OK;
}
#endif

static ngx_int_t ngx_http_modsecurity_resolv_header_server(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_core_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    ngx_str_t value;

    static char ngx_http_server_full_string[] = NGINX_VER;
    static char ngx_http_server_string[] = "nginx";

    if (r->headers_out.server == NULL)
    {
        value.data = (u_char *)(clcf->server_tokens ? ngx_http_server_full_string : ngx_http_server_string);
        value.len = clcf->server_tokens ? sizeof(ngx_http_server_full_string) : sizeof(ngx_http_server_string);
    }
    else
    {
        ngx_table_elt_t *h = r->headers_out.server;
        value.data = h->value.data;
        value.len = h->value.len;
    }

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data, name.len,
        (const unsigned char *) value.data, value.len);
}

static ngx_int_t ngx_http_modsecurity_resolv_header_date(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    ngx_str_t date;

    if (r->headers_out.date == NULL)
    {
        date.data = ngx_cached_http_time.data;
        date.len = ngx_cached_http_time.len;
    }
    else
    {
        ngx_table_elt_t *h = r->headers_out.date;
        date.data = h->value.data;
        date.len = h->value.len;
    }

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &date);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data, name.len,
        (const unsigned char *) date.data, date.len);
}

static ngx_int_t ngx_http_modsecurity_resolv_header_content_length(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    if (r->headers_out.content_length_n <= 0) return NGX_OK;
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    char buf[NGX_INT64_LEN + 1];
    ngx_str_t value;

    ngx_sprintf((u_char *)buf, "%O", r->headers_out.content_length_n);
    value.data = (u_char *)buf;
    value.len = ngx_strlen(buf);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data, name.len,
        (const unsigned char *) value.data, value.len);
}

static ngx_int_t ngx_http_modsecurity_resolv_header_content_type(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    if (r->headers_out.content_type.len == 0) return NGX_OK;
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &r->headers_out.content_type);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data, name.len,
        (const unsigned char *) r->headers_out.content_type.data,
        r->headers_out.content_type.len);
}

static ngx_int_t ngx_http_modsecurity_resolv_header_last_modified(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    if (r->headers_out.last_modified_time == -1) return NGX_OK;
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    u_char buf[1024];
    ngx_str_t value;

    u_char *p = ngx_http_time(buf, r->headers_out.last_modified_time);
    value.data = buf;
    value.len = p - buf;

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data, name.len,
        (const unsigned char *) value.data, value.len);
}

static ngx_int_t ngx_http_modsecurity_resolv_header_connection(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    ngx_http_core_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    const char *connection;
    ngx_str_t value;

    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS)
    {
        connection = "upgrade";
    }
    else if (r->keepalive)
    {
        connection = "keep-alive";

        if (clcf->keepalive_header)
        {
            u_char buf[1024];
            ngx_sprintf(buf, "timeout=%T", clcf->keepalive_header);
            ngx_str_t keep_alive = ngx_string("Keep-Alive");
            value.data = buf;
            value.len = ngx_strlen(buf);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
            ngx_http_modsecurity_store_ctx_header(r, &keep_alive, &value);
#endif

            msc_add_n_response_header(ctx->modsec_transaction,
                (const unsigned char *) keep_alive.data, keep_alive.len,
                (const unsigned char *) value.data, value.len);
        }
    }
    else
    {
        connection = "close";
    }

    value.data = (u_char *)connection;
    value.len = ngx_strlen(connection);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data, name.len,
        (const unsigned char *) value.data, value.len);
}

static ngx_int_t ngx_http_modsecurity_resolv_header_transfer_encoding(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    if (!r->chunked)
    {
        return NGX_OK;
    }

    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    ngx_str_t value = ngx_string("chunked");

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data, name.len,
        (const unsigned char *) value.data, value.len);
}

static ngx_int_t ngx_http_modsecurity_resolv_header_vary(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
#if (NGX_HTTP_GZIP)
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    ngx_http_core_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->gzip_vary && clcf->gzip_vary)
    {
        ngx_str_t value = ngx_string("Accept-Encoding");

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

        return msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) name.data, name.len,
            (const unsigned char *) value.data, value.len);
    }
#endif

    return NGX_OK;
}

ngx_int_t ngx_http_modsecurity_header_filter_init(void)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_modsecurity_header_filter;

    return NGX_OK;
}

ngx_int_t ngx_http_modsecurity_header_filter(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    if (ctx == NULL || ctx->intervention_triggered || ctx->processed)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "skipping ModSecurity header filter, ctx: %p", ctx);

        return ngx_http_next_header_filter(r);
    }

    r->filter_need_in_memory = 1;
    ctx->processed = 1;

    for (ngx_uint_t i = 0; ngx_http_modsecurity_headers_out[i].name.len; i++)
    {
        ngx_http_modsecurity_headers_out[i].resolver(r,
            ngx_http_modsecurity_headers_out[i].name,
            ngx_http_modsecurity_headers_out[i].offset);
    }

    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *data = part->elts;

    for (ngx_uint_t i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
            {
                break;
            }

            part = part->next;
            data = part->elts;
            i = 0;
        }

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        ngx_http_modsecurity_store_ctx_header(r, &data[i].key, &data[i].value);
#endif

        msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *)data[i].key.data, data[i].key.len,
            (const unsigned char *) data[i].value.data, data[i].value.len);
    }

    ngx_uint_t status = r->err_status ? r->err_status : r->headers_out.status;
    const char *http_response_ver = "HTTP 1.1";

#if (NGX_HTTP_V2)
    if (r->stream)
    {
        http_response_ver = "HTTP 2.0";
    }
#endif

    ngx_pool_t *old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_response_headers(ctx->modsec_transaction, status, http_response_ver);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    int ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
    if (r->error_page || ret <= 0) return ngx_http_next_header_filter(r);
    return ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module, ret);
}
