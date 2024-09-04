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

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

ngx_int_t ngx_http_modsecurity_body_filter_init(void)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_modsecurity_body_filter;

    return NGX_OK;
}

ngx_int_t ngx_http_modsecurity_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    if (in == NULL) return ngx_http_next_body_filter(r, in);
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    if (ctx == NULL || ctx->intervention_triggered) return ngx_http_next_body_filter(r, in);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_conf_t *mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf != NULL && mcf->sanity_checks_enabled != NGX_CONF_UNSET)
    {
        ngx_list_part_t *part = &r->headers_out.headers.part;
        ngx_table_elt_t *data = part->elts;
        ngx_uint_t i = 0;
        int worth_to_fail = 0;

        do {
            for (i = 0; i < part->nelts; i++)
            {
                ngx_uint_t j = 0;
                ngx_table_elt_t *s1 = &data[i];
                ngx_http_modsecurity_header_t *vals = ctx->sanity_headers_out->elts;
                int found = 0;

                for (j = 0; j < ctx->sanity_headers_out->nelts; j++)
                {
                    ngx_str_t *s2 = &vals[j].name;
                    ngx_str_t *s3 = &vals[j].value;

                    if (s1->key.len == s2->len && !ngx_strncmp(s1->key.data, s2->data, s1->key.len) &&
                        s1->value.len == s3->len && !ngx_strncmp(s1->value.data, s3->data, s1->value.len))
                    {
                        found = 1;
                        break;
                    }
                }

                if (!found)
                {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "header: `%V` with value: `%V` was not inspected by ModSecurity",
                                  &s1->key, &s1->value);

                    worth_to_fail++;
                }
            }

            part = part->next;
            data = part->elts;
        } while (part);

        if (worth_to_fail)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%d header(s) were not inspected by ModSecurity, exiting", worth_to_fail);

            return ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module,
                                                    NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
    }
#endif

    ngx_chain_t *chain;
    ngx_int_t is_request_processed = 0;

    for (chain = in; chain != NULL; chain = chain->next)
    {
        u_char *data = chain->buf->pos;
        ngx_int_t ret;

        msc_append_response_body(ctx->modsec_transaction, data, chain->buf->last - data);
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
        if (ret > 0) return ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module, ret);

        is_request_processed = chain->buf->last_buf;
        if (is_request_processed)
        {
            ngx_pool_t *old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
            msc_process_response_body(ctx->modsec_transaction);
            ngx_http_modsecurity_pcre_malloc_done(old_pool);

            ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
            if (ret != NGX_OK)
            {
                ngx_int_t status = ret > 0 ? ret : NGX_HTTP_INTERNAL_SERVER_ERROR;
                return ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module, status);
            }
        }
    }

    if (!is_request_processed)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "buffer was not fully loaded! ctx: %p", ctx);
    }

    return ngx_http_next_body_filter(r, in);
}
