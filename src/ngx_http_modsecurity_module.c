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

#ifdef _MSC_VER
#define strdup _strdup
#endif

static ngx_int_t ngx_http_modsecurity_init(ngx_conf_t *cf);
static void *ngx_http_modsecurity_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_modsecurity_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_modsecurity_create_conf(ngx_conf_t *cf);
static char *ngx_http_modsecurity_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_modsecurity_cleanup_instance(void *data);
static void ngx_http_modsecurity_cleanup_rules(void *data);

#if !(NGX_PCRE2)
static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);
static ngx_pool_t *ngx_http_modsec_pcre_pool = NULL;

static void *ngx_http_modsec_pcre_malloc(size_t size)
{
    if (ngx_http_modsec_pcre_pool)
    {
        return ngx_palloc(ngx_http_modsec_pcre_pool, size);
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ModSecurity PCRE malloc failed: empty PCRE pool");
    return NULL;
}

static void ngx_http_modsec_pcre_free(void *ptr)
{
    if (ngx_http_modsec_pcre_pool)
    {
        ngx_pfree(ngx_http_modsec_pcre_pool, ptr);
        return;
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ModSecurity PCRE free failed: empty PCRE pool");
}

ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool)
{
    ngx_pool_t *old_pool;

    if (pcre_malloc != ngx_http_modsec_pcre_malloc)
    {
        ngx_http_modsec_pcre_pool = pool;

        old_pcre_malloc = pcre_malloc;
        old_pcre_free = pcre_free;

        pcre_malloc = ngx_http_modsec_pcre_malloc;
        pcre_free = ngx_http_modsec_pcre_free;

        return NULL;
    }

    old_pool = ngx_http_modsec_pcre_pool;
    ngx_http_modsec_pcre_pool = pool;

    return old_pool;
}

void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *old_pool)
{
    ngx_http_modsec_pcre_pool = old_pool;

    if (old_pool == NULL)
    {
        pcre_malloc = old_pcre_malloc;
        pcre_free = old_pcre_free;
    }
}
#endif

ngx_inline char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p)
{
    if (a.len == 0)
    {
        return NULL;
    }

    char *str = ngx_pnalloc(p, a.len + 1);
    if (str == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Failed to allocate memory to convert ngx_string to C string");
        return (char *)-1;
    }

    ngx_memcpy(str, a.data, a.len);
    str[a.len] = '\0';

    return str;
}

int ngx_http_modsecurity_process_intervention(Transaction *transaction, ngx_http_request_t *r, ngx_int_t early_log)
{
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;

    ngx_http_modsecurity_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    if (ctx == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (msc_intervention(transaction, &intervention) == 0) return 0;

    if (intervention.log)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", intervention.log);
        free(intervention.log);
    }

    if (intervention.url)
    {
        if (r->header_sent)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Headers already sent, cannot perform redirection");
            return -1;
        }

        ngx_http_clear_location(r);
        ngx_str_t location_str = ngx_string("");
        location_str.data = (unsigned char *)intervention.url;
        location_str.len = strlen(intervention.url);

        ngx_table_elt_t *location = ngx_list_push(&r->headers_out.headers);
        ngx_str_set(&location->key, "Location");
        location->value = location_str;
        r->headers_out.location = location;
        r->headers_out.location->hash = 1;

        return intervention.status;
    }

    if (intervention.status != 200)
    {
        msc_update_status_code(ctx->modsec_transaction, intervention.status);

        if (early_log)
        {
            ngx_http_modsecurity_log_handler(r);
            ctx->logged = 1;
        }

        if (r->header_sent)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Headers already sent, cannot perform redirection");
            return -1;
        }

        return intervention.status;
    }

    return 0;
}

void ngx_http_modsecurity_cleanup(void *data)
{
    ngx_http_modsecurity_ctx_t *ctx = data;
    msc_transaction_cleanup(ctx->modsec_transaction);
#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_array_destroy(ctx->sanity_headers_out);
#endif
}

ngx_int_t ngx_http_modsecurity_create_transaction(ngx_http_modsecurity_ctx_t *ctx, ngx_http_request_t *r)
{
    ngx_http_modsecurity_conf_t *mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    ngx_http_modsecurity_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_modsecurity_module);

    if (mcf->transaction_id)
    {
        ngx_str_t transaction_id_str;
        if (ngx_http_complex_value(r, mcf->transaction_id, &transaction_id_str) != NGX_OK) return -1;

        ctx->modsec_transaction = msc_new_transaction_with_id(mmcf->modsec, mcf->rules_set,
            (char *)transaction_id_str.data, r->connection->log);
    }
    else
    {
        ctx->modsec_transaction = msc_new_transaction(mmcf->modsec, mcf->rules_set, r->connection->log);
    }

    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to create ModSecurity context cleanup");
        return -1;
    }

    cln->handler = ngx_http_modsecurity_cleanup;
    cln->data = ctx;

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ctx->sanity_headers_out = ngx_array_create(r->pool, 12, sizeof(ngx_http_modsecurity_header_t));
    if (ctx->sanity_headers_out == NULL) return -1;
#endif

    return 0;
}

char *
ngx_conf_modsecurity_set_thread_pool_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_thread_pool_t *tp;
    ngx_http_modsecurity_conf_t *mcf = conf;

    value = cf->args->elts;
    value++;

    tp = ngx_thread_pool_add(cf, value);
    mcf->thread_pool = tp;

    return NGX_CONF_OK;
}

char *ngx_conf_set_rules(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    char *rules = ngx_str_to_char(value[1], cf->pool);
    if (rules == (char *)-1) return NGX_CONF_ERROR;

    const char *error;
    ngx_pool_t *old_pool = ngx_http_modsecurity_pcre_malloc_init(cf->pool);
    int res = msc_rules_add(((ngx_http_modsecurity_conf_t *)conf)->rules_set, rules, &error);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    if (res < 0)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to load rules: %s", error);
        return strdup(error);
    }

    ngx_http_modsecurity_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_modsecurity_module);
    mmcf->rules_inline += res;

    return NGX_CONF_OK;
}

char *ngx_conf_set_rules_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    char *rules_set = ngx_str_to_char(value[1], cf->pool);
    if (rules_set == (char *)-1) return NGX_CONF_ERROR;

    const char *error;
    ngx_pool_t *old_pool = ngx_http_modsecurity_pcre_malloc_init(cf->pool);
    int res = msc_rules_add_file(((ngx_http_modsecurity_conf_t *)conf)->rules_set, rules_set, &error);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    if (res < 0)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to load rules from file: %s", error);
        return strdup(error);
    }

    ngx_http_modsecurity_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_modsecurity_module);
    mmcf->rules_file += res;

    return NGX_CONF_OK;
}

char *ngx_conf_set_rules_remote(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    const char *rules_remote_key = ngx_str_to_char(value[1], cf->pool);
    const char *rules_remote_server = ngx_str_to_char(value[2], cf->pool);
    if (rules_remote_key == (char *)-1 || rules_remote_server == (char *)-1)
    {
        return NGX_CONF_ERROR;
    }

    const char *error;
    ngx_pool_t *old_pool = ngx_http_modsecurity_pcre_malloc_init(cf->pool);
    int res = msc_rules_add_remote(((ngx_http_modsecurity_conf_t *)conf)->rules_set, rules_remote_key, rules_remote_server, &error);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    if (res < 0)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to load rules from remote server: %s", error);
        return strdup(error);
    }

    ngx_http_modsecurity_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_modsecurity_module);
    mmcf->rules_remote += res;

    return NGX_CONF_OK;
}

char *ngx_conf_set_transaction_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_compile_complex_value_t ccv;
    ngx_http_complex_value_t cv;
    ngx_http_modsecurity_conf_t *mcf = conf;

    ngx_memzero(&ccv, sizeof(ccv));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return NGX_CONF_ERROR;

    mcf->transaction_id = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (mcf->transaction_id == NULL) return NGX_CONF_ERROR;

    *mcf->transaction_id = cv;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_modsecurity_commands[] = {
    {
        ngx_string("modsecurity"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_modsecurity_conf_t, enable),
        NULL
    },
    {
        ngx_string("modsecurity_thread_pool"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_modsecurity_set_thread_pool_name,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_modsecurity_conf_t, thread_pool_name),
        NULL
    },
    {
        ngx_string("modsecurity_rules"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_rules,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_modsecurity_conf_t, enable),
        NULL
    },
    {
        ngx_string("modsecurity_rules_file"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_rules_file,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_modsecurity_conf_t, enable),
        NULL
    },
    {
        ngx_string("modsecurity_rules_remote"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2,
        ngx_conf_set_rules_remote,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_modsecurity_conf_t, enable),
        NULL
    },
    {
        ngx_string("modsecurity_transaction_id"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
        ngx_conf_set_transaction_id,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_modsecurity_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_modsecurity_init,              /* postconfiguration */

    ngx_http_modsecurity_create_main_conf,  /* create main configuration */
    ngx_http_modsecurity_init_main_conf,    /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_modsecurity_create_conf,       /* create location configuration */
    ngx_http_modsecurity_merge_conf         /* merge location configuration */
};

ngx_module_t ngx_http_modsecurity_module = {
    NGX_MODULE_V1,
    &ngx_http_modsecurity_ctx,              /* module context */
    ngx_http_modsecurity_commands,          /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

#include <pcre.h>

static ngx_int_t ngx_http_modsecurity_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Core main configuration not found");
        return NGX_ERROR;
    }

    ngx_http_handler_pt *h_rewrite = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h_rewrite == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to create NGX_HTTP_REWRITE_PHASE handler");
        return NGX_ERROR;
    }
    *h_rewrite = ngx_http_modsecurity_rewrite_handler;

    ngx_http_handler_pt *h_preaccess = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h_preaccess == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to create NGX_HTTP_PREACCESS_PHASE handler");
        return NGX_ERROR;
    }
    *h_preaccess = ngx_http_modsecurity_pre_access_handler;

    ngx_http_handler_pt *h_log = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h_log == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to create NGX_HTTP_LOG_PHASE handler");
        return NGX_ERROR;
    }
    *h_log = ngx_http_modsecurity_log_handler;

    if (ngx_http_modsecurity_header_filter_init() != NGX_OK ||
        ngx_http_modsecurity_body_filter_init() != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *ngx_http_modsecurity_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_modsecurity_main_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_modsecurity_main_conf_t));
    if (conf == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to allocate memory for main configuration");
        return NGX_CONF_ERROR;
    }

    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to add cleanup handler for main configuration");
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_modsecurity_cleanup_instance;
    cln->data = conf;
    conf->pool = cf->pool;
    conf->modsec = msc_init();

    if (conf->modsec == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to initialize ModSecurity instance");
        return NGX_CONF_ERROR;
    }

    msc_set_connector_info(conf->modsec, MODSECURITY_NGINX_WHOAMI);
    msc_set_log_cb(conf->modsec, ngx_http_modsecurity_log);

    return conf;
}

static char *ngx_http_modsecurity_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_modsecurity_main_conf_t *mmcf = conf;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "%s (rules loaded inline/local/remote: %ui/%ui/%ui)",
                  MODSECURITY_NGINX_WHOAMI, mmcf->rules_inline,
                  mmcf->rules_file, mmcf->rules_remote);

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "libmodsecurity3 version %s.%s.%s",
                  MODSECURITY_MAJOR, MODSECURITY_MINOR, MODSECURITY_PATCHLEVEL);

    return NGX_CONF_OK;
}

static void *ngx_http_modsecurity_create_conf(ngx_conf_t *cf)
{
    ngx_http_modsecurity_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_modsecurity_conf_t));
    if (conf == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to allocate memory for location configuration");
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->rules_set = msc_create_rules_set();
    conf->pool = cf->pool;
    conf->transaction_id = NGX_CONF_UNSET_PTR;
    conf->thread_pool = ngx_thread_pool_add(cf, NULL);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    conf->sanity_checks_enabled = NGX_CONF_UNSET;
#endif

    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to add cleanup handler for location configuration");
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_modsecurity_cleanup_rules;
    cln->data = conf;

    return conf;
}

static char *ngx_http_modsecurity_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_modsecurity_conf_t *prev = parent;
    ngx_http_modsecurity_conf_t *conf = child;
    const char *error = NULL;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->transaction_id, prev->transaction_id, NULL);
    ngx_conf_merge_str_value(conf->thread_pool_name, prev->thread_pool_name, "");

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_conf_merge_value(conf->sanity_checks_enabled, prev->sanity_checks_enabled, 0);
#endif

    if (msc_rules_merge(conf->rules_set, prev->rules_set, &error) < 0)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to merge rules: %s", error);
        return strdup(error);
    }

    return NGX_CONF_OK;
}

static void ngx_http_modsecurity_cleanup_instance(void *data)
{
    ngx_http_modsecurity_main_conf_t *mmcf = data;

    ngx_pool_t *old_pool = ngx_http_modsecurity_pcre_malloc_init(mmcf->pool);
    msc_cleanup(mmcf->modsec);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
}

static void ngx_http_modsecurity_cleanup_rules(void *data)
{
    ngx_http_modsecurity_conf_t *mcf = data;

    ngx_pool_t *old_pool = ngx_http_modsecurity_pcre_malloc_init(mcf->pool);
    msc_rules_cleanup(mcf->rules_set);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
