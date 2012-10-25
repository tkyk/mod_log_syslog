/*
 * The MIT License
 * Copyright (c) 2012 Takayuki Miwa <i@tkyk.name>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice, this permission notice, and the
 * following disclaimer shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_hash.h"
#include "mod_log_config.h"

#define MODULE_NAME "mod_log_syslog"
#define MODULE_VERSION "0.0.1"

#ifdef _DEBUG
#define DEBUGLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, NULL, MODULE_NAME ": " __VA_ARGS__)
#else
#define DEBUGLOG(...) //
#endif

#define TRACELOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, NULL, MODULE_NAME ": " __VA_ARGS__)

module AP_MODULE_DECLARE_DATA log_syslog_module;


static ap_log_writer_init *default_log_writer_init = NULL;
static ap_log_writer      *default_log_writer      = NULL;

typedef struct {
    apr_hash_t *handle_table;
} log_syslog_config;


static void *create_log_syslog_server_conf(apr_pool_t *p, server_rec *s)
{
    log_syslog_config *config =
        (log_syslog_config *)apr_pcalloc(p, sizeof(*config));

    config->handle_table = apr_hash_make(p);

    return (void *)config;
}

void *log_syslog_writer_init(apr_pool_t *p, server_rec *s, const char *name) 
{
    DEBUGLOG("log_writer_init is called with: %s", name);

    if(default_log_writer_init != NULL && default_log_writer_init != log_syslog_writer_init) {
        return default_log_writer_init(p, s, name);
    }
    return NULL;
}

apr_status_t log_syslog_writer(
        request_rec *r,
        void *handle, 
        const char **portions,
        int *lengths,
        int nelts,
        apr_size_t len)
{
    DEBUGLOG("log_writer is called");

    if(default_log_writer != NULL && default_log_writer != log_syslog_writer) {
        return default_log_writer(r, handle, portions, lengths, nelts, len);
    }

    ap_log_rerror(APLOG_MARK, APLOG_CRIT, APR_EGENERAL, r, MODULE_NAME ": No valid ap_log_writer is available!");
    return APR_EGENERAL;
}

static int log_syslog_open_logs(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    static APR_OPTIONAL_FN_TYPE(ap_log_set_writer_init) *set_writer_init;
    static APR_OPTIONAL_FN_TYPE(ap_log_set_writer) *set_writer;

    set_writer_init = APR_RETRIEVE_OPTIONAL_FN(ap_log_set_writer_init);
    set_writer = APR_RETRIEVE_OPTIONAL_FN(ap_log_set_writer);

    if(default_log_writer_init == NULL) {
        default_log_writer_init = set_writer_init(log_syslog_writer_init);
    }
    if(default_log_writer == NULL) {
        default_log_writer = set_writer(log_syslog_writer);
    }

    return OK;
}

static void log_syslog_register_hooks(apr_pool_t *p)
{
    static const char * const suc[] = {
        "mod_log_config.c",
        NULL
    };

    ap_hook_open_logs(log_syslog_open_logs, NULL, suc, APR_HOOK_FIRST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA log_syslog_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    create_log_syslog_server_conf,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    log_syslog_register_hooks  /* register hooks                      */
};

