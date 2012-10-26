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

#include <string.h>
#include <sys/syslog.h>
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_hash.h"
#include "mod_log_config.h"

#define MODULE_NAME "mod_log_syslog"
#define MODULE_VERSION "0.1.0"

#define CUSTOM_LOG_PREFIX "syslog:"

#ifdef _DEBUG
#define DEBUGLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, NULL, MODULE_NAME ": " __VA_ARGS__)
#else
#define DEBUGLOG(...) //
#endif

module AP_MODULE_DECLARE_DATA log_syslog_module;

typedef struct syslog_code {
	char *name;
	int	value;
} syslog_code_t;

/* must end with '.' */
static syslog_code_t syslog_facilities[] = {
    { "local0.", LOG_LOCAL0 },
    { "local1.", LOG_LOCAL1 },
    { "local2.", LOG_LOCAL2 },
    { "local3.", LOG_LOCAL3 },
    { "local4.", LOG_LOCAL4 },
    { "local5.", LOG_LOCAL5 },
    { "local6.", LOG_LOCAL6 },
    { "local7.", LOG_LOCAL7 },
    { "user.",   LOG_USER   },
    { NULL, -1 },
};

static syslog_code_t syslog_priorities[] = {
    { "debug",   LOG_DEBUG   },
    { "info",    LOG_INFO    },
    { "notice",  LOG_NOTICE  },
    { "warning", LOG_WARNING },
    { "err",     LOG_ERR     },
    { "crit",    LOG_CRIT    },
    { "alert",   LOG_ALERT   },
    { "emerg",   LOG_EMERG   },
    { NULL, -1 },
};

// (num of facilities) * (num of priorities) < 100
static int syslog_flag_table[100];

static ap_log_writer_init *default_log_writer_init = NULL;
static ap_log_writer      *default_log_writer      = NULL;

typedef struct {
    apr_hash_t *name_to_pointer;
    unsigned int counter;
} log_syslog_config;


static void *create_log_syslog_server_conf(apr_pool_t *p, server_rec *s)
{
    log_syslog_config *config =
        (log_syslog_config *)apr_pcalloc(p, sizeof(*config));

    config->name_to_pointer = apr_hash_make(p);
    config->counter = 0;

    return (void *)config;
}

/*
 * Searches "<facility>." from string
 * and returns rest of the string
 */
static const char *extract_facility(const char *rest, int *facility)
{
    syslog_code_t *code;
    for(code = syslog_facilities; code->name; code++) {
        if(strstr(rest, code->name) == rest) {
            *facility = code->value;
            return rest + strlen(code->name);
        }
    }
    *facility = 0;
    return NULL;
}

/*
 * Tests if the string is valid priority string.
 * If valid set *priority and return 1
 */
static int extract_priority(const char *rest, int *priority)
{
    syslog_code_t *code;
    for(code = syslog_priorities; code->name; code++) {
        if(strcmp(rest, code->name) == 0) {
            *priority = code->value;
            return 1;
        }
    }
    *priority = 0;
    return 0;
}

static int *get_next_flag_reference(apr_pool_t *p, log_syslog_config *config, const char *name)
{
    int *flag_reference;
    int flag;
    int facility, priority;
    const char *rest = name + sizeof(CUSTOM_LOG_PREFIX) - 1;

    rest = extract_facility(rest, &facility);
    if(rest && extract_priority(rest, &priority)) {
        flag = facility|priority;
        syslog_flag_table[config->counter] = flag;
        flag_reference = syslog_flag_table + config->counter;

        config->counter++;
        return flag_reference;
    }
    return NULL;
}

/*
 * log_syslog_writer_init and get_next_flag_reference work like:
 *
 * if name matches "syslog:{facility}.{priority}"
 *   unless config->name_to_pointer[name] exists
 *     syslog_flag_table[config->counter] = facility|priority
 *     config->name_to_pointer[name] = syslog_flag_table + config->counter++
 *   return config->name_to_pointer[name]
 *
 */
static void *log_syslog_writer_init(apr_pool_t *p, server_rec *s, const char *name) 
{
    DEBUGLOG("log_writer_init is called with: %s", name);

    // starts with syslog:
    if(strstr(name, CUSTOM_LOG_PREFIX) == name) {
        log_syslog_config *config;
        int *flag_reference;

        config = ap_get_module_config(s->module_config, &log_syslog_module);
        if((flag_reference = apr_hash_get(config->name_to_pointer, name, APR_HASH_KEY_STRING))) {
            DEBUGLOG("%s is already in hash, flag=%d", name, *flag_reference);
            return flag_reference;
        }
        if((flag_reference = get_next_flag_reference(p, config, name))) {
            apr_hash_set(config->name_to_pointer, name, APR_HASH_KEY_STRING, flag_reference);
            DEBUGLOG("Register %s to hash, flag=%d", name, *flag_reference);
            return flag_reference;
        }
        ap_log_error(
                APLOG_MARK,
                APLOG_CRIT,
                APR_EGENERAL,
                s,
                MODULE_NAME ": Invalid syslog facility/priority => %s",
                name
                );
        return NULL;
    }

    if(default_log_writer_init != NULL && default_log_writer_init != log_syslog_writer_init) {
        return default_log_writer_init(p, s, name);
    }
    return NULL;
}

/*
 * If handle is a pointer refering to syslog_flag_table array,
 * it was initialized as a syslog writer in log_syslog_writer_init
 * and its dereferenced value is syslog flag.
 *
 * Otherwise this module is not responsible for the handle
 * and passes it to the default log_writer.
 *
 */
static apr_status_t log_syslog_writer(
        request_rec *r,
        void *handle, 
        const char **portions,
        int *lengths,
        int nelts,
        apr_size_t len)
{
    DEBUGLOG("log_writer is called");

    log_syslog_config *config = ap_get_module_config(r->server->module_config, &log_syslog_module);
    int *flag_reference = (int *)handle;

    /* handle is inside the syslog_flag_table array */
    if(
            syslog_flag_table <= flag_reference &&
            flag_reference <= (syslog_flag_table + config->counter)
      ) {
        int flag = *flag_reference;
        int i;
        char *s;
        char *str = apr_pcalloc(r->pool, len + 1);

        for (i = 0, s = str; i < nelts; ++i) {
            memcpy(s, portions[i], lengths[i]);
            s += lengths[i];
        }

        DEBUGLOG("syslog handle is found, writing with flag=%d", flag);
        syslog(flag, "%s", str);
        return APR_SUCCESS;
    }

    if(default_log_writer != NULL && default_log_writer != log_syslog_writer) {
        return default_log_writer(r, handle, portions, lengths, nelts, len);
    }

    ap_log_rerror(APLOG_MARK, APLOG_CRIT, APR_EGENERAL, r, MODULE_NAME ": No valid ap_log_writer is available!");
    return APR_EGENERAL;
}

/*
 * This hook must be called:
 * - After mod_log_config's configuration phase,
 *   because log_writer{_init} can be changed by configuration directives.
 * - Before mod_log_config's open_logs,
 *   i.e. log_writer_init is called.
 *
 */
static int log_syslog_open_logs(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    static APR_OPTIONAL_FN_TYPE(ap_log_set_writer_init) *set_writer_init;
    static APR_OPTIONAL_FN_TYPE(ap_log_set_writer) *set_writer;

    set_writer_init = APR_RETRIEVE_OPTIONAL_FN(ap_log_set_writer_init);
    set_writer = APR_RETRIEVE_OPTIONAL_FN(ap_log_set_writer);

    default_log_writer_init = set_writer_init(log_syslog_writer_init);
    default_log_writer = set_writer(log_syslog_writer);

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

