
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream_request.h>
#include <nginx.h>

static ngx_stream_request_variable_t *ngx_stream_request_add_prefix_variable(
      ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags);

//static ngx_int_t ngx_stream_request_get_variable_data (ngx_stream_request_t *r,
//          ngx_stream_request_variable_value_t *v, uintptr_t data);

static ngx_stream_request_variable_t  ngx_stream_request_core_variables[] = {

//    { ngx_string("request_data"), NULL,
//      ngx_stream_request_get_variable_data, 0,
//      NGX_STREAM_REQUEST_VAR_NOCACHEABLE|NGX_STREAM_REQUEST_VAR_CHANGEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t ngx_stream_request_get_variable_from_session (ngx_stream_request_t *r,
    ngx_stream_request_variable_value_t *v, uintptr_t data);

ngx_stream_request_variable_value_t  ngx_stream_request_variable_null_value =
    ngx_stream_request_variable("");
ngx_stream_request_variable_value_t  ngx_stream_request_variable_true_value =
    ngx_stream_request_variable("1");


static ngx_uint_t  ngx_stream_request_variable_depth = 100;


ngx_stream_request_variable_t *
ngx_stream_request_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
{
    ngx_int_t                     rc;
    ngx_uint_t                    i;
    ngx_hash_key_t               *key;
    ngx_stream_request_variable_t        *v;
    ngx_stream_request_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    if (flags & NGX_STREAM_REQUEST_VAR_PREFIX) {
        return ngx_stream_request_add_prefix_variable(cf, name, flags);
    }

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_request_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || ngx_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (!(v->flags & NGX_STREAM_REQUEST_VAR_CHANGEABLE)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        v->flags &= flags | ~NGX_STREAM_REQUEST_VAR_WEAK;

        return v;
    }

    v = ngx_palloc(cf->pool, sizeof(ngx_stream_variable_t));
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    rc = ngx_hash_add_key(cmcf->variables_keys, &v->name, v, 0);

    if (rc == NGX_ERROR) {
        return NULL;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }

    return v;
}


static ngx_stream_request_variable_t *
ngx_streamrequest__add_prefix_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags)
{
    ngx_uint_t                    i;
    ngx_stream_request_variable_t        *v;
    ngx_stream_request_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_request_core_module);

    v = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len != v[i].name.len
            || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
        {
            continue;
        }

        v = &v[i];

        if (!(v->flags & NGX_STREAM_REQUEST_VAR_CHANGEABLE)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        v->flags &= flags | ~NGX_STREAM_REQUEST_VAR_WEAK;

        return v;
    }

    v = ngx_array_push(&cmcf->prefix_variables);
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    return v;
}


ngx_int_t
ngx_stream_request_get_variable_index(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                    i;
    ngx_stream_request_variable_t        *v;
    ngx_stream_request_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NGX_ERROR;
    }

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_request_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (ngx_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(ngx_stream_variable_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || ngx_strncasecmp(name->data
                                   , v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }

    v = ngx_array_push(&cmcf->variables);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = 0;
    v->index = cmcf->variables.nelts - 1;

    return v->index;
}


ngx_stream_request_variable_value_t *
ngx_stream_request_get_indexed_variable(ngx_stream_request_t *r, ngx_uint_t index)
{
    ngx_stream_request_variable_t        *v;
    ngx_stream_request_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_get_module_main_conf(r->session, ngx_stream_request_core_module);

    if (cmcf->variables.nelts <= index) {
        ngx_log_error(NGX_LOG_ALERT, r->session->connection->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    if (r->variables[index].not_found || r->variables[index].valid) {
        return &r->variables[index];
    }

    v = cmcf->variables.elts;

    if (ngx_stream_request_variable_depth == 0) {
        ngx_log_error(NGX_LOG_ERR, r->session->connection->log, 0,
                      "cycle while evaluating variable \"%V\"",
                      &v[index].name);
        return NULL;
    }

    ngx_stream_request_variable_depth--;

    if (v[index].get_handler(r, &r->variables[index], v[index].data)
        == NGX_OK)
    {
        ngx_stream_request_variable_depth++;

        if (v[index].flags & NGX_STREAM_REQUEST_VAR_NOCACHEABLE) {
            r->variables[index].no_cacheable = 1;
        }

        return &r->variables[index];
    }

    ngx_stream_request_variable_depth++;

    r->variables[index].valid = 0;
    r->variables[index].not_found = 1;

    return NULL;
}


ngx_stream_request_variable_value_t *
ngx_stream_request_get_flushed_variable(ngx_stream_request_t *r, ngx_uint_t index)
{
    ngx_stream_request_variable_value_t  *v;

    v = &r->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return ngx_stream_request_get_indexed_variable(r, index);
}


ngx_stream_request_variable_value_t *
ngx_stream_request_get_variable(ngx_stream_request_t *r, ngx_str_t *name,
    ngx_uint_t key)
{
    size_t                        len;
    ngx_uint_t                    i, n;
    ngx_stream_request_variable_t        *v;
    ngx_stream_request_variable_value_t  *vv;
    ngx_stream_request_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_get_module_main_conf(r->session, ngx_stream_request_core_module);

    v = ngx_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & NGX_STREAM_REQUEST_VAR_INDEXED) {
            return ngx_stream_request_get_flushed_variable(r, v->index);
        }

        if (ngx_stream_request_variable_depth == 0) {
            ngx_log_error(NGX_LOG_ERR, r->session->connection->log, 0,
                          "cycle while evaluating variable \"%V\"", name);
            return NULL;
        }

        ngx_stream_request_variable_depth--;

        vv = ngx_palloc(r->pool,
                        sizeof(ngx_stream_request_variable_value_t));

        if (vv && v->get_handler(r, vv, v->data) == NGX_OK) {
            ngx_stream_request_variable_depth++;
            return vv;
        }

        ngx_stream_request_variable_depth++;
        return NULL;
    }

    vv = ngx_palloc(r->pool, sizeof(ngx_stream_request_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    len = 0;

    v = cmcf->prefix_variables.elts;
    n = cmcf->prefix_variables.nelts;

    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len >= v[i].name.len && name->len > len
            && ngx_strncmp(name->data, v[i].name.data, v[i].name.len) == 0)
        {
            len = v[i].name.len;
            n = i;
        }
    }

    if (n != cmcf->prefix_variables.nelts) {
        if (v[n].get_handler(r, vv, (uintptr_t) name) == NGX_OK) {
            return vv;
        }

        return NULL;
    }

    vv->not_found = 1;

    return vv;
}


void *
ngx_stream_request_map_find(ngx_stream_request_t *r, ngx_stream_request_map_t *map,
    ngx_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    ngx_uint_t   key;

    len = match->len;

    if (len) {
        low = ngx_pnalloc(r->pool, len);
        if (low == NULL) {
            return NULL;
        }

    } else {
        low = NULL;
    }

    key = ngx_hash_strlow(low, match->data, len);

    value = ngx_hash_find_combined(&map->hash, key, low, len);
    if (value) {
        return value;
    }

#if (NGX_PCRE)

    if (len && map->nregex) {
        ngx_int_t                n;
        ngx_uint_t               i;
        ngx_stream_request_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = ngx_stream_request_regex_exec(r, reg[i].regex, match);

            if (n == NGX_OK) {
                return reg[i].value;
            }

            if (n == NGX_DECLINED) {
                continue;
            }

            /* NGX_ERROR */

            return NULL;
        }
    }

#endif

    return NULL;
}


#if (NGX_PCRE)

static ngx_int_t
ngx_stream_request_variable_not_found(ngx_stream_request_t *r,
    ngx_stream_request_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}


ngx_stream_request_regex_t *
ngx_stream_request_regex_compile(ngx_conf_t *cf, ngx_regex_compile_t *rc)
{
    u_char                       *p;
    size_t                        size;
    ngx_str_t                     name;
    ngx_uint_t                    i, n;
    ngx_stream_request_variable_t        *v;
    ngx_stream_request_regex_t           *re;
    ngx_stream_request_regex_variable_t  *rv;
    ngx_stream_request_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = ngx_pcalloc(cf->pool, sizeof(ngx_stream_request_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;
    re->name = rc->pattern;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_request_core_module);
    cmcf->ncaptures = ngx_max(cmcf->ncaptures, re->ncaptures);

    n = (ngx_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = ngx_palloc(rc->pool, n * sizeof(ngx_stream_request_regex_variable_t));
    if (rv == NULL) {
        return NULL;
    }

    re->variables = rv;
    re->nvariables = n;

    size = rc->name_size;
    p = rc->names;

    for (i = 0; i < n; i++) {
        rv[i].capture = 2 * ((p[0] << 8) + p[1]);

        name.data = &p[2];
        name.len = ngx_strlen(name.data);

        v = ngx_stream_request_add_variable(cf, &name, NGX_STREAM_REQUEST_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = ngx_stream_request_get_variable_index(cf, &name);
        if (rv[i].index == NGX_ERROR) {
            return NULL;
        }

        v->get_handler = ngx_stream_request_variable_not_found;

        p += size;
    }

    return re;
}


ngx_int_t
ngx_stream_request_regex_exec(ngx_stream_request_t *r, ngx_stream_request_regex_t *re,
    ngx_str_t *str)
{
    ngx_int_t                     rc, index;
    ngx_uint_t                    i, n, len;
    ngx_stream_request_variable_value_t  *vv;
    ngx_stream_request_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_get_module_main_conf(r->session, ngx_stream_request_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (r->captures == NULL) {
            r->captures = ngx_palloc(r->pool, len * sizeof(int));
            if (r->captures == NULL) {
                return NGX_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = ngx_regex_exec(re->regex, str, r->captures, len);

    if (rc == NGX_REGEX_NO_MATCHED) {
        return NGX_DECLINED;
    }

    if (rc < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->session->connection->log, 0,
                      ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, str, &re->name);
        return NGX_ERROR;
    }

    for (i = 0; i < re->nvariables; i++) {

        n = re->variables[i].capture;
        index = re->variables[i].index;
        vv = &r->variables[index];

        vv->len = r->captures[n + 1] - r->captures[n];
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = &str->data[r->captures[n]];

#if (NGX_DEBUG)
        {
        ngx_stream_request_variable_t  *v;

        v = cmcf->variables.elts;

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, r->session->connection->log, 0,
                       "stream regex set $%V to \"%v\"", &v[index].name, vv);
        }
#endif
    }

    r->ncaptures = rc * 2;
    r->captures_data = str->data;

    return NGX_OK;
}

#endif


ngx_int_t
ngx_stream_request_variables_add_core_vars(ngx_conf_t *cf)
{
    ngx_stream_request_variable_t        *cv, *v;
    ngx_stream_request_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_request_core_module);

    cmcf->variables_keys = ngx_pcalloc(cf->temp_pool,
                                       sizeof(ngx_hash_keys_arrays_t));
    if (cmcf->variables_keys == NULL) {
        return NGX_ERROR;
    }

    cmcf->variables_keys->pool = cf->pool;
    cmcf->variables_keys->temp_pool = cf->pool;

    if (ngx_hash_keys_array_init(cmcf->variables_keys, NGX_HASH_SMALL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->prefix_variables, cf->pool, 8,
                       sizeof(ngx_stream_variable_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (cv = ngx_stream_request_core_variables; cv->name.len; cv++) {
        v = ngx_stream_request_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;
    }

    return NGX_OK;
}


ngx_int_t
ngx_stream_request_variables_init_vars(ngx_conf_t *cf)
{
    size_t                        len;
    ngx_uint_t                    i, n;
    ngx_hash_key_t               *key;
    ngx_hash_init_t               hash;
    ngx_stream_request_variable_t        *v, *av, *pv;
    ngx_stream_request_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed stream variables */

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_request_core_module);

    v = cmcf->variables.elts;
    pv = cmcf->prefix_variables.elts;
    key = cmcf->variables_keys->keys.elts;

    for (i = 0; i < cmcf->variables.nelts; i++) {

        for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {

            av = key[n].value;

            if (v[i].name.len == key[n].key.len
                && ngx_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
                   == 0)
            {
                v[i].get_handler = av->get_handler;
                v[i].data = av->data;

                av->flags |= NGX_STREAM_REQUEST_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                if (av->get_handler == NULL
                    || (av->flags & NGX_STREAM_REQUEST_VAR_WEAK))
                {
                    break;
                }

                goto next;
            }
        }

        len = 0;
        av = NULL;

        for (n = 0; n < cmcf->prefix_variables.nelts; n++) {
            if (v[i].name.len >= pv[n].name.len && v[i].name.len > len
                && ngx_strncmp(v[i].name.data, pv[n].name.data, pv[n].name.len)
                   == 0)
            {
                av = &pv[n];
                len = pv[n].name.len;
            }
        }

        if (av) {
            v[i].get_handler = av->get_handler;
            v[i].data = (uintptr_t) &v[i].name;
            v[i].flags = av->flags;

            goto next;
         }

        if (v[i].get_handler == NULL) {
          /* ger var value from session */
          
          ngx_int_t index = (uintptr_t)ngx_stream_get_variable_index(cf, &v[i].name);
          if (index == NGX_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "get session index for \"%V\" variable", &v[i].name);
            return NGX_ERROR;
          }
          
          v[i].data = index;
          v[i].get_handler = ngx_stream_request_get_variable_from_session;
        }

    next:
        continue;
    }


    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;

        if (av->flags & NGX_STREAM_REQUEST_VAR_NOHASH) {
            key[n].key.data = NULL;
        }
    }


    hash.hash = &cmcf->variables_hash;
    hash.key = ngx_hash_key;
    hash.max_size = cmcf->variables_hash_max_size;
    hash.bucket_size = cmcf->variables_hash_bucket_size;
    hash.name = "variables_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, cmcf->variables_keys->keys.elts,
                      cmcf->variables_keys->keys.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cmcf->variables_keys = NULL;

    return NGX_OK;
}

static ngx_int_t ngx_stream_request_get_variable_from_session (ngx_stream_request_t *r,
    ngx_stream_request_variable_value_t *v, uintptr_t data) {
  ngx_int_t index;
  ngx_stream_request_variable_value_t* vv;
  
  index = (ngx_int_t)data;
  vv = ngx_stream_get_flushed_variable(r->session, index);
  if (vv == NULL) {
    return NGX_ERROR;
  }
  
  v->data = vv->data;
  v->len = vv->len;
  v->escape = vv->escape;
  v->no_cacheable = vv->escape;
  v->not_found = vv->not_found;
  v->valid = vv->valid;
  
  return NGX_OK;
}



