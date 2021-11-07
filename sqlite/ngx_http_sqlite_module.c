#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sqlite3.h>

typedef struct ngx_http_sqlite_ctx
{
    ngx_http_request_t *r;
    ngx_chain_t input;
    ngx_chain_t *output;
    ngx_chain_t *output_end; // last link in chain
} ngx_http_sqlite_ctx_t;

typedef struct ngx_http_sqlite_loc_conf
{
    ngx_str_t sqlite_query;
    sqlite3_stmt *statement;
} ngx_http_sqlite_loc_conf_t;

typedef struct ngx_http_sqlite_main_conf
{
    ngx_log_t *log;
    sqlite3 *db;
    ngx_str_t sqlite_database;
    struct sqlite_location_t
    {
        ngx_http_sqlite_loc_conf_t *loc;
        struct sqlite_location_t *prev;
    } *locations; // references in order to prepare on init_process
} ngx_http_sqlite_main_conf_t;

static void* ngx_http_sqlite_create_main_conf(ngx_conf_t *cf);

static char* ngx_http_sqlite_init_main_conf(ngx_conf_t *cf, void *main_conf_ptr);

static void* ngx_http_sqlite_create_loc_conf(ngx_conf_t *cf);

static char* ngx_http_sqlite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char* ngx_http_sqlite_post_sqlite_query(ngx_conf_t *cf, void *post, void *field);

static ngx_int_t ngx_http_sqlite_init_process(ngx_cycle_t *cycle);

static void ngx_http_sqlite_exit_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_sqlite_request_handler(ngx_http_request_t *r);

static void ngx_http_sqlite_request_data_handler(ngx_http_request_t *r);

static ngx_int_t execute_request(ngx_http_sqlite_ctx_t *sqlite_request);

static ngx_int_t send_response(ngx_http_sqlite_ctx_t *sqlite_request);


ngx_conf_post_t ngx_http_sqlite_query_post = { ngx_http_sqlite_post_sqlite_query };

static ngx_command_t
ngx_http_sqlite_commands[] =
{
    {   // directive to set sqlite_query for location configuration
        ngx_string("sqlite_query"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_sqlite_loc_conf_t, sqlite_query),
        &ngx_http_sqlite_query_post // post handler
    },
    {   // directive to set sqlite_query for location configuration
        ngx_string("sqlite_database"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_sqlite_main_conf_t, sqlite_database),
        NULL // post handler
    },
    ngx_null_command
};

static ngx_http_module_t
ngx_http_sqlite_module_ctx =
{
    NULL, // preconfiguration
    NULL, // postconfiguration
    ngx_http_sqlite_create_main_conf, // create main configuration
    ngx_http_sqlite_init_main_conf, // init main configuration
    NULL, // create server configuration
    NULL, // merge server configuration
    ngx_http_sqlite_create_loc_conf, // allocates and initializes location-scope struct
    ngx_http_sqlite_merge_loc_conf   // sets location-scope struct values from outer scope if left unset in location scope
};

ngx_module_t
ngx_http_sqlite_module =
{
    NGX_MODULE_V1,
    &ngx_http_sqlite_module_ctx,  // module callbacks
    ngx_http_sqlite_commands,     // module configuration callbacks
    NGX_HTTP_MODULE,           // module type is HTTP
    NULL,        // init_master
    NULL,        // init_module
    ngx_http_sqlite_init_process, // init_process
    NULL,        // init_thread
    NULL,        // exit_thread
    ngx_http_sqlite_exit_process, // exit_process
    NULL,        // exit_master
    NGX_MODULE_V1_PADDING
};



static void*
ngx_http_sqlite_create_main_conf(ngx_conf_t *cf)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "sqlite: [PID=%d] %s", ngx_pid, __FUNCTION__);
    ngx_http_sqlite_main_conf_t *main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sqlite_main_conf_t));
    // if (main_conf != NULL)
    // {
    // }
    return main_conf;
}
static char*
ngx_http_sqlite_init_main_conf(ngx_conf_t *cf, void *main_conf_ptr)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,"sqlite: [PID=%d] %s", ngx_pid, __FUNCTION__);
    // ngx_http_sqlite_main_conf_t *main_conf = main_conf_ptr;
    // if (main_conf->config == NGX_CONF_UNSET_PTR)
    // {
    // }
    return NGX_CONF_OK;
}

static void*
ngx_http_sqlite_create_loc_conf(ngx_conf_t *cf)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "sqlite: [PID=%d] %s", ngx_pid, __FUNCTION__);
    ngx_http_sqlite_loc_conf_t *loc_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sqlite_loc_conf_t));
    if (loc_conf != NULL)
    {
    }
    return loc_conf;
}

static char*
ngx_http_sqlite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "sqlite: [PID=%d] %s", ngx_pid, __FUNCTION__);
    ngx_http_sqlite_loc_conf_t *prev = parent;
    ngx_http_sqlite_loc_conf_t *loc_conf = child;
    ngx_conf_merge_str_value(loc_conf->sqlite_query, prev->sqlite_query, /*default*/ "");
    return NGX_CONF_OK;
}

static char*
ngx_http_sqlite_post_sqlite_query(ngx_conf_t *cf, void *post, void *field)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "sqlite: [PID=%d] %s", ngx_pid, __FUNCTION__);


    // setting "sqlite_query" also enables HTTP handler for location
    ngx_http_core_loc_conf_t *http_core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    http_core_loc_conf->handler = ngx_http_sqlite_request_handler; // sets HTTP request handler

    // push_front locations because they are prepared in init_process
    ngx_http_sqlite_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sqlite_module);
    char *p = field;
    ngx_http_sqlite_loc_conf_t *loc_conf = (ngx_http_sqlite_loc_conf_t*)(p - offsetof(ngx_http_sqlite_loc_conf_t, sqlite_query));

    // linked-list: 1 <- 2 <- 3
    struct sqlite_location_t *l = ngx_palloc(cf->pool, sizeof(struct sqlite_location_t));
    l->loc = loc_conf;
    l->prev = main_conf->locations;
    main_conf->locations = l;

    return NGX_CONF_OK;
}

static int
callback(void *arg, int column_count, char **column_texts, char **column_names)
{
    ngx_cycle_t *cycle = arg;

    for (int i = 0; i < column_count; i += 1)
    {
        ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "sqlite: [PID=%d] | %s = %s", ngx_pid, column_names[i], column_texts[i]);
    }
    return 0; // if non-zero, sqlite3_exec() returns SQLITE_ABORT.
}

static ngx_int_t
ngx_http_sqlite_init_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "sqlite: [PID=%d] %s pid=%d", ngx_pid, __FUNCTION__, ngx_pid);

    ngx_http_sqlite_main_conf_t *main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_sqlite_module);

    if (!main_conf)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "sqlite: [PID=%d] !main_conf", ngx_pid);
        return NGX_ERROR;
    }

    main_conf->log = cycle->log;


    // Open sqlite3 databse
    //  If database is an empty string a temporary (automatically deleted) file is created.
    //  If database is ":memory:" an in-memory database is used.
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "sqlite: [PID=%d] database = %V", ngx_pid, &main_conf->sqlite_database);
    // copy database to zero-terminated string
    char *database = ngx_palloc(cycle->pool, main_conf->sqlite_database.len + 1);
    ngx_memcpy(database, main_conf->sqlite_database.data, main_conf->sqlite_database.len);
    database[main_conf->sqlite_database.len] = '\0';
    
    int rc = sqlite3_open_v2(database, &main_conf->db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "sqlite: [PID=%d] %s", ngx_pid, sqlite3_errmsg(main_conf->db));
        sqlite3_close_v2(main_conf->db); // even on error resources are released by close
        return NGX_ERROR; // does not invoke exit_process
    }

    // log path to database file
    char *err_msg = NULL;
    rc = sqlite3_exec(main_conf->db, "PRAGMA database_list", callback, /*callback arg*/cycle, &err_msg);
    sqlite3_free(err_msg);
    if (rc != SQLITE_OK)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "sqlite: [PID=%d] %s", ngx_pid, sqlite3_errmsg(main_conf->db));
        sqlite3_close_v2(main_conf->db); // even on error resources can be released by sqlite3_close_v2()
        return NGX_ERROR;
    }

    struct sqlite_location_t *location = main_conf->locations;
    while (location)
    {
        ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "sqlite: [PID=%d] preparing statement", ngx_pid);
        ngx_http_sqlite_loc_conf_t *loc_conf = location->loc;
        int rc = sqlite3_prepare_v3(main_conf->db, (const char*)loc_conf->sqlite_query.data, loc_conf->sqlite_query.len, 0, &loc_conf->statement, NULL);
        if (rc != SQLITE_OK)
        {
            sqlite3_finalize(loc_conf->statement);
            loc_conf->statement = NULL;
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "sqlite: [PID=%d] %s", ngx_pid, sqlite3_errmsg(main_conf->db));
            return NGX_ERROR;
        }
        location = location->prev;
    }

    return NGX_OK;
}

static void
ngx_http_sqlite_exit_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "sqlite: [PID=%d] %s", ngx_pid, __FUNCTION__);
    ngx_http_sqlite_main_conf_t *main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_sqlite_module);
    struct sqlite_location_t *location = main_conf->locations;
    while (location)
    {
        sqlite3_finalize(location->loc->statement);
        location = location->prev;
    }
    sqlite3_close_v2(main_conf->db);
}


static ngx_int_t
ngx_http_sqlite_request_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sqlite: [PID=%d] %s pid=%d", ngx_pid, __FUNCTION__, ngx_pid);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_POST)))
    {
        return NGX_HTTP_NOT_ALLOWED;
    }
    ngx_http_sqlite_ctx_t *sqlite_request = ngx_pcalloc(r->pool, sizeof(ngx_http_sqlite_ctx_t)); // NOTE: zero-initialized
    if (sqlite_request == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_set_ctx(r, sqlite_request, ngx_http_sqlite_module); // makes context retrievable from r with ngx_http_get_module_ctx(r, ngx_http_sqlite_module)
    sqlite_request->r = r;

    if ((r->method & NGX_HTTP_GET) && ngx_http_discard_request_body(r) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_int_t ret = ngx_http_read_client_request_body(r, ngx_http_sqlite_request_data_handler); // delegates to body handler callback
    if (ret >= NGX_HTTP_SPECIAL_RESPONSE)
    {
        return ret;
    }
    return NGX_DONE; // doesn't destroy request until ngx_http_finalize_request is called
}


static void
ngx_http_sqlite_request_data_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sqlite: [PID=%d] %s", ngx_pid, __FUNCTION__);

    ngx_http_sqlite_ctx_t *sqlite_request = ngx_http_get_module_ctx(r, ngx_http_sqlite_module);

    off_t buffer_size = 0;
    for (ngx_chain_t *cl = r->request_body->bufs; cl; cl = cl->next)
    {
        buffer_size += ngx_buf_size(cl->buf);
    }

    if (buffer_size)
    {
        // copy incoming buffer into contiguous input buffer
        if (sqlite_request->input.buf == NULL)
        {
            sqlite_request->input.buf = ngx_create_temp_buf(r->pool, buffer_size);
        }
        else
        {
            off_t capacity = sqlite_request->input.buf->end - sqlite_request->input.buf->start;
            off_t used = sqlite_request->input.buf->last - sqlite_request->input.buf->pos;
            if (buffer_size > capacity - used)
            {
                ngx_buf_t *buf = ngx_create_temp_buf(r->pool, buffer_size + capacity);
                buf->last = ngx_cpymem(buf->pos, sqlite_request->input.buf->pos, used);
                sqlite_request->input.buf = buf;
            }
        }

        for (ngx_chain_t *cl = r->request_body->bufs; cl; cl = cl->next)
        {
            // ngx_str_t str = {ngx_buf_size(cl->buf), cl->buf->pos};
            // ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] buffer = '[%V]'", ngx_pid, &str);

            ngx_buf_t *buf = sqlite_request->input.buf;

            if (cl->buf->in_file || cl->buf->temp_file) // if buffered in file, then read entire file into a buffer
            {
                ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] buffer in file", ngx_pid);
                ssize_t bytes_read = ngx_read_file(cl->buf->file, buf->pos, buffer_size, cl->buf->file_pos);
                if (bytes_read != (ssize_t)buffer_size)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sqlite: [PID=%d] error reading tempfile; ret=%zu", ngx_pid, bytes_read);
                    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
                buf->last = buf->pos + bytes_read;
            }
            else
            {
                buf->last = ngx_cpymem(buf->pos, cl->buf->pos, ngx_buf_size(cl->buf));
            }
            buf->last_buf = cl->buf->last_buf;
        }
    }

    // begin request handling when all input has been received
    if (!sqlite_request->input.buf || (sqlite_request->input.buf->last_buf))
    {
        ngx_int_t ret = execute_request(sqlite_request);
        if (ret != NGX_OK)
        {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        else
        {
            ngx_http_finalize_request(r, send_response(sqlite_request));
        }
        // to instead finalize later, something needs to trigger a callback
    }
    else
    {   // chunked input?
        ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] chunk", ngx_pid);
    }
}


static ngx_int_t
execute_request(ngx_http_sqlite_ctx_t *sqlite_request)
{
    ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] %s", ngx_pid, __FUNCTION__);

    ngx_http_sqlite_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(sqlite_request->r, ngx_http_sqlite_module);
    ngx_http_sqlite_main_conf_t *main_conf = ngx_http_get_module_main_conf(sqlite_request->r, ngx_http_sqlite_module);

    sqlite3_stmt *statement = loc_conf->statement;

    // there may not be any output, but prepare anyway
    off_t buffer_capacity = 4096; // each
    ngx_buf_t *buf = ngx_create_temp_buf(sqlite_request->r->pool, buffer_capacity);
    buf->memory = 1;
    ngx_chain_t *chain = ngx_alloc_chain_link(sqlite_request->r->pool);
    chain->buf = buf;
    chain->next = NULL;
    sqlite_request->output = sqlite_request->output_end = chain;

    int parameter_count = sqlite3_bind_parameter_count(statement);
    int column_count = sqlite3_column_count(statement); // 0 for UPDATE, 1 or more for SELECT
    ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] parameter count = %d, column count = %d", ngx_pid, parameter_count, column_count);
    const char *param = sqlite_request->input.buf ? (const char*)sqlite_request->input.buf->pos : NULL;
    int run_again = 0; // each input row's fields is bound per execution.
    do
    {
        // bind input parameters to statement
        if (parameter_count != 0 && sqlite_request->input.buf != NULL)
        {
            const char *end = (const char*)sqlite_request->input.buf->last;
            const char *it = param;
            int index = 1; // the leftmost SQL parameter has an index of 1.
            while (it != end && *it != '\n')
            {
                if (*it == ',')
                {
                    int len = it - param;
                    ngx_str_t str={len, (unsigned char*)param};
                    ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] binding parameter '%V'", ngx_pid, &str);
                    int rc = sqlite3_bind_text(statement, index, len != 0 ? param : NULL, len, /*no text destruction*/SQLITE_STATIC);
                    if (rc != SQLITE_OK)
                    {
                        sqlite3_reset(statement);
                        ngx_log_error(NGX_LOG_ERR, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] %s", ngx_pid, sqlite3_errmsg(main_conf->db));
                        return NGX_ERROR;
                    }
                    index += 1;
                    param = it+1;
                }
                it += 1;
            }
            // now at row's final field (no comma at end and may not have newline when at end of buffer)
            int len = it - param;
            ngx_str_t str={len, (unsigned char*)param};
            ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] binding parameter '%V'", ngx_pid, &str);
            int rc = sqlite3_bind_text(statement, index, len != 0 ? param : NULL, len, /*no text destruction*/SQLITE_STATIC);
            if (rc != SQLITE_OK)
            {
                sqlite3_reset(statement);
                ngx_log_error(NGX_LOG_ERR, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] %s", ngx_pid, sqlite3_errmsg(main_conf->db));
                return NGX_ERROR;
            }
            if (*it == '\n')
            {
                it += 1;
            }
            param = it; // advance to next row
            run_again = it != end; // run again if input has more rows to bind
        }

        ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] run_again = %d", ngx_pid, run_again);

        int rc;
        while ((rc = sqlite3_step(statement)) == SQLITE_ROW)
        {
            ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] sqlite3_step == SQLITE_ROW", ngx_pid);
            // the leftmost column of the result set has the index 0.
            for (int index = 0; index < column_count; index += 1)
            {
                // pointer is valid until sqlite3_step() or sqlite3_reset() or sqlite3_finalize() is called.
                const unsigned char *field_value = sqlite3_column_text(statement, index);
                // sqlite3_column_type(statement, i) != SQLITE_NULL
                // char *column_name = (char *)sqlite3_column_name(statement, i);
                if (field_value == NULL)
                {   // if NULL, check if value is NULL or if there was an error
                    if (sqlite3_errcode(main_conf->db) != SQLITE_OK)
                    {
                        sqlite3_reset(statement);
                        ngx_log_error(NGX_LOG_ERR, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] %s", ngx_pid, sqlite3_errmsg(main_conf->db));
                        return NGX_ERROR;
                    }
                    field_value = (const unsigned char*)"NULL"; // NULL value
                }
                ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] field_value = '%s'", ngx_pid, field_value);
                int len = sqlite3_column_bytes(statement, index);
                len += 1; // +1 byte for separator (, or \n)
                if (buf->last + len >= buf->end)
                {   // create and chain another buffer if previous can't fit the data
                    if (len > buffer_capacity)
                    {
                        buffer_capacity = len;
                    }
                    buf = ngx_create_temp_buf(sqlite_request->r->pool, buffer_capacity);
                    buf->memory = 1;
                    if (sqlite_request->output_end->buf->last == sqlite_request->output_end->buf->pos)
                    {   // if previous buffer is empty, overwrite it with the new one.
                        sqlite_request->output_end->buf = buf;
                    }
                    else // append new buffer in chain
                    {
                        chain = ngx_alloc_chain_link(sqlite_request->r->pool);
                        chain->buf = buf;
                        chain->next = NULL;
                        sqlite_request->output_end->next = chain;
                        sqlite_request->output_end = chain;
                    }
                }
                buf->last = ngx_cpymem(buf->last, field_value, len-1);
                *buf->last++ = index == column_count-1 ? '\n' : ','; // comma between values, newline between records
            }
        }
        if (rc != SQLITE_DONE)
        {
            sqlite3_reset(statement);
            ngx_log_error(NGX_LOG_ERR, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] %s", ngx_pid, sqlite3_errmsg(main_conf->db));
            return NGX_ERROR;
        }
        ngx_log_error(NGX_LOG_INFO, sqlite_request->r->connection->log, 0, "sqlite: [PID=%d] %s", ngx_pid, sqlite3_errmsg(main_conf->db));
        sqlite3_reset(statement); // reset statement before running with new bound parameters
    } while (run_again);

    sqlite_request->r->headers_out.status = NGX_HTTP_OK;
    return NGX_OK;
}

static ngx_int_t
send_response(ngx_http_sqlite_ctx_t *sqlite_request)
{
    ngx_http_request_t *r = sqlite_request->r;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sqlite: [PID=%d] %s", ngx_pid, __FUNCTION__);

    if (sqlite_request->output)
    {
        ngx_str_t str = {ngx_buf_size(sqlite_request->output->buf), sqlite_request->output->buf->pos};
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sqlite: [PID=%d] output buffer[0] = '%V'", ngx_pid, &str);
    }
    else
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sqlite: [PID=%d] no output", ngx_pid);
    }

    off_t content_length = 0;
    for (ngx_chain_t *cl = sqlite_request->output; cl; cl = cl->next)
    {
        content_length += ngx_buf_size(cl->buf);
        if (cl->next == NULL)
        {
            cl->buf->last_in_chain = 1;
            cl->buf->last_buf = 1;
        }
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sqlite: [PID=%d] content_length=%O", ngx_pid, content_length);

    if (r->headers_out.status == 0)
    {
        r->headers_out.status = NGX_HTTP_OK;
    }
    r->headers_out.content_length_n = content_length;
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (content_length == 0)
    {
        r->header_only = 1;
    }

    if (ngx_http_send_header(r) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sqlite: [PID=%d] ngx_http_send_header(r) != NGX_OK", ngx_pid);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (content_length != 0)
    {
        if (ngx_http_output_filter(r, sqlite_request->output) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sqlite: [PID=%d] ngx_http_output_filter() != NGX_OK", ngx_pid);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return r->headers_out.status;
}

