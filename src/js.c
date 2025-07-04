#include <assert.h>
#include <intrusive.h>
#include <intrusive/list.h>
#include <jerryscript-core.h>
#include <jerryscript-port.h>
#include <jerryscript-types.h>
#include <jerryscript.h>
#include <js.h>
#include <limits.h>
#include <math.h>
#include <path.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utf.h>
#include <uv.h>
#include <wchar.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#ifndef thread_local
#ifdef _WIN32
#define thread_local __declspec(thread)
#else
#define thread_local _Thread_local
#endif
#endif

#define JS_STRING_LITERAL(x) #x
#define JS_STRING(x)         JS_STRING_LITERAL(x)

typedef struct js_callback_s js_callback_t;
typedef struct js_finalizer_s js_finalizer_t;
typedef struct js_finalizer_list_s js_finalizer_list_t;
typedef struct js_delegate_s js_delegate_t;
typedef struct js_arraybuffer_header_s js_arraybuffer_header_t;
typedef struct js_arraybuffer_attachment_s js_arraybuffer_attachment_t;
typedef struct js_promise_rejection_s js_promise_rejection_t;
typedef struct js_teardown_task_s js_teardown_task_t;
typedef struct js_teardown_queue_s js_teardown_queue_t;

struct js_deferred_teardown_s {
  js_env_t *env;
};

struct js_teardown_task_s {
  enum {
    js_immediate_teardown,
    js_deferred_teardown,
  } type;

  union {
    struct {
      js_teardown_cb cb;
    } immediate;

    struct {
      js_deferred_teardown_t handle;
      js_deferred_teardown_cb cb;
    } deferred;
  };

  void *data;
  intrusive_list_node_t list;
};

struct js_teardown_queue_s {
  intrusive_list_t tasks;
};

struct js_platform_s {
  uv_loop_t *loop;
};

struct js_env_s {
  uv_loop_t *loop;
  uv_prepare_t prepare;
  uv_check_t check;
  uv_async_t teardown;
  int active_handles;

  js_platform_t *platform;
  js_handle_scope_t *scope;
  js_context_t *context;

  uint32_t refs;
  uint32_t depth;

  jerry_value_t bindings;
  jerry_value_t exception;

  int64_t external_memory;

  bool destroying;

  js_promise_rejection_t *promise_rejections;

  js_teardown_queue_t teardown_queue;

  struct {
    js_uncaught_exception_cb uncaught_exception;
    void *uncaught_exception_data;

    js_unhandled_rejection_cb unhandled_rejection;
    void *unhandled_rejection_data;

    js_dynamic_import_cb dynamic_import;
    void *dynamic_import_data;
  } callbacks;
};

struct js_context_s {
  jerry_value_t realm;

  js_context_t *previous;
};

struct js_value_s;

struct js_handle_scope_s {
  js_handle_scope_t *parent;
  jerry_value_t *values;
  size_t len;
  size_t capacity;
};

struct js_escapable_handle_scope_s {
  js_handle_scope_t *parent;
};

struct js_module_s {
  js_env_t *env;
  char *name;
  jerry_value_t handle;
  js_module_meta_cb meta;
  void *meta_data;
  js_module_resolve_cb resolve;
  void *resolve_data;
  js_module_evaluate_cb evaluate;
  void *evaluate_data;
};

struct js_ref_s {
  jerry_value_t value;
  uint32_t count;
  jerry_value_t symbol;
  bool finalized;
};

struct js_deferred_s {
  jerry_value_t promise;
};

struct js_string_view_s {
  jerry_size_t len;
  jerry_char_t value[];
};

struct js_finalizer_s {
  js_env_t *env;
  void *data;
  js_finalize_cb cb;
  void *hint;
};

struct js_finalizer_list_s {
  js_finalizer_t finalizer;
  js_finalizer_list_t *next;
};

struct js_delegate_s {
  js_env_t *env;
  js_delegate_callbacks_t callbacks;
  void *data;
  js_finalize_cb finalize_cb;
  void *finalize_hint;
};

struct js_callback_s {
  js_env_t *env;
  js_function_cb cb;
  void *data;
};

struct js_callback_info_s {
  js_callback_t *callback;
  const jerry_call_info_t *info;
  const jerry_value_t *argv;
  jerry_length_t argc;
};

struct js_threadsafe_function_s {
};

struct js_arraybuffer_header_s {
  atomic_int references;
  jerry_length_t len;
  uint8_t data[];
};

struct js_arraybuffer_backing_store_s {
  jerry_value_t owner;
  atomic_int references;
  jerry_length_t len;
  uint8_t *data;
};

struct js_arraybuffer_attachment_s {
  enum {
    js_arraybuffer_finalizer = 1,
    js_arraybuffer_backing_store = 2,
  } type;

  union {
    js_finalizer_t finalizer;
    js_arraybuffer_backing_store_t *backing_store;
  };
};

struct js_promise_rejection_s {
  jerry_value_t promise;
  jerry_value_t reason;
  js_promise_rejection_t *next;
};

static thread_local uint64_t jerry_context_heap_size;

static thread_local jerry_context_t *jerry_context = NULL;

size_t
jerry_port_context_alloc(size_t context_size) {
  if (jerry_context_heap_size > UINT32_MAX) jerry_context_heap_size = UINT32_MAX;

  jerry_context_heap_size += context_size;

#ifdef _WIN32
  jerry_context = VirtualAlloc(NULL, jerry_context_heap_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
  jerry_context = mmap(NULL, jerry_context_heap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (jerry_context == MAP_FAILED) jerry_context = NULL;
#endif

  assert(jerry_context);

  return jerry_context_heap_size;
}

jerry_context_t *
jerry_port_context_get(void) {
  return jerry_context;
}

void
jerry_port_context_free(void) {
#ifdef _WIN32
  VirtualFree(jerry_context, jerry_context_heap_size, MEM_RELEASE);
#else
  munmap(jerry_context, jerry_context_heap_size);
#endif
}

void
jerry_port_init(void) {}

void
jerry_port_fatal(jerry_fatal_code_t code) {
  abort();
}

void
jerry_port_log(const char *message) {
  fputs(message, stderr);
}

int32_t
jerry_port_local_tza(double ms) {
  return ms;
}

double
jerry_port_current_time(void) {
  int err;

  uv_timeval64_t tv;
  err = uv_gettimeofday(&tv);
  assert(err == 0);

  return ((double) tv.tv_sec) * 1000.0 + ((double) tv.tv_usec) / 1000.0;
}

jerry_char_t *
jerry_port_path_normalize(const jerry_char_t *path, jerry_size_t len) {
  int err;

  (void) len;

  uv_fs_t req;
  err = uv_fs_realpath(NULL, &req, (const char *) path, NULL);
  assert(err == 0);

  jerry_char_t *result = (jerry_char_t *) strdup(req.ptr);

  uv_fs_req_cleanup(&req);

  return result;
}

void
jerry_port_path_free(jerry_char_t *path) {
  free(path);
}

jerry_size_t
jerry_port_path_base(const jerry_char_t *path) {
  int err;

  size_t dirname;
  err = path_dirname((const char *) path, &dirname, path_behavior_system);
  assert(err == 0);

  return dirname + 1;
}

jerry_char_t *
jerry_port_source_read(const char *path, jerry_size_t *len) {
  return NULL;
}

void
jerry_port_source_free(uint8_t *buffer) {
  free(buffer);
}

static inline jerry_value_t
js__value_from_abi(const js_value_t *value) {
  return (jerry_value_t) (uintptr_t) value;
}

static inline js_value_t *
js__value_to_abi(jerry_value_t value) {
  return (js_value_t *) (uintptr_t) value;
}

static const char *js__platform_identifier = "jerryscript";

static const char *js__platform_version = JS_STRING(JERRY_API_MAJOR_VERSION) "." JS_STRING(JERRY_API_MINOR_VERSION) "." JS_STRING(JERRY_API_PATCH_VERSION);

int
js_create_platform(uv_loop_t *loop, const js_platform_options_t *options, js_platform_t **result) {
  js_platform_t *platform = malloc(sizeof(js_platform_t));

  platform->loop = loop;

  *result = platform;

  return 0;
}

int
js_destroy_platform(js_platform_t *platform) {
  free(platform);

  return 0;
}

int
js_get_platform_identifier(js_platform_t *platform, const char **result) {
  *result = js__platform_identifier;

  return 0;
}

int
js_get_platform_version(js_platform_t *platform, const char **result) {
  *result = js__platform_version;

  return 0;
}

int
js_get_platform_limits(js_platform_t *platform, js_platform_limits_t *result) {
  result->arraybuffer_length = UINT32_MAX;
  result->string_length = INT32_MAX;

  return 0;
}

int
js_get_platform_loop(js_platform_t *platform, uv_loop_t **result) {
  *result = platform->loop;

  return 0;
}

static inline void
js__uncaught_exception(js_env_t *env, jerry_value_t exception) {
  assert(env->exception == 0);

  int err;

  jerry_value_t value = jerry_exception_value(exception, true);

  if (env->callbacks.uncaught_exception) {
    js_handle_scope_t *scope;
    err = js_open_handle_scope(env, &scope);
    assert(err == 0);

    env->callbacks.uncaught_exception(
      env,
      js__value_to_abi(value),
      env->callbacks.uncaught_exception_data
    );

    err = js_close_handle_scope(env, scope);
    assert(err == 0);

    jerry_value_free(value);
  } else {
    env->exception = jerry_throw_value(value, true);
  }
}

static inline void
js__unhandled_rejection(js_env_t *env, jerry_value_t promise, jerry_value_t reason) {
  assert(env->exception == 0);

  int err;

  if (env->callbacks.unhandled_rejection) {
    js_handle_scope_t *scope;
    err = js_open_handle_scope(env, &scope);
    assert(err == 0);

    env->callbacks.unhandled_rejection(
      env,
      js__value_to_abi(reason),
      js__value_to_abi(promise),
      env->callbacks.uncaught_exception_data
    );

    err = js_close_handle_scope(env, scope);
    assert(err == 0);
  }

  jerry_value_free(promise);
  jerry_value_free(reason);
}

static inline void
js__run_microtasks(js_env_t *env) {
  int err;

  jerry_value_t value;

  for (;;) {
    js_handle_scope_t *scope;
    err = js_open_handle_scope(env, &scope);
    assert(err == 0);

    value = jerry_run_jobs();

    err = js_close_handle_scope(env, scope);
    assert(err == 0);

    if (jerry_value_is_exception(value)) {
      js__uncaught_exception(env, value);
    } else {
      break;
    }
  }

  jerry_value_free(value);

  js_promise_rejection_t *next = env->promise_rejections;
  js_promise_rejection_t *prev;

  env->promise_rejections = NULL;

  while (next) {
    js__unhandled_rejection(env, next->promise, next->reason);

    prev = next;
    next = next->next;

    free(prev);

    js__run_microtasks(env);
  }
}

static inline int
js__error(js_env_t *env) {
  return env->exception ? js_pending_exception : js_uncaught_exception;
}

static inline js_arraybuffer_header_t *
js__arraybuffer_header(void *buffer) {
  return (js_arraybuffer_header_t *) ((char *) buffer - sizeof(js_arraybuffer_header_t));
}

static uint8_t *
js__on_arraybuffer_allocate(jerry_arraybuffer_type_t type, uint32_t len, void **data, void *opaque) {
  uint8_t *buffer;

  if (type == JERRY_ARRAYBUFFER_TYPE_SHARED_ARRAYBUFFER) {
    js_arraybuffer_header_t *header = malloc(sizeof(js_arraybuffer_header_t) + len);

    header->references = 1;
    header->len = len;

    buffer = header->data;
  } else {
    buffer = malloc(len);
  }

  return buffer;
}

static void
js__on_arraybuffer_free(jerry_arraybuffer_type_t type, uint8_t *buffer, uint32_t len, void *data, void *opaque) {
  if (type == JERRY_ARRAYBUFFER_TYPE_SHARED_ARRAYBUFFER) {
    js_arraybuffer_header_t *header = js__arraybuffer_header(buffer);

    if (--header->references == 0) {
      free(header);
    }
  } else {
    js_env_t *env = opaque;

    js_arraybuffer_attachment_t *attachment = data;

    if (attachment == NULL) {
      free(buffer);

      return;
    }

    switch (attachment->type) {
    case js_arraybuffer_finalizer: {
      js_finalizer_t *finalizer = &attachment->finalizer;

      if (finalizer->cb) finalizer->cb(finalizer->env, finalizer->data, finalizer->hint);

      break;
    }

    case js_arraybuffer_backing_store: {
      js_arraybuffer_backing_store_t *backing_store = attachment->backing_store;

      if (--backing_store->references == 0) {
        jerry_value_free(backing_store->owner);

        if (env->destroying) jerry_heap_gc(JERRY_GC_PRESSURE_LOW);

        free(backing_store);
      }

      break;
    }
    }

    free(attachment);
  }
}

static void
js__on_promise_event(jerry_promise_event_type_t event_type, const jerry_value_t promise, const jerry_value_t reason, void *opaque) {
  int err;

  js_env_t *env = opaque;

  if (env->callbacks.unhandled_rejection == NULL) return;

  if (event_type == JERRY_PROMISE_EVENT_REJECT_WITHOUT_HANDLER) {
    js_promise_rejection_t *node = malloc(sizeof(js_promise_rejection_t));

    node->promise = jerry_value_copy(promise);
    node->reason = jerry_value_copy(reason);

    node->next = env->promise_rejections;

    env->promise_rejections = node;
  } else if (event_type == JERRY_PROMISE_EVENT_CATCH_HANDLER_ADDED) {
    js_promise_rejection_t *next = env->promise_rejections;
    js_promise_rejection_t *prev = NULL;

    while (next) {
      if (next->promise == promise) {
        jerry_value_free(next->promise);
        jerry_value_free(next->reason);

        if (prev) prev->next = next->next;
        else env->promise_rejections = next->next;

        return free(next);
      }

      prev = next;
      next = next->next;
    }
  }
}

static void
js__on_module_import_meta(const jerry_value_t handle, const jerry_value_t meta, void *opaque);

static jerry_value_t
js__on_module_import(const jerry_value_t specifier, const jerry_value_t user_value, void *opaque);

static inline void
js__check_liveness(js_env_t *env);

static void
js__on_prepare(uv_prepare_t *handle) {
  js_env_t *env = (js_env_t *) handle->data;

  js__check_liveness(env);
}

static void
js__on_check(uv_check_t *handle) {
  js_env_t *env = (js_env_t *) handle->data;

  if (uv_loop_alive(env->loop)) return;

  js__check_liveness(env);
}

static inline void
js__check_liveness(js_env_t *env) {
  int err;

  if (true /* macrotask queue empty */) {
    err = uv_prepare_stop(&env->prepare);
  } else {
    err = uv_prepare_start(&env->prepare, js__on_prepare);
  }

  assert(err == 0);
}

static void
js__on_handle_close(uv_handle_t *handle) {
  js_env_t *env = (js_env_t *) handle->data;

  if (--env->active_handles == 0) {
    free(env->context);
    free(env);
  }
}

static void
js__close_env(js_env_t *env) {
  jerry_value_free(env->context->realm);
  jerry_value_free(env->bindings);
  jerry_value_free(env->exception);

  jerry_cleanup();

  uv_close((uv_handle_t *) &env->prepare, js__on_handle_close);
  uv_close((uv_handle_t *) &env->check, js__on_handle_close);
  uv_close((uv_handle_t *) &env->teardown, js__on_handle_close);
}

static void
js__on_teardown(uv_async_t *handle) {
  js_env_t *env = (js_env_t *) handle->data;

  if (env->refs == 0) js__close_env(env);
}

int
js_create_env(uv_loop_t *loop, js_platform_t *platform, const js_env_options_t *options, js_env_t **result) {
  int err;

  if (options && options->memory_limit) {
    jerry_context_heap_size = options->memory_limit;
  } else {
    uint64_t constrained_memory = uv_get_constrained_memory();
    uint64_t total_memory = uv_get_total_memory();

    if (constrained_memory > 0 && constrained_memory < total_memory) {
      total_memory = constrained_memory;
    }

    if (total_memory > 0) {
      jerry_context_heap_size = total_memory;
    } else {
      jerry_context_heap_size = 8 * 1024 * 1024;
    }
  }

  js_env_t *env = malloc(sizeof(js_env_t));

  jerry_init(JERRY_INIT_EMPTY);

  jerry_arraybuffer_allocator(js__on_arraybuffer_allocate, js__on_arraybuffer_free, env);

  jerry_arraybuffer_heap_allocation_limit(64);

  jerry_promise_on_event(JERRY_PROMISE_EVENT_FILTER_ERROR, js__on_promise_event, env);

  jerry_module_on_import_meta(js__on_module_import_meta, env);

  jerry_module_on_import(js__on_module_import, env);

  env->loop = loop;
  env->active_handles = 3;

  env->platform = platform;
  env->scope = NULL;

  env->context = malloc(sizeof(js_context_t));
  env->context->realm = jerry_current_realm();
  env->context->previous = NULL;

  env->refs = 0;
  env->depth = 0;

  env->bindings = jerry_object();
  env->exception = 0;

  env->external_memory = 0;

  env->destroying = false;

  env->promise_rejections = NULL;

  intrusive_list_init(&env->teardown_queue.tasks);

  env->callbacks.uncaught_exception = NULL;
  env->callbacks.uncaught_exception_data = NULL;

  env->callbacks.unhandled_rejection = NULL;
  env->callbacks.unhandled_rejection_data = NULL;

  env->callbacks.dynamic_import = NULL;
  env->callbacks.dynamic_import_data = NULL;

  err = uv_prepare_init(loop, &env->prepare);
  assert(err == 0);

  err = uv_prepare_start(&env->prepare, js__on_prepare);
  assert(err == 0);

  env->prepare.data = (void *) env;

  err = uv_check_init(loop, &env->check);
  assert(err == 0);

  err = uv_check_start(&env->check, js__on_check);
  assert(err == 0);

  env->check.data = (void *) env;

  // The check handle should not on its own keep the loop alive; it's simply
  // used for running any outstanding tasks that might cause additional work
  // to be queued.
  uv_unref((uv_handle_t *) &env->check);

  err = uv_async_init(loop, &env->teardown, js__on_teardown);
  assert(err == 0);

  env->teardown.data = (void *) env;

  uv_unref((uv_handle_t *) &env->teardown);

  *result = env;

  return 0;
}

int
js_destroy_env(js_env_t *env) {
  env->destroying = true;

  intrusive_list_for_each(next, &env->teardown_queue.tasks) {
    js_teardown_task_t *task = intrusive_entry(next, js_teardown_task_t, list);

    if (task->type == js_deferred_teardown) {
      task->deferred.cb(&task->deferred.handle, task->data);
    } else {
      task->immediate.cb(task->data);

      intrusive_list_remove(&env->teardown_queue.tasks, &task->list);

      free(task);
    }
  }

  if (env->refs == 0) {
    js__close_env(env);
  } else {
    uv_ref((uv_handle_t *) &env->teardown);
  }

  return 0;
}

int
js_on_uncaught_exception(js_env_t *env, js_uncaught_exception_cb cb, void *data) {
  env->callbacks.uncaught_exception = cb;
  env->callbacks.uncaught_exception_data = data;

  return 0;
}

int
js_on_unhandled_rejection(js_env_t *env, js_unhandled_rejection_cb cb, void *data) {
  env->callbacks.unhandled_rejection = cb;
  env->callbacks.unhandled_rejection_data = data;

  return 0;
}

int
js_on_dynamic_import(js_env_t *env, js_dynamic_import_cb cb, void *data) {
  env->callbacks.dynamic_import = cb;
  env->callbacks.dynamic_import_data = data;

  return 0;
}

int
js_get_env_loop(js_env_t *env, uv_loop_t **result) {
  *result = env->loop;

  return 0;
}

int
js_get_env_platform(js_env_t *env, js_platform_t **result) {
  *result = env->platform;

  return 0;
}

int
js_open_handle_scope(js_env_t *env, js_handle_scope_t **result) {
  // Allow continuing even with a pending exception

  js_handle_scope_t *scope = malloc(sizeof(js_handle_scope_t));

  scope->parent = env->scope;
  scope->values = NULL;
  scope->len = 0;
  scope->capacity = 0;

  env->scope = scope;

  *result = scope;

  return 0;
}

int
js_close_handle_scope(js_env_t *env, js_handle_scope_t *scope) {
  // Allow continuing even with a pending exception

  for (size_t i = 0; i < scope->len; i++) {
    jerry_value_free(scope->values[i]);
  }

  env->scope = scope->parent;

  if (scope->values) free(scope->values);

  free(scope);

  return 0;
}

int
js_open_escapable_handle_scope(js_env_t *env, js_escapable_handle_scope_t **result) {
  return js_open_handle_scope(env, (js_handle_scope_t **) result);
}

int
js_close_escapable_handle_scope(js_env_t *env, js_escapable_handle_scope_t *scope) {
  return js_close_handle_scope(env, (js_handle_scope_t *) scope);
}

static inline void
js__attach_to_handle_scope(js_env_t *env, js_handle_scope_t *scope, js_value_t *value) {
  assert(scope);

  if (scope->len >= scope->capacity) {
    if (scope->capacity) scope->capacity *= 2;
    else scope->capacity = 4;

    scope->values = realloc(scope->values, scope->capacity * sizeof(jerry_value_t));
  }

  scope->values[scope->len++] = js__value_from_abi(value);
}

int
js_escape_handle(js_env_t *env, js_escapable_handle_scope_t *scope, js_value_t *escapee, js_value_t **result) {
  // Allow continuing even with a pending exception

  jerry_value_t value = jerry_value_copy(js__value_from_abi(escapee));

  *result = js__value_to_abi(value);

  js__attach_to_handle_scope(env, scope->parent, *result);

  return 0;
}

int
js_create_context(js_env_t *env, js_context_t **result) {
  // Allow continuing even with a pending exception

  js_context_t *context = malloc(sizeof(js_context_t));

  context->realm = jerry_realm();
  context->previous = NULL;

  *result = context;

  return 0;
}

int
js_destroy_context(js_env_t *env, js_context_t *context) {
  // Allow continuing even with a pending exception

  jerry_value_free(context->realm);

  free(context);

  return 0;
}

int
js_enter_context(js_env_t *env, js_context_t *context) {
  // Allow continuing even with a pending exception

  context->previous = env->context;

  env->context = context;

  jerry_set_realm(context->realm);

  return 0;
}

int
js_exit_context(js_env_t *env, js_context_t *context) {
  // Allow continuing even with a pending exception

  env->context = context->previous;

  context->previous = NULL;

  jerry_set_realm(env->context->realm);

  return 0;
}

int
js_get_bindings(js_env_t *env, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(env->bindings);

  return 0;
}

int
js_run_script(js_env_t *env, const char *file, size_t len, int offset, js_value_t *source, js_value_t **result) {
  if (env->exception) return js__error(env);

  int err;

  if (len == (size_t) -1) len = strlen(file);

  if (len > UINT32_MAX) {
    err = js_throw_range_error(env, NULL, "String allocation failed");
    assert(err == 0);

    return js__error(env);
  }

  jerry_value_t source_name = jerry_string((const jerry_char_t *) file, len, JERRY_ENCODING_UTF8);

  jerry_parse_options_t options = {
    .options = JERRY_PARSE_HAS_SOURCE_NAME | JERRY_PARSE_HAS_START | JERRY_PARSE_HAS_USER_VALUE,
    .source_name = source_name,
    .start_line = 1,
    .start_column = offset,
    .user_value = source_name,
  };

  jerry_value_t parsed = jerry_parse_value(js__value_from_abi(source), &options);

  jerry_value_free(source_name);

  if (jerry_value_is_exception(parsed)) {
    if (env->depth) {
      env->exception = parsed;
    } else {
      js__uncaught_exception(env, parsed);
    }

    return js__error(env);
  }

  env->depth++;

  jerry_value_t value = jerry_run(parsed);

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  jerry_value_free(parsed);

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result == NULL) jerry_value_free(value);
  else {
    *result = js__value_to_abi(value);

    js__attach_to_handle_scope(env, env->scope, *result);
  }

  return 0;
}

static const jerry_object_native_info_t js__module = {};

static void
js__on_module_import_meta(const jerry_value_t handle, const jerry_value_t meta, void *opaque) {
  int err;

  js_module_t *module = jerry_object_get_native_ptr(handle, &js__module);

  js_env_t *env = module->env;

  if (module->meta) {
    js_handle_scope_t *scope;
    err = js_open_handle_scope(env, &scope);
    assert(err == 0);

    module->meta(env, module, js__value_to_abi(meta), module->meta_data);

    err = js_close_handle_scope(env, scope);
    assert(err == 0);
  }
}

static jerry_value_t
js__on_module_import(const jerry_value_t specifier, const jerry_value_t referrer, void *opaque) {
  int err;

  js_env_t *env = opaque;

  if (env->callbacks.dynamic_import == NULL) {
    return jerry_throw_sz(JERRY_ERROR_COMMON, "Dynamic import() is not supported");
  }

  jerry_value_t assertions = jerry_null();

  js_handle_scope_t *scope;
  err = js_open_handle_scope(env, &scope);
  assert(err == 0);

  js_module_t *module = env->callbacks.dynamic_import(
    env,
    js__value_to_abi(specifier),
    js__value_to_abi(assertions),
    js__value_to_abi(referrer),
    env->callbacks.dynamic_import_data
  );

  err = js_close_handle_scope(env, scope);
  assert(err == 0);

  jerry_value_free(assertions);

  jerry_value_t value;

  if (env->exception) {
    value = env->exception;

    env->exception = 0;
  } else {
    value = jerry_value_copy(module->handle);
  }

  return value;
}

int
js_create_module(js_env_t *env, const char *name, size_t len, int offset, js_value_t *source, js_module_meta_cb cb, void *data, js_module_t **result) {
  if (env->exception) return js__error(env);

  int err;

  if (len == (size_t) -1) len = strlen(name);

  if (len > UINT32_MAX) {
    err = js_throw_range_error(env, NULL, "String allocation failed");
    assert(err == 0);

    return js__error(env);
  }

  jerry_value_t source_name = jerry_string((const jerry_char_t *) name, len, JERRY_ENCODING_UTF8);

  jerry_parse_options_t options = {
    .options = JERRY_PARSE_MODULE | JERRY_PARSE_HAS_SOURCE_NAME | JERRY_PARSE_HAS_START | JERRY_PARSE_HAS_USER_VALUE,
    .source_name = source_name,
    .start_line = 1,
    .start_column = offset,
    .user_value = source_name,
  };

  jerry_value_t handle = jerry_parse_value(js__value_from_abi(source), &options);

  jerry_value_free(source_name);

  if (jerry_value_is_exception(handle)) {
    if (env->depth) {
      env->exception = handle;
    } else {
      js__uncaught_exception(env, handle);
    }

    return js__error(env);
  }

  js_module_t *module = malloc(sizeof(js_module_t));

  jerry_object_set_native_ptr(handle, &js__module, module);

  module->env = env;
  module->handle = handle;
  module->meta = cb;
  module->meta_data = data;

  if (len == (size_t) -1) {
    module->name = strdup(name);
  } else {
    module->name = malloc(len + 1);
    module->name[len] = '\0';

    memcpy(module->name, name, len);
  }

  *result = module;

  return 0;
}

jerry_value_t
js__on_module_evaluate(const jerry_value_t handle) {
  int err;

  js_module_t *module = jerry_object_get_native_ptr(handle, &js__module);

  js_env_t *env = module->env;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(env, &scope);
  assert(err == 0);

  module->evaluate(env, module, module->evaluate_data);

  err = js_close_handle_scope(env, scope);
  assert(err == 0);

  jerry_value_t value;

  if (env->exception) {
    value = env->exception;

    env->exception = 0;
  } else {
    value = jerry_undefined();
  }

  return value;
}

int
js_create_synthetic_module(js_env_t *env, const char *name, size_t len, js_value_t *const export_names[], size_t names_len, js_module_evaluate_cb cb, void *data, js_module_t **result) {
  if (env->exception) return js__error(env);

  jerry_value_t *names = malloc(names_len * sizeof(jerry_value_t));

  for (size_t i = 0, n = names_len; i < n; i++) {
    names[i] = js__value_from_abi(export_names[i]);
  }

  jerry_value_t handle = jerry_native_module(js__on_module_evaluate, names, names_len);

  free(names);

  js_module_t *module = malloc(sizeof(js_module_t));

  jerry_object_set_native_ptr(handle, &js__module, module);

  module->env = env;
  module->handle = handle;
  module->evaluate = cb;
  module->evaluate_data = data;

  if (len == (size_t) -1) {
    module->name = strdup(name);
  } else {
    module->name = malloc(len + 1);
    module->name[len] = '\0';

    memcpy(module->name, name, len);
  }

  *result = module;

  return 0;
}

int
js_delete_module(js_env_t *env, js_module_t *module) {
  // Allow continuing even with a pending exception

  jerry_value_free(module->handle);

  free(module->name);
  free(module);

  return 0;
}

int
js_get_module_name(js_env_t *env, js_module_t *module, const char **result) {
  // Allow continuing even with a pending exception

  *result = module->name;

  return 0;
}

int
js_get_module_namespace(js_env_t *env, js_module_t *module, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_module_namespace(module->handle));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_set_module_export(js_env_t *env, js_module_t *module, js_value_t *name, js_value_t *value) {
  if (env->exception) return js__error(env);

  jerry_value_t exception = jerry_native_module_set(module->handle, js__value_from_abi(name), js__value_from_abi(value));

  if (jerry_value_is_exception(exception)) {
    if (env->depth) {
      env->exception = exception;
    } else {
      js__uncaught_exception(env, exception);
    }

    return js__error(env);
  }

  jerry_value_free(exception);

  return 0;
}

static jerry_value_t
js__on_module_resolve(const jerry_value_t specifier, const jerry_value_t referrer, void *data) {
  int err;

  js_module_t *module = data;

  js_env_t *env = module->env;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(env, &scope);
  assert(err == 0);

  jerry_value_t assertions = jerry_null();

  js_module_t *resolved = module->resolve(
    env,
    js__value_to_abi(specifier),
    js__value_to_abi(assertions),
    module,
    module->resolve_data
  );

  jerry_value_free(assertions);

  err = js_close_handle_scope(env, scope);
  assert(err == 0);

  jerry_value_t value;

  if (env->exception) {
    value = env->exception;

    env->exception = 0;
  } else {
    value = jerry_value_copy(resolved->handle);
  }

  return value;
}

int
js_instantiate_module(js_env_t *env, js_module_t *module, js_module_resolve_cb cb, void *data) {
  if (env->exception) return js__error(env);

  module->resolve = cb;
  module->resolve_data = data;

  env->depth++;

  jerry_value_t exception = jerry_module_link(module->handle, js__on_module_resolve, module);

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(exception)) {
    if (env->depth) {
      env->exception = exception;
    } else {
      js__uncaught_exception(env, exception);
    }

    return js__error(env);
  }

  jerry_value_free(exception);

  return 0;
}

int
js_run_module(js_env_t *env, js_module_t *module, js_value_t **result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_module_evaluate(module->handle);

  jerry_value_t promise = jerry_promise();

  if (jerry_value_is_exception(value)) {
    value = jerry_exception_value(value, true);

    jerry_value_free(jerry_promise_reject(promise, value));
  } else if (env->exception) {
    jerry_value_free(value);

    value = jerry_exception_value(env->exception, true);

    env->exception = 0;

    jerry_value_free(jerry_promise_reject(promise, value));
  } else {
    jerry_value_free(jerry_promise_resolve(promise, value));
  }

  jerry_value_free(value);

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  *result = js__value_to_abi(promise);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

static void
js__on_reference_finalize(void *data, jerry_object_native_info_t *info) {
  js_ref_t *reference = data;

  if (reference->symbol) jerry_value_free(reference->symbol);

  reference->value = 0;
  reference->count = 0;
  reference->symbol = 0;
  reference->finalized = true;
}

static const jerry_object_native_info_t js__reference = {
  .free_cb = js__on_reference_finalize,
};

static inline void
js__set_weak_reference(js_env_t *env, js_ref_t *reference) {
  if (reference->finalized) return;

  if (jerry_value_is_object(reference->value)) {
    jerry_value_t description = jerry_string_sz("reference");

    reference->symbol = jerry_symbol_with_description(description);

    jerry_value_free(description);

    jerry_value_t external = jerry_object();

    jerry_object_set_native_ptr(external, &js__reference, reference);

    jerry_object_set_internal(reference->value, reference->symbol, external);

    jerry_value_free(external);

    jerry_value_free(reference->value);
  }
}

static inline void
js__clear_weak_reference(js_env_t *env, js_ref_t *reference) {
  if (reference->finalized) return;

  if (jerry_value_is_object(reference->value)) {
    reference->value = jerry_value_copy(reference->value);

    jerry_value_t external = jerry_object_get_internal(reference->value, reference->symbol);

    jerry_object_delete_native_ptr(external, &js__reference);

    jerry_object_delete_internal(reference->value, reference->symbol);

    jerry_value_free(external);

    jerry_value_free(reference->symbol);

    reference->symbol = 0;
  }
}

int
js_create_reference(js_env_t *env, js_value_t *value, uint32_t count, js_ref_t **result) {
  // Allow continuing even with a pending exception

  js_ref_t *reference = malloc(sizeof(js_ref_t));

  reference->value = jerry_value_copy(js__value_from_abi(value));
  reference->count = count;
  reference->symbol = 0;
  reference->finalized = false;

  if (reference->count == 0) js__set_weak_reference(env, reference);

  *result = reference;

  return 0;
}

int
js_delete_reference(js_env_t *env, js_ref_t *reference) {
  // Allow continuing even with a pending exception

  if (reference->count == 0) js__clear_weak_reference(env, reference);

  jerry_value_free(reference->value);

  free(reference);

  return 0;
}

int
js_reference_ref(js_env_t *env, js_ref_t *reference, uint32_t *result) {
  // Allow continuing even with a pending exception

  reference->count++;

  if (reference->count == 1) js__clear_weak_reference(env, reference);

  if (result) *result = reference->count;

  return 0;
}

int
js_reference_unref(js_env_t *env, js_ref_t *reference, uint32_t *result) {
  // Allow continuing even with a pending exception

  if (reference->count > 0) {
    reference->count--;

    if (reference->count == 0) js__set_weak_reference(env, reference);
  }

  if (result) *result = reference->count;

  return 0;
}

int
js_get_reference_value(js_env_t *env, js_ref_t *reference, js_value_t **result) {
  // Allow continuing even with a pending exception

  if (reference->finalized) *result = NULL;
  else {
    *result = js__value_to_abi(jerry_value_copy(reference->value));

    js__attach_to_handle_scope(env, env->scope, *result);
  }

  return 0;
}

int
js_define_class(js_env_t *env, const char *name, size_t len, js_function_cb constructor, void *data, js_property_descriptor_t const properties[], size_t properties_len, js_value_t **result) {
  if (env->exception) return js__error(env);

  int err;

  js_value_t *class;
  err = js_create_function(env, name, len, constructor, data, &class);
  assert(err == 0);

  js_value_t *prototype;
  err = js_create_object(env, &prototype);
  assert(err == 0);

  err = js_set_named_property(env, class, "prototype", prototype);
  assert(err == 0);

  size_t instance_properties_len = 0;
  size_t static_properties_len = 0;

  for (size_t i = 0; i < properties_len; i++) {
    const js_property_descriptor_t *property = &properties[i];

    if ((property->attributes & js_static) == 0) {
      instance_properties_len++;
    } else {
      static_properties_len++;
    }
  }

  if (instance_properties_len) {
    js_property_descriptor_t *instance_properties = malloc(sizeof(js_property_descriptor_t) * instance_properties_len);

    for (size_t i = 0, j = 0; i < properties_len; i++) {
      const js_property_descriptor_t *property = &properties[i];

      if ((property->attributes & js_static) == 0) {
        instance_properties[j++] = *property;
      }
    }

    err = js_define_properties(env, prototype, instance_properties, instance_properties_len);
    assert(err == 0);

    free(instance_properties);
  }

  if (static_properties_len) {
    js_property_descriptor_t *static_properties = malloc(sizeof(js_property_descriptor_t) * static_properties_len);

    for (size_t i = 0, j = 0; i < properties_len; i++) {
      const js_property_descriptor_t *property = &properties[i];

      if ((property->attributes & js_static) != 0) {
        static_properties[j++] = *property;
      }
    }

    err = js_define_properties(env, class, static_properties, static_properties_len);
    assert(err == 0);

    free(static_properties);
  }

  *result = class;

  return 0;
}

int
js_define_properties(js_env_t *env, js_value_t *object, js_property_descriptor_t const properties[], size_t properties_len) {
  if (env->exception) return js__error(env);

  int err;

  for (size_t i = 0; i < properties_len; i++) {
    const js_property_descriptor_t *property = &properties[i];

    uint16_t flags = JERRY_PROP_IS_WRITABLE_DEFINED | JERRY_PROP_IS_ENUMERABLE_DEFINED | JERRY_PROP_IS_CONFIGURABLE_DEFINED;

    if ((property->attributes & js_writable) != 0 || property->getter || property->setter) {
      flags |= JERRY_PROP_IS_WRITABLE;
    }

    if ((property->attributes & js_enumerable) != 0) {
      flags |= JERRY_PROP_IS_ENUMERABLE;
    }

    if ((property->attributes & js_configurable) != 0) {
      flags |= JERRY_PROP_IS_CONFIGURABLE;
    }

    jerry_value_t value, getter, setter;

    if (property->getter || property->setter) {
      if (property->getter) {
        flags |= JERRY_PROP_IS_GET_DEFINED;

        js_value_t *fn;
        err = js_create_function(env, "fn", -1, property->getter, property->data, &fn);
        assert(err == 0);

        getter = js__value_from_abi(fn);
      }

      if (property->setter) {
        flags |= JERRY_PROP_IS_SET_DEFINED;

        js_value_t *fn;
        err = js_create_function(env, "fn", -1, property->setter, property->data, &fn);
        assert(err == 0);

        setter = js__value_from_abi(fn);
      }
    } else if (property->method) {
      flags |= JERRY_PROP_IS_VALUE_DEFINED;

      js_value_t *fn;
      err = js_create_function(env, "fn", -1, property->method, property->data, &fn);
      assert(err == 0);

      value = js__value_from_abi(fn);
    } else {
      flags |= JERRY_PROP_IS_VALUE_DEFINED;

      value = js__value_from_abi(property->value);
    }

    jerry_property_descriptor_t descriptor = {
      flags,
      value,
      getter,
      setter,
    };

    jerry_value_t exception = jerry_object_define_own_prop(js__value_from_abi(object), js__value_from_abi(property->name), &descriptor);

    if (jerry_value_is_exception(exception)) {
      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  return 0;
}

static void
js__on_wrap_finalize(void *data, jerry_object_native_info_t *info) {
  js_finalizer_t *finalizer = data;

  if (finalizer->cb) finalizer->cb(finalizer->env, finalizer->data, finalizer->hint);

  free(finalizer);
}

static const jerry_object_native_info_t js__wrap = {
  .free_cb = js__on_wrap_finalize,
};

int
js_wrap(js_env_t *env, js_value_t *object, void *data, js_finalize_cb finalize_cb, void *finalize_hint, js_ref_t **result) {
  if (env->exception) return js__error(env);

  js_finalizer_t *finalizer = malloc(sizeof(js_finalizer_t));

  finalizer->env = env;
  finalizer->data = data;
  finalizer->cb = finalize_cb;
  finalizer->hint = finalize_hint;

  jerry_object_set_native_ptr(js__value_from_abi(object), &js__wrap, finalizer);

  if (result) return js_create_reference(env, object, 0, result);

  return 0;
}

int
js_unwrap(js_env_t *env, js_value_t *object, void **result) {
  if (env->exception) return js__error(env);

  js_finalizer_t *finalizer = jerry_object_get_native_ptr(js__value_from_abi(object), &js__wrap);

  *result = finalizer->data;

  return 0;
}

int
js_remove_wrap(js_env_t *env, js_value_t *object, void **result) {
  if (env->exception) return js__error(env);

  js_finalizer_t *finalizer = jerry_object_get_native_ptr(js__value_from_abi(object), &js__wrap);

  jerry_object_delete_native_ptr(js__value_from_abi(object), &js__wrap);

  if (result) *result = finalizer->data;

  free(finalizer);

  return 0;
}

static void
js__on_delegate_finalize(void *data, jerry_object_native_info_t *info) {
  js_delegate_t *delegate = data;

  if (delegate->finalize_cb) delegate->finalize_cb(delegate->env, delegate->data, delegate->finalize_hint);

  free(delegate);
}

static js_value_t *
js__on_delegate_get(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 3;
  js_value_t *argv[3];

  js_delegate_t *delegate;
  err = js_get_callback_info(env, info, &argc, argv, NULL, (void **) &delegate);
  assert(err == 0);

  assert(argc == 3);

  return delegate->callbacks.get(env, argv[1], delegate->data);
}

static js_value_t *
js__on_delegate_has(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 2;
  js_value_t *argv[2];

  js_delegate_t *delegate;
  err = js_get_callback_info(env, info, &argc, argv, NULL, (void **) &delegate);
  assert(err == 0);

  assert(argc == 2);

  bool exists = delegate->callbacks.has(env, argv[1], delegate->data);

  if (env->exception) return NULL;

  js_value_t *result;
  err = js_get_boolean(env, exists, &result);
  assert(err == 0);

  return result;
}

static js_value_t *
js__on_delegate_set(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 4;
  js_value_t *argv[4];

  js_delegate_t *delegate;
  err = js_get_callback_info(env, info, &argc, argv, NULL, (void **) &delegate);
  assert(err == 0);

  assert(argc == 4);

  bool success = delegate->callbacks.set(env, argv[1], argv[2], delegate->data);

  if (env->exception) return NULL;

  js_value_t *result;
  err = js_get_boolean(env, success, &result);
  assert(err == 0);

  return result;
}

static js_value_t *
js__on_delegate_delete_property(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 2;
  js_value_t *argv[2];

  js_delegate_t *delegate;
  err = js_get_callback_info(env, info, &argc, argv, NULL, (void **) &delegate);
  assert(err == 0);

  assert(argc == 2);

  bool success = delegate->callbacks.delete_property(env, argv[1], delegate->data);

  if (env->exception) {
    jerry_value_free(env->exception);

    env->exception = 0;

    success = false;
  };

  js_value_t *result;
  err = js_get_boolean(env, success, &result);
  assert(err == 0);

  return result;
}

static js_value_t *
js__on_delegate_own_keys(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  js_delegate_t *delegate;
  err = js_get_callback_info(env, info, &argc, argv, NULL, (void **) &delegate);
  assert(err == 0);

  assert(argc == 1);

  return delegate->callbacks.own_keys(env, delegate->data);
}

static const jerry_object_native_info_t js__delegate = {
  .free_cb = js__on_delegate_finalize,
};

int
js_create_delegate(js_env_t *env, const js_delegate_callbacks_t *callbacks, void *data, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result) {
  // Allow continuing even with a pending exception

  int err;

  js_delegate_t *delegate = malloc(sizeof(js_delegate_t));

  delegate->env = env;
  delegate->data = data;
  delegate->finalize_cb = finalize_cb;
  delegate->finalize_hint = finalize_hint;

  memcpy(&delegate->callbacks, callbacks, sizeof(js_delegate_callbacks_t));

  jerry_value_t target = jerry_object();
  jerry_value_t handler = jerry_object();

  if (callbacks->get) {
    js_value_t *fn;
    err = js_create_function(env, "get", -1, js__on_delegate_get, delegate, &fn);
    assert(err == 0);

    err = js_set_named_property(env, js__value_to_abi(handler), "get", fn);
    assert(err == 0);
  }

  if (callbacks->has) {
    js_value_t *fn;
    err = js_create_function(env, "has", -1, js__on_delegate_has, delegate, &fn);
    assert(err == 0);

    err = js_set_named_property(env, js__value_to_abi(handler), "has", fn);
    assert(err == 0);
  }

  if (callbacks->set) {
    js_value_t *fn;
    err = js_create_function(env, "set", -1, js__on_delegate_set, delegate, &fn);
    assert(err == 0);

    err = js_set_named_property(env, js__value_to_abi(handler), "set", fn);
    assert(err == 0);
  }

  if (callbacks->delete_property) {
    js_value_t *fn;
    err = js_create_function(env, "deleteProperty", -1, js__on_delegate_delete_property, delegate, &fn);
    assert(err == 0);

    err = js_set_named_property(env, js__value_to_abi(handler), "deleteProperty", fn);
    assert(err == 0);
  }

  if (callbacks->own_keys) {
    js_value_t *fn;
    err = js_create_function(env, "ownKeys", -1, js__on_delegate_own_keys, delegate, &fn);
    assert(err == 0);

    err = js_set_named_property(env, js__value_to_abi(handler), "ownKeys", fn);
    assert(err == 0);
  }

  jerry_value_t proxy = jerry_proxy(target, handler);

  jerry_object_set_native_ptr(proxy, &js__delegate, delegate);

  jerry_value_free(target);
  jerry_value_free(handler);

  *result = js__value_to_abi(proxy);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

static void
js__on_finalizer_finalize(void *data, jerry_object_native_info_t *info) {
  js_finalizer_list_t *next = data, *prev;

  while (next) {
    js_finalizer_t *finalizer = &next->finalizer;

    if (finalizer->cb) finalizer->cb(finalizer->env, finalizer->data, finalizer->hint);

    prev = next;
    next = next->next;

    free(prev);
  }
}

static const jerry_object_native_info_t js__finalizer = {
  .free_cb = js__on_finalizer_finalize,
};

int
js_add_finalizer(js_env_t *env, js_value_t *object, void *data, js_finalize_cb finalize_cb, void *finalize_hint, js_ref_t **result) {
  // Allow continuing even with a pending exception

  js_finalizer_list_t *next = malloc(sizeof(js_finalizer_list_t));

  js_finalizer_t *finalizer = &next->finalizer;

  finalizer->env = env;
  finalizer->data = data;
  finalizer->cb = finalize_cb;
  finalizer->hint = finalize_hint;

  next->next = jerry_object_get_native_ptr(js__value_from_abi(object), &js__finalizer);

  jerry_object_set_native_ptr(js__value_from_abi(object), &js__finalizer, next);

  if (result) return js_create_reference(env, object, 0, result);

  return 0;
}

static void
js__on_type_tag_finalize(void *data, jerry_object_native_info_t *info) {
  free(data);
}

static const jerry_object_native_info_t js__type_tag = {
  .free_cb = js__on_type_tag_finalize,
};

int
js_add_type_tag(js_env_t *env, js_value_t *object, const js_type_tag_t *tag) {
  if (env->exception) return js__error(env);

  int err;

  if (jerry_object_has_native_ptr(js__value_from_abi(object), &js__type_tag)) {
    err = js_throw_errorf(env, NULL, "Object is already type tagged");
    assert(err == 0);

    return js__error(env);
  }

  js_type_tag_t *existing = malloc(sizeof(js_type_tag_t));

  existing->lower = tag->lower;
  existing->upper = tag->upper;

  jerry_object_set_native_ptr(js__value_from_abi(object), &js__type_tag, existing);

  return 0;
}

int
js_check_type_tag(js_env_t *env, js_value_t *object, const js_type_tag_t *tag, bool *result) {
  if (env->exception) return js__error(env);

  js_type_tag_t *existing = jerry_object_get_native_ptr(js__value_from_abi(object), &js__type_tag);

  *result = existing != NULL && existing->lower == tag->lower && existing->upper == tag->upper;

  return 0;
}

int
js_create_int32(js_env_t *env, int32_t value, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_number((double) value));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_uint32(js_env_t *env, uint32_t value, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_number((double) value));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_int64(js_env_t *env, int64_t value, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_number((double) value));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_double(js_env_t *env, double value, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_number(value));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_bigint_int64(js_env_t *env, int64_t value, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_bigint((uint64_t *) &value, 1, value < 0));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_bigint_uint64(js_env_t *env, uint64_t value, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_bigint(&value, 1, false));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_string_utf8(js_env_t *env, const utf8_t *str, size_t len, js_value_t **result) {
  int err;

  if (len == (size_t) -1) len = strlen((const char *) str);

  if (len > UINT32_MAX) {
    err = js_throw_range_error(env, NULL, "String allocation failed");
    assert(err == 0);

    return js__error(env);
  }

  jerry_value_t value = jerry_string(str, len, JERRY_ENCODING_UTF8);

  *result = js__value_to_abi(value);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_string_utf16le(js_env_t *env, const utf16_t *str, size_t len, js_value_t **result) {
  int err;

  if (len == (size_t) -1) len = wcslen((wchar_t *) str);

  size_t utf8_len = utf8_length_from_utf16le(str, len);

  if (utf8_len > UINT32_MAX) {
    err = js_throw_range_error(env, NULL, "String allocation failed");
    assert(err == 0);

    return js__error(env);
  }

  utf8_t *utf8 = malloc(utf8_len);

  utf16le_convert_to_utf8(str, len, utf8);

  jerry_value_t value = jerry_string(utf8, utf8_len, JERRY_ENCODING_UTF8);

  free(utf8);

  *result = js__value_to_abi(value);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_string_latin1(js_env_t *env, const latin1_t *str, size_t len, js_value_t **result) {
  int err;

  if (len == (size_t) -1) len = strlen((char *) str);

  size_t utf8_len = utf8_length_from_latin1(str, len);

  if (utf8_len > UINT32_MAX) {
    err = js_throw_range_error(env, NULL, "String allocation failed");
    assert(err == 0);

    return js__error(env);
  }

  utf8_t *utf8 = malloc(utf8_len);

  latin1_convert_to_utf8(str, len, utf8);

  jerry_value_t value = jerry_string(utf8, utf8_len, JERRY_ENCODING_UTF8);

  free(utf8);

  *result = js__value_to_abi(value);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_external_string_utf8(js_env_t *env, utf8_t *str, size_t len, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result, bool *copied) {
  int err;
  err = js_create_string_utf8(env, str, len, result);
  if (err < 0) return err;

  if (copied) *copied = true;

  if (finalize_cb) finalize_cb(env, str, finalize_hint);

  return 0;
}

int
js_create_external_string_utf16le(js_env_t *env, utf16_t *str, size_t len, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result, bool *copied) {
  int err;
  err = js_create_string_utf16le(env, str, len, result);
  if (err < 0) return err;

  if (copied) *copied = true;

  if (finalize_cb) finalize_cb(env, str, finalize_hint);

  return 0;
}

int
js_create_external_string_latin1(js_env_t *env, latin1_t *str, size_t len, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result, bool *copied) {
  int err;
  err = js_create_string_latin1(env, str, len, result);
  if (err < 0) return err;

  if (copied) *copied = true;

  if (finalize_cb) finalize_cb(env, str, finalize_hint);

  return 0;
}

int
js_create_property_key_utf8(js_env_t *env, const utf8_t *str, size_t len, js_value_t **result) {
  return js_create_string_utf8(env, str, len, result);
}

int
js_create_property_key_utf16le(js_env_t *env, const utf16_t *str, size_t len, js_value_t **result) {
  return js_create_string_utf16le(env, str, len, result);
}

int
js_create_property_key_latin1(js_env_t *env, const latin1_t *str, size_t len, js_value_t **result) {
  return js_create_string_latin1(env, str, len, result);
}

int
js_create_symbol(js_env_t *env, js_value_t *description, js_value_t **result) {
  // Allow continuing even with a pending exception

  jerry_value_t symbol = jerry_symbol_with_description(js__value_from_abi(description));

  *result = js__value_to_abi(symbol);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_object(js_env_t *env, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_object());

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

static void
js__on_function_finalize(void *data, jerry_object_native_info_t *info) {
  free(data);
}

static const jerry_object_native_info_t js__function = {
  .free_cb = js__on_function_finalize,
};

static jerry_value_t
js__on_function_call(const jerry_call_info_t *info, const jerry_value_t argv[], const jerry_length_t argc) {
  int err;

  js_callback_t *callback = jerry_object_get_native_ptr(info->function, &js__function);

  js_callback_info_t callback_info = {
    .callback = callback,
    .info = info,
    .argv = argv,
    .argc = argc,
  };

  js_env_t *env = callback->env;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(env, &scope);
  assert(err == 0);

  js_value_t *result = callback->cb(env, &callback_info);

  jerry_value_t value;

  if (env->exception) {
    value = env->exception;

    env->exception = 0;
  } else {
    value = jerry_value_copy(js__value_from_abi(result));
  }

  err = js_close_handle_scope(env, scope);
  assert(err == 0);

  return value;
}

int
js_create_function(js_env_t *env, const char *name, size_t len, js_function_cb cb, void *data, js_value_t **result) {
  if (env->exception) return js__error(env);

  js_callback_t *callback = malloc(sizeof(js_callback_t));

  callback->env = env;
  callback->cb = cb;
  callback->data = data;

  jerry_value_t function = jerry_function_external(js__on_function_call);

  jerry_object_set_native_ptr(function, &js__function, callback);

  *result = js__value_to_abi(function);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_function_with_source(js_env_t *env, const char *name, size_t name_len, const char *file, size_t file_len, js_value_t *const args[], size_t args_len, int offset, js_value_t *source, js_value_t **result) {
  if (env->exception) return js__error(env);

  int err;

  if (file_len == (size_t) -1) file_len = strlen(file);

  if (file_len > UINT32_MAX) {
    err = js_throw_range_error(env, NULL, "String allocation failed");
    assert(err == 0);

    return js__error(env);
  }

  size_t buf_len = 0;

  for (int i = 0; i < args_len; i++) {
    if (i != 0) buf_len += 2;

    buf_len += jerry_string_size(js__value_from_abi(args[i]), JERRY_ENCODING_UTF8);
  }

  char *buf = malloc(buf_len + 1 /* NULL */);

  size_t j = 0;

  for (int i = 0; i < args_len; i++) {
    if (i != 0) {
      buf[j++] = ',';
      buf[j++] = ' ';
    }

    j += jerry_string_to_buffer(js__value_from_abi(args[i]), JERRY_ENCODING_UTF8, (uint8_t *) &buf[j], buf_len - j);
  }

  buf[j] = '\0';

  jerry_value_t source_name = jerry_string((const jerry_char_t *) file, file_len, JERRY_ENCODING_UTF8);

  jerry_value_t argument_list = jerry_string_sz(buf);

  jerry_parse_options_t options = {
    .options = JERRY_PARSE_HAS_SOURCE_NAME | JERRY_PARSE_HAS_START | JERRY_PARSE_HAS_USER_VALUE | JERRY_PARSE_HAS_ARGUMENT_LIST,
    .source_name = source_name,
    .start_line = 1,
    .start_column = offset,
    .user_value = source_name,
    .argument_list = argument_list,
  };

  free(buf);

  jerry_value_t parsed = jerry_parse_value(js__value_from_abi(source), &options);

  jerry_value_free(source_name);
  jerry_value_free(argument_list);

  if (jerry_value_is_exception(parsed)) {
    if (env->depth) {
      env->exception = parsed;
    } else {
      js__uncaught_exception(env, parsed);
    }

    return js__error(env);
  }

  *result = js__value_to_abi(parsed);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_typed_function(js_env_t *env, const char *name, size_t len, js_function_cb cb, const js_callback_signature_t *signature, const void *address, void *data, js_value_t **result) {
  return js_create_function(env, name, len, cb, data, result);
}

int
js_create_array(js_env_t *env, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_array(0));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_array_with_length(js_env_t *env, size_t len, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_array(len));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

static void
js__on_external_finalize(void *data, jerry_object_native_info_t *info) {
  js_finalizer_t *finalizer = data;

  if (finalizer->cb) finalizer->cb(finalizer->env, finalizer->data, finalizer->hint);

  free(finalizer);
}

static const jerry_object_native_info_t js__external = {
  .free_cb = js__on_external_finalize,
};

int
js_create_external(js_env_t *env, void *data, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result) {
  // Allow continuing even with a pending exception

  js_finalizer_t *finalizer = malloc(sizeof(js_finalizer_t));

  finalizer->env = env;
  finalizer->data = data;
  finalizer->cb = finalize_cb;
  finalizer->hint = finalize_hint;

  jerry_value_t external = jerry_object();

  jerry_object_set_native_ptr(external, &js__external, finalizer);

  *result = js__value_to_abi(external);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_date(js_env_t *env, double time, js_value_t **result) {
  // Allow continuing even with a pending exception

  jerry_value_t global = jerry_current_realm();
  jerry_value_t constructor = jerry_object_get_sz(global, "Date");
  jerry_value_t arg = jerry_number(time);
  jerry_value_t date = jerry_construct(constructor, &arg, 1);

  jerry_value_free(global);
  jerry_value_free(constructor);
  jerry_value_free(arg);

  *result = js__value_to_abi(date);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_error(js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  // Allow continuing even with a pending exception

  jerry_value_t error = jerry_error(JERRY_ERROR_COMMON, js__value_from_abi(message));

  if (code) {
    jerry_value_t exception = jerry_object_set_sz(error, "code", js__value_from_abi(code));

    if (jerry_value_is_exception(exception)) {
      jerry_value_free(error);

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  *result = js__value_to_abi(error);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_type_error(js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  // Allow continuing even with a pending exception

  jerry_value_t error = jerry_error(JERRY_ERROR_TYPE, js__value_from_abi(message));

  if (code) {
    jerry_value_t exception = jerry_object_set_sz(error, "code", js__value_from_abi(code));

    if (jerry_value_is_exception(exception)) {
      jerry_value_free(error);

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  *result = js__value_to_abi(error);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_range_error(js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  // Allow continuing even with a pending exception

  jerry_value_t error = jerry_error(JERRY_ERROR_RANGE, js__value_from_abi(message));

  if (code) {
    jerry_value_t exception = jerry_object_set_sz(error, "code", js__value_from_abi(code));

    if (jerry_value_is_exception(exception)) {
      jerry_value_free(error);

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  *result = js__value_to_abi(error);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_syntax_error(js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  // Allow continuing even with a pending exception

  jerry_value_t error = jerry_error(JERRY_ERROR_SYNTAX, js__value_from_abi(message));

  if (code) {
    jerry_value_t exception = jerry_object_set_sz(error, "code", js__value_from_abi(code));

    if (jerry_value_is_exception(exception)) {
      jerry_value_free(error);

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  *result = js__value_to_abi(error);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_reference_error(js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  // Allow continuing even with a pending exception

  jerry_value_t error = jerry_error(JERRY_ERROR_REFERENCE, js__value_from_abi(message));

  if (code) {
    jerry_value_t exception = jerry_object_set_sz(error, "code", js__value_from_abi(code));

    if (jerry_value_is_exception(exception)) {
      jerry_value_free(error);

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  *result = js__value_to_abi(error);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_promise(js_env_t *env, js_deferred_t **deferred, js_value_t **promise) {
  // Allow continuing even with a pending exception

  js_deferred_t *result = malloc(sizeof(js_deferred_t));

  result->promise = jerry_promise();

  *deferred = result;

  *promise = js__value_to_abi(result->promise);

  return 0;
}

int
js_resolve_deferred(js_env_t *env, js_deferred_t *deferred, js_value_t *resolution) {
  // Allow continuing even with a pending exception

  jerry_value_free(jerry_promise_resolve(deferred->promise, js__value_from_abi(resolution)));

  jerry_value_free(deferred->promise);

  if (env->depth == 0) js__run_microtasks(env);

  free(deferred);

  return 0;
}

int
js_reject_deferred(js_env_t *env, js_deferred_t *deferred, js_value_t *resolution) {
  // Allow continuing even with a pending exception

  jerry_value_free(jerry_promise_reject(deferred->promise, js__value_from_abi(resolution)));

  jerry_value_free(deferred->promise);

  if (env->depth == 0) js__run_microtasks(env);

  free(deferred);

  return 0;
}

int
js_get_promise_state(js_env_t *env, js_value_t *promise, js_promise_state_t *result) {
  // Allow continuing even with a pending exception

  jerry_promise_state_t state = jerry_promise_state(js__value_from_abi(promise));

  switch (state) {
  case JERRY_PROMISE_STATE_PENDING:
  default:
    *result = js_promise_pending;
    break;
  case JERRY_PROMISE_STATE_FULFILLED:
    *result = js_promise_fulfilled;
    break;
  case JERRY_PROMISE_STATE_REJECTED:
    *result = js_promise_rejected;
    break;
  }

  return 0;
}

int
js_get_promise_result(js_env_t *env, js_value_t *promise, js_value_t **result) {
  // Allow continuing even with a pending exception

  jerry_value_t value = jerry_promise_result(js__value_from_abi(promise));

  assert(jerry_value_is_exception(value) == false);

  *result = js__value_to_abi(value);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_arraybuffer(js_env_t *env, size_t len, void **data, js_value_t **result) {
  if (env->exception) return js__error(env);

  int err;

  if (len > UINT32_MAX) {
    err = js_throw_range_error(env, NULL, "Array buffer allocation failed");
    assert(err == 0);

    return js__error(env);
  }

  jerry_value_t value = jerry_arraybuffer(len);

  if (data) *data = jerry_arraybuffer_data(value);

  *result = js__value_to_abi(value);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_arraybuffer_with_backing_store(js_env_t *env, js_arraybuffer_backing_store_t *backing_store, void **data, size_t *len, js_value_t **result) {
  if (env->exception) return js__error(env);

  backing_store->references++;

  if (data) *data = backing_store->data;

  if (len) *len = backing_store->len;

  js_arraybuffer_attachment_t *attachment = malloc(sizeof(js_arraybuffer_attachment_t));

  attachment->type = js_arraybuffer_backing_store;
  attachment->backing_store = backing_store;

  *result = js__value_to_abi(jerry_arraybuffer_external(backing_store->data, backing_store->len, attachment));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_unsafe_arraybuffer(js_env_t *env, size_t len, void **data, js_value_t **result) {
  return js_create_arraybuffer(env, len, data, result);
}

int
js_create_external_arraybuffer(js_env_t *env, void *data, size_t len, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result) {
  if (env->exception) return js__error(env);

  js_arraybuffer_attachment_t *attachment = malloc(sizeof(js_arraybuffer_attachment_t));

  attachment->type = js_arraybuffer_finalizer;

  js_finalizer_t *finalizer = &attachment->finalizer;

  finalizer->env = env;
  finalizer->data = data;
  finalizer->cb = finalize_cb;
  finalizer->hint = finalize_hint;

  *result = js__value_to_abi(jerry_arraybuffer_external(data, len, attachment));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_detach_arraybuffer(js_env_t *env, js_value_t *arraybuffer) {
  // Allow continuing even with a pending exception

  jerry_value_free(jerry_arraybuffer_detach(js__value_from_abi(arraybuffer)));

  return 0;
}

int
js_get_arraybuffer_backing_store(js_env_t *env, js_value_t *arraybuffer, js_arraybuffer_backing_store_t **result) {
  // Allow continuing even with a pending exception

  js_arraybuffer_backing_store_t *backing_store = malloc(sizeof(js_arraybuffer_backing_store_t));

  backing_store->owner = jerry_value_copy(js__value_from_abi(arraybuffer));
  backing_store->references = 1;
  backing_store->len = jerry_arraybuffer_size(js__value_from_abi(arraybuffer));
  backing_store->data = jerry_arraybuffer_data(js__value_from_abi(arraybuffer));

  *result = backing_store;

  return 0;
}

int
js_create_sharedarraybuffer(js_env_t *env, size_t len, void **data, js_value_t **result) {
  if (env->exception) return js__error(env);

  int err;

  if (len > UINT32_MAX) {
    err = js_throw_range_error(env, NULL, "Array buffer allocation failed");
    assert(err == 0);

    return js__error(env);
  }

  jerry_value_t value = jerry_shared_arraybuffer(len);

  if (data) *data = jerry_arraybuffer_data(value);

  *result = js__value_to_abi(value);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_sharedarraybuffer_with_backing_store(js_env_t *env, js_arraybuffer_backing_store_t *backing_store, void **data, size_t *len, js_value_t **result) {
  if (env->exception) return js__error(env);

  if (data) *data = backing_store->data;

  if (len) *len = backing_store->len;

  jerry_value_t value = jerry_shared_arraybuffer_external(backing_store->data, backing_store->len, NULL);

  js_arraybuffer_header_t *header = js__arraybuffer_header(backing_store->data);

  header->references++;

  *result = js__value_to_abi(value);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_unsafe_sharedarraybuffer(js_env_t *env, size_t len, void **data, js_value_t **result) {
  return js_create_sharedarraybuffer(env, len, data, result);
}

int
js_create_external_sharedarraybuffer(js_env_t *env, void *data, size_t len, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result) {
  if (env->exception) return js__error(env);

  js_arraybuffer_attachment_t *attachment = malloc(sizeof(js_arraybuffer_attachment_t));

  attachment->type = js_arraybuffer_finalizer;

  js_finalizer_t *finalizer = &attachment->finalizer;

  finalizer->env = env;
  finalizer->data = data;
  finalizer->cb = finalize_cb;
  finalizer->hint = finalize_hint;

  *result = js__value_to_abi(jerry_shared_arraybuffer_external(data, len, attachment));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_get_sharedarraybuffer_backing_store(js_env_t *env, js_value_t *sharedarraybuffer, js_arraybuffer_backing_store_t **result) {
  // Allow continuing even with a pending exception

  js_arraybuffer_backing_store_t *backing_store = malloc(sizeof(js_arraybuffer_backing_store_t));

  backing_store->owner = 0;
  backing_store->references = 1;
  backing_store->len = jerry_arraybuffer_size(js__value_from_abi(sharedarraybuffer));
  backing_store->data = jerry_arraybuffer_data(js__value_from_abi(sharedarraybuffer));

  js_arraybuffer_header_t *header = js__arraybuffer_header(backing_store->data);

  header->references++;

  *result = backing_store;

  return 0;
}

int
js_release_arraybuffer_backing_store(js_env_t *env, js_arraybuffer_backing_store_t *backing_store) {
  // Allow continuing even with a pending exception

  if (--backing_store->references == 0) {
    if (backing_store->owner) {
      jerry_value_free(backing_store->owner);
    } else {
      js_arraybuffer_header_t *header = js__arraybuffer_header(backing_store->data);

      if (--header->references == 0) {
        free(header);
      }
    }

    free(backing_store);
  }

  return 0;
}

int
js_create_typedarray(js_env_t *env, js_typedarray_type_t type, size_t len, js_value_t *arraybuffer, size_t offset, js_value_t **result) {
  if (env->exception) return js__error(env);

  jerry_typedarray_type_t type_name;

  switch (type) {
  case js_int8array:
    type_name = JERRY_TYPEDARRAY_INT8;
    break;
  case js_uint8array:
  default:
    type_name = JERRY_TYPEDARRAY_UINT8;
    break;
  case js_uint8clampedarray:
    type_name = JERRY_TYPEDARRAY_UINT8CLAMPED;
    break;
  case js_int16array:
    type_name = JERRY_TYPEDARRAY_INT16;
    break;
  case js_uint16array:
    type_name = JERRY_TYPEDARRAY_UINT16;
    break;
  case js_int32array:
    type_name = JERRY_TYPEDARRAY_INT32;
    break;
  case js_uint32array:
    type_name = JERRY_TYPEDARRAY_UINT32;
    break;
  case js_float32array:
    type_name = JERRY_TYPEDARRAY_FLOAT32;
    break;
  case js_float64array:
    type_name = JERRY_TYPEDARRAY_FLOAT64;
    break;
  case js_bigint64array:
    type_name = JERRY_TYPEDARRAY_BIGINT64;
    break;
  case js_biguint64array:
    type_name = JERRY_TYPEDARRAY_BIGUINT64;
    break;
  }

  jerry_value_t typedarray = jerry_typedarray_with_buffer_span(type_name, js__value_from_abi(arraybuffer), offset, len);

  *result = js__value_to_abi(typedarray);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_create_dataview(js_env_t *env, size_t len, js_value_t *arraybuffer, size_t offset, js_value_t **result) {
  if (env->exception) return js__error(env);

  jerry_value_t dataview = jerry_dataview(js__value_from_abi(arraybuffer), offset, len);

  *result = js__value_to_abi(dataview);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_coerce_to_boolean(js_env_t *env, js_value_t *value, js_value_t **result) {
  // Allow continuing even with a pending exception

  jerry_value_t boolean = jerry_boolean(jerry_value_to_boolean(js__value_from_abi(value)));

  *result = js__value_to_abi(boolean);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_coerce_to_number(js_env_t *env, js_value_t *value, js_value_t **result) {
  if (env->exception) return js__error(env);

  jerry_value_t number = jerry_value_to_number(js__value_from_abi(value));

  if (jerry_value_is_exception(number)) {
    if (env->depth) {
      env->exception = number;
    } else {
      js__uncaught_exception(env, number);
    }

    return js__error(env);
  }

  *result = js__value_to_abi(number);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_coerce_to_string(js_env_t *env, js_value_t *value, js_value_t **result) {
  if (env->exception) return js__error(env);

  jerry_value_t string = jerry_value_to_string(js__value_from_abi(value));

  if (jerry_value_is_exception(string)) {
    if (env->depth) {
      env->exception = string;
    } else {
      js__uncaught_exception(env, string);
    }

    return js__error(env);
  }

  *result = js__value_to_abi(string);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_coerce_to_object(js_env_t *env, js_value_t *value, js_value_t **result) {
  if (env->exception) return js__error(env);

  jerry_value_t object = jerry_value_to_object(js__value_from_abi(value));

  if (jerry_value_is_exception(object)) {
    if (env->depth) {
      env->exception = object;
    } else {
      js__uncaught_exception(env, object);
    }

    return js__error(env);
  }

  *result = js__value_to_abi(object);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_typeof(js_env_t *env, js_value_t *value, js_value_type_t *result) {
  // Allow continuing even with a pending exception

  jerry_type_t type = jerry_value_type(js__value_from_abi(value));

  switch (type) {
  case JERRY_TYPE_UNDEFINED:
  default:
    *result = js_undefined;
    break;
  case JERRY_TYPE_NULL:
    *result = js_null;
    break;
  case JERRY_TYPE_BOOLEAN:
    *result = js_boolean;
    break;
  case JERRY_TYPE_NUMBER:
    *result = js_number;
    break;
  case JERRY_TYPE_STRING:
    *result = js_string;
    break;
  case JERRY_TYPE_SYMBOL:
    *result = js_symbol;
    break;
  case JERRY_TYPE_OBJECT:
    *result = jerry_object_has_native_ptr(js__value_from_abi(value), &js__external)
                ? js_external
                : js_object;
    break;
  case JERRY_TYPE_FUNCTION:
    *result = js_function;
    break;
  case JERRY_TYPE_BIGINT:
    *result = js_bigint;
    break;
  }

  return 0;
}

int
js_instanceof(js_env_t *env, js_value_t *object, js_value_t *constructor, bool *result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_binary_op(JERRY_BIN_OP_INSTANCEOF, js__value_from_abi(object), js__value_from_abi(constructor));

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  *result = jerry_value_to_boolean(value);

  jerry_value_free(value);

  return 0;
}

int
js_is_undefined(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_undefined(js__value_from_abi(value));

  return 0;
}

int
js_is_null(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_null(js__value_from_abi(value));

  return 0;
}

int
js_is_boolean(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_boolean(js__value_from_abi(value));

  return 0;
}

int
js_is_number(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_number(js__value_from_abi(value));

  return 0;
}

int
js_is_int32(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  if (jerry_value_is_number(js__value_from_abi(value))) {
    double integral, number = jerry_value_as_number(js__value_from_abi(value));

    *result = modf(number, &integral) == 0.0 && integral >= INT32_MIN && integral <= INT32_MAX;
  } else {
    *result = false;
  }

  return 0;
}

int
js_is_uint32(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  if (jerry_value_is_number(js__value_from_abi(value))) {
    double integral, number = jerry_value_as_number(js__value_from_abi(value));

    *result = modf(number, &integral) == 0.0 && integral >= 0.0 && integral <= UINT32_MAX;
  } else {
    *result = false;
  }

  return 0;
}

int
js_is_string(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_string(js__value_from_abi(value));

  return 0;
}

int
js_is_symbol(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_symbol(js__value_from_abi(value));

  return 0;
}

int
js_is_object(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_object(js__value_from_abi(value));

  return 0;
}

int
js_is_function(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_function(js__value_from_abi(value));

  return 0;
}

int
js_is_async_function(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_async_function(js__value_from_abi(value));

  return 0;
}

int
js_is_generator_function(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_function_type(js__value_from_abi(value)) == JERRY_FUNCTION_TYPE_GENERATOR;

  return 0;
}

int
js_is_generator(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_object_type(js__value_from_abi(value)) == JERRY_OBJECT_TYPE_ITERATOR;

  return 0;
}

int
js_is_arguments(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_object_type(js__value_from_abi(value)) == JERRY_OBJECT_TYPE_ARGUMENTS;

  return 0;
}

int
js_is_array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_array(js__value_from_abi(value));

  return 0;
}

int
js_is_external(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_object_has_native_ptr(js__value_from_abi(value), &js__external);

  return 0;
}

int
js_is_wrapped(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_object_has_native_ptr(js__value_from_abi(value), &js__wrap);

  return 0;
}

int
js_is_delegate(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  return 0;
}

int
js_is_bigint(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_bigint(js__value_from_abi(value));

  return 0;
}

int
js_is_date(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_object_type(js__value_from_abi(value)) == JERRY_OBJECT_TYPE_DATE;

  return 0;
}

int
js_is_regexp(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_object_type(js__value_from_abi(value)) == JERRY_OBJECT_TYPE_REGEXP;

  return 0;
}

int
js_is_error(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_object_type(js__value_from_abi(value)) == JERRY_OBJECT_TYPE_ERROR;

  return 0;
}

int
js_is_promise(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_promise(js__value_from_abi(value));

  return 0;
}

int
js_is_proxy(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_proxy(js__value_from_abi(value));

  return 0;
}

int
js_is_map(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_container_type(js__value_from_abi(value)) == JERRY_CONTAINER_TYPE_MAP;

  return 0;
}

int
js_is_map_iterator(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_iterator_type(js__value_from_abi(value)) == JERRY_ITERATOR_TYPE_MAP;

  return 0;
}

int
js_is_set(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_container_type(js__value_from_abi(value)) == JERRY_CONTAINER_TYPE_SET;

  return 0;
}

int
js_is_set_iterator(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_iterator_type(js__value_from_abi(value)) == JERRY_ITERATOR_TYPE_SET;

  return 0;
}

int
js_is_weak_map(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_container_type(js__value_from_abi(value)) == JERRY_CONTAINER_TYPE_WEAKMAP;

  return 0;
}

int
js_is_weak_set(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_container_type(js__value_from_abi(value)) == JERRY_CONTAINER_TYPE_WEAKSET;

  return 0;
}

int
js_is_weak_ref(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_object_type(js__value_from_abi(value)) == JERRY_OBJECT_TYPE_WEAKREF;

  return 0;
}

int
js_is_arraybuffer(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_arraybuffer(js__value_from_abi(value));

  return 0;
}

int
js_is_detached_arraybuffer(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_arraybuffer(js__value_from_abi(value)) && jerry_arraybuffer_data(js__value_from_abi(value)) == NULL;

  return 0;
}

int
js_is_sharedarraybuffer(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_shared_arraybuffer(js__value_from_abi(value));

  return 0;
}

int
js_is_typedarray(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_typedarray(js__value_from_abi(value));

  return 0;
}

int
js_is_int8array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_INT8;

  return 0;
}

int
js_is_uint8array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_UINT8;

  return 0;
}

int
js_is_uint8clampedarray(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_UINT8CLAMPED;

  return 0;
}

int
js_is_int16array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_INT16;

  return 0;
}

int
js_is_uint16array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_UINT16;

  return 0;
}

int
js_is_int32array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_INT32;

  return 0;
}

int
js_is_uint32array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_UINT32;

  return 0;
}

int
js_is_float32array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_FLOAT32;

  return 0;
}

int
js_is_float64array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_FLOAT64;

  return 0;
}

int
js_is_bigint64array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_BIGINT64;

  return 0;
}

int
js_is_biguint64array(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_typedarray_type(js__value_from_abi(value)) == JERRY_TYPEDARRAY_BIGUINT64;

  return 0;
}

int
js_is_dataview(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_is_dataview(js__value_from_abi(value));

  return 0;
}

int
js_is_module_namespace(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_object_type(js__value_from_abi(value)) == JERRY_OBJECT_TYPE_MODULE_NAMESPACE;

  return 0;
}

int
js_strict_equals(js_env_t *env, js_value_t *a, js_value_t *b, bool *result) {
  // Allow continuing even with a pending exception

  jerry_value_t value = jerry_binary_op(JERRY_BIN_OP_STRICT_EQUAL, js__value_from_abi(a), js__value_from_abi(b));

  *result = jerry_value_to_boolean(value);

  jerry_value_free(value);

  return 0;
}

int
js_get_global(js_env_t *env, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_current_realm());

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_get_undefined(js_env_t *env, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_undefined());

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_get_null(js_env_t *env, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_null());

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_get_boolean(js_env_t *env, bool value, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_boolean(value));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_get_value_bool(js_env_t *env, js_value_t *value, bool *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_to_boolean(js__value_from_abi(value));

  return 0;
}

int
js_get_value_int32(js_env_t *env, js_value_t *value, int32_t *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_as_int32(js__value_from_abi(value));

  return 0;
}

int
js_get_value_uint32(js_env_t *env, js_value_t *value, uint32_t *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_as_uint32(js__value_from_abi(value));

  return 0;
}

int
js_get_value_int64(js_env_t *env, js_value_t *value, int64_t *result) {
  // Allow continuing even with a pending exception

  *result = (int64_t) jerry_value_as_number(js__value_from_abi(value));

  return 0;
}

int
js_get_value_double(js_env_t *env, js_value_t *value, double *result) {
  // Allow continuing even with a pending exception

  *result = jerry_value_as_number(js__value_from_abi(value));

  return 0;
}

int
js_get_value_bigint_int64(js_env_t *env, js_value_t *value, int64_t *result, bool *lossless) {
  // Allow continuing even with a pending exception

  // TODO
  abort();

  return 0;
}

int
js_get_value_bigint_uint64(js_env_t *env, js_value_t *value, uint64_t *result, bool *lossless) {
  // Allow continuing even with a pending exception

  // TODO
  abort();

  return 0;
}

int
js_get_value_string_utf8(js_env_t *env, js_value_t *value, utf8_t *str, size_t len, size_t *result) {
  // Allow continuing even with a pending exception

  if (str == NULL) {
    *result = jerry_string_size(js__value_from_abi(value), JERRY_ENCODING_UTF8);
  } else if (len != 0) {
    size_t written = jerry_string_to_buffer(js__value_from_abi(value), JERRY_ENCODING_UTF8, str, len);

    if (written < len) str[written] = '\0';

    if (result) *result = written;
  } else if (result) *result = 0;

  return 0;
}

int
js_get_value_string_utf16le(js_env_t *env, js_value_t *value, utf16_t *str, size_t len, size_t *result) {
  // Allow continuing even with a pending exception

  // TODO
  abort();

  return 0;
}

int
js_get_value_string_latin1(js_env_t *env, js_value_t *value, latin1_t *str, size_t len, size_t *result) {
  // Allow continuing even with a pending exception

  // TODO
  abort();

  return 0;
}

int
js_get_value_external(js_env_t *env, js_value_t *value, void **result) {
  // Allow continuing even with a pending exception

  js_finalizer_t *finalizer = jerry_object_get_native_ptr(js__value_from_abi(value), &js__external);

  *result = finalizer->data;

  return 0;
}

int
js_get_value_date(js_env_t *env, js_value_t *value, double *result) {
  // Allow continuing even with a pending exception

  jerry_value_t number = jerry_value_to_number(js__value_from_abi(value));

  *result = jerry_value_as_number(number);

  jerry_value_free(number);

  return 0;
}

int
js_get_array_length(js_env_t *env, js_value_t *array, uint32_t *result) {
  // Allow continuing even with a pending exception

  *result = jerry_array_length(js__value_from_abi(array));

  return 0;
}

int
js_get_array_elements(js_env_t *env, js_value_t *array, js_value_t **elements, size_t len, size_t offset, uint32_t *result) {
  if (env->exception) return js__error(env);

  uint32_t written = 0;

  env->depth++;

  for (uint32_t i = 0, n = len, j = offset, m = jerry_array_length(js__value_from_abi(array)); i < n && j < m; i++, j++) {
    jerry_value_t value = jerry_object_get_index(js__value_from_abi(array), j);

    if (jerry_value_is_exception(value)) {
      if (env->depth == 1) js__run_microtasks(env);

      env->depth--;

      if (env->depth) {
        env->exception = value;
      } else {
        js__uncaught_exception(env, value);
      }

      return js__error(env);
    }

    elements[i] = js__value_to_abi(value);

    js__attach_to_handle_scope(env, env->scope, elements[i]);

    written++;
  }

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (result) *result = written;

  return 0;
}

int
js_set_array_elements(js_env_t *env, js_value_t *array, const js_value_t *elements[], size_t len, size_t offset) {
  if (env->exception) return js__error(env);

  env->depth++;

  for (uint32_t i = 0, n = len, j = offset; i < n; i++, j++) {
    jerry_value_t exception = jerry_object_set_index(js__value_from_abi(array), j, js__value_from_abi(elements[i]));

    if (jerry_value_is_exception(exception)) {
      if (env->depth == 1) js__run_microtasks(env);

      env->depth--;

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  return 0;
}

int
js_get_prototype(js_env_t *env, js_value_t *object, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(jerry_object_proto(js__value_from_abi(object)));

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_get_property_names(js_env_t *env, js_value_t *object, js_value_t **result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_object_keys(js__value_from_abi(object));

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result == NULL) jerry_value_free(value);
  else {
    *result = js__value_to_abi(value);

    js__attach_to_handle_scope(env, env->scope, *result);
  }

  return 0;
}

int
js_get_filtered_property_names(js_env_t *env, js_value_t *object, js_key_collection_mode_t mode, js_property_filter_t property_filter, js_index_filter_t index_filter, js_key_conversion_mode_t key_conversion, js_value_t **result) {
  if (env->exception) return js__error(env);

  int filter = JERRY_PROPERTY_FILTER_ALL;

  if (mode == js_key_include_prototypes) {
    filter |= JERRY_PROPERTY_FILTER_TRAVERSE_PROTOTYPE_CHAIN;
  }

  if (property_filter & js_property_only_writable) {
    filter |= JERRY_PROPERTY_FILTER_EXCLUDE_NON_WRITABLE;
  }

  if (property_filter & js_property_only_enumerable) {
    filter |= JERRY_PROPERTY_FILTER_EXCLUDE_NON_ENUMERABLE;
  }

  if (property_filter & js_property_only_configurable) {
    filter |= JERRY_PROPERTY_FILTER_EXCLUDE_NON_CONFIGURABLE;
  }

  if (property_filter & js_property_skip_strings) {
    filter |= JERRY_PROPERTY_FILTER_EXCLUDE_STRINGS;
  }

  if (property_filter & js_property_skip_symbols) {
    filter |= JERRY_PROPERTY_FILTER_EXCLUDE_SYMBOLS;
  }

  if (index_filter == js_index_skip_indices) {
    filter |= JERRY_PROPERTY_FILTER_EXCLUDE_INTEGER_INDICES;
  }

  if (key_conversion == js_key_keep_numbers) {
    filter |= JERRY_PROPERTY_FILTER_INTEGER_INDICES_AS_NUMBER;
  }

  env->depth++;

  jerry_value_t value = jerry_object_property_names(js__value_from_abi(object), (jerry_property_filter_t) filter);

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result == NULL) jerry_value_free(value);
  else {
    *result = js__value_to_abi(value);

    js__attach_to_handle_scope(env, env->scope, *result);
  }

  return 0;
}

int
js_get_property(js_env_t *env, js_value_t *object, js_value_t *key, js_value_t **result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_object_get(js__value_from_abi(object), js__value_from_abi(key));

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result == NULL) jerry_value_free(value);
  else {
    *result = js__value_to_abi(value);

    js__attach_to_handle_scope(env, env->scope, *result);
  }

  return 0;
}

int
js_has_property(js_env_t *env, js_value_t *object, js_value_t *key, bool *result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_object_has(js__value_from_abi(object), js__value_from_abi(key));

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result) *result = jerry_value_is_true(value);

  jerry_value_free(value);

  return 0;
}

int
js_has_own_property(js_env_t *env, js_value_t *object, js_value_t *key, bool *result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_object_has_own(js__value_from_abi(object), js__value_from_abi(key));

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result) *result = jerry_value_is_true(value);

  jerry_value_free(value);

  return 0;
}

int
js_set_property(js_env_t *env, js_value_t *object, js_value_t *key, js_value_t *value) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t exception = jerry_object_set(js__value_from_abi(object), js__value_from_abi(key), js__value_from_abi(value));

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(exception)) {
    if (env->depth) {
      env->exception = exception;
    } else {
      js__uncaught_exception(env, exception);
    }

    return js__error(env);
  }

  jerry_value_free(exception);

  return 0;
}

int
js_delete_property(js_env_t *env, js_value_t *object, js_value_t *key, bool *result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_object_delete(js__value_from_abi(object), js__value_from_abi(key));

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result) *result = jerry_value_is_true(value);

  jerry_value_free(value);

  return 0;
}

int
js_get_named_property(js_env_t *env, js_value_t *object, const char *name, js_value_t **result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_object_get_sz(js__value_from_abi(object), name);

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result == NULL) jerry_value_free(value);
  else {
    *result = js__value_to_abi(value);

    js__attach_to_handle_scope(env, env->scope, *result);
  }

  return 0;
}

int
js_has_named_property(js_env_t *env, js_value_t *object, const char *name, bool *result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_object_has_sz(js__value_from_abi(object), name);

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result) *result = jerry_value_is_true(value);

  jerry_value_free(value);

  return 0;
}

int
js_set_named_property(js_env_t *env, js_value_t *object, const char *name, js_value_t *value) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t exception = jerry_object_set_sz(js__value_from_abi(object), name, js__value_from_abi(value));

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(exception)) {
    if (env->depth) {
      env->exception = exception;
    } else {
      js__uncaught_exception(env, exception);
    }

    return js__error(env);
  }

  jerry_value_free(exception);

  return 0;
}

int
js_delete_named_property(js_env_t *env, js_value_t *object, const char *name, bool *result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_object_delete_sz(js__value_from_abi(object), name);

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result) *result = jerry_value_is_true(value);

  jerry_value_free(value);

  return 0;
}

int
js_get_element(js_env_t *env, js_value_t *object, uint32_t index, js_value_t **result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_object_get_index(js__value_from_abi(object), index);

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result == NULL) jerry_value_free(value);
  else {
    *result = js__value_to_abi(value);

    js__attach_to_handle_scope(env, env->scope, *result);
  }

  return 0;
}

int
js_has_element(js_env_t *env, js_value_t *object, uint32_t index, bool *result) {
  if (env->exception) return js__error(env);

  // TODO
  abort();

  return 0;
}

int
js_set_element(js_env_t *env, js_value_t *object, uint32_t index, js_value_t *value) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t exception = jerry_object_set_index(js__value_from_abi(object), index, js__value_from_abi(value));

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(exception)) {
    if (env->depth) {
      env->exception = exception;
    } else {
      js__uncaught_exception(env, exception);
    }

    return js__error(env);
  }

  jerry_value_free(exception);

  return 0;
}

int
js_delete_element(js_env_t *env, js_value_t *object, uint32_t index, bool *result) {
  if (env->exception) return js__error(env);

  env->depth++;

  jerry_value_t value = jerry_object_delete_index(js__value_from_abi(object), index);

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result) *result = jerry_value_is_true(value);

  jerry_value_free(value);

  return 0;
}

int
js_get_string_view(js_env_t *env, js_value_t *string, js_string_encoding_t *encoding, const void **str, size_t *len, js_string_view_t **result) {
  // Allow continuing even with a pending exception

  jerry_size_t view_len = jerry_string_size(js__value_from_abi(string), JERRY_ENCODING_UTF8);

  js_string_view_t *view = malloc(sizeof(js_string_view_t) + view_len + 1);

  view->len = view_len;

  jerry_string_to_buffer(js__value_from_abi(string), JERRY_ENCODING_UTF8, view->value, view_len);

  if (encoding) *encoding = js_utf8;

  if (str) *str = view->value;

  if (len) *len = view->len;

  *result = view;

  return 0;
}

int
js_release_string_view(js_env_t *env, js_string_view_t *view) {
  // Allow continuing even with a pending exception

  free(view);

  return 0;
}

int
js_get_callback_info(js_env_t *env, const js_callback_info_t *info, size_t *argc, js_value_t *argv[], js_value_t **receiver, void **data) {
  // Allow continuing even with a pending exception

  if (argv) {
    size_t i = 0, n = info->argc < *argc ? info->argc : *argc;

    for (; i < n; i++) {
      argv[i] = js__value_to_abi(info->argv[i]);
    }

    n = *argc;

    if (i < n) {
      js_value_t *undefined = js__value_to_abi(jerry_undefined());

      js__attach_to_handle_scope(env, env->scope, undefined);

      for (; i < n; i++) {
        argv[i] = undefined;
      }
    }
  }

  if (argc) *argc = info->argc;

  if (receiver) *receiver = js__value_to_abi(info->info->this_value);

  if (data) *data = info->callback->data;

  return 0;
}

int
js_get_typed_callback_info(const js_typed_callback_info_t *info, js_env_t **env, void **data) {
  // Allow continuing even with a pending exception

  if (env) *env = NULL;

  if (data) *data = NULL;

  return 0;
}

int
js_get_new_target(js_env_t *env, const js_callback_info_t *info, js_value_t **result) {
  // Allow continuing even with a pending exception

  *result = js__value_to_abi(info->info->new_target);

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_get_arraybuffer_info(js_env_t *env, js_value_t *arraybuffer, void **data, size_t *len) {
  // Allow continuing even with a pending exception

  if (data) *data = jerry_arraybuffer_data(js__value_from_abi(arraybuffer));

  if (len) *len = jerry_arraybuffer_size(js__value_from_abi(arraybuffer));

  return 0;
}

int
js_get_sharedarraybuffer_info(js_env_t *env, js_value_t *sharedarraybuffer, void **data, size_t *len) {
  // Allow continuing even with a pending exception

  if (data) *data = jerry_arraybuffer_data(js__value_from_abi(sharedarraybuffer));

  if (len) *len = jerry_arraybuffer_size(js__value_from_abi(sharedarraybuffer));

  return 0;
}

int
js_get_typedarray_info(js_env_t *env, js_value_t *typedarray, js_typedarray_type_t *type, void **data, size_t *len, js_value_t **arraybuffer, size_t *offset) {
  // Allow continuing even with a pending exception

  jerry_length_t byte_offset, byte_len;

  jerry_value_t buffer = jerry_typedarray_buffer(js__value_from_abi(typedarray), &byte_offset, &byte_len);

  if (type) {
    switch (jerry_typedarray_type(js__value_from_abi(typedarray))) {
    case JERRY_TYPEDARRAY_UINT8:
    default:
      *type = js_uint8array;
      break;
    case JERRY_TYPEDARRAY_UINT8CLAMPED:
      *type = js_uint8clampedarray;
      break;
    case JERRY_TYPEDARRAY_INT8:
      *type = js_int8array;
      break;
    case JERRY_TYPEDARRAY_UINT16:
      *type = js_uint16array;
      break;
    case JERRY_TYPEDARRAY_INT16:
      *type = js_int16array;
      break;
    case JERRY_TYPEDARRAY_UINT32:
      *type = js_uint32array;
      break;
    case JERRY_TYPEDARRAY_INT32:
      *type = js_int32array;
      break;
    case JERRY_TYPEDARRAY_FLOAT32:
      *type = js_float32array;
      break;
    case JERRY_TYPEDARRAY_FLOAT64:
      *type = js_float64array;
      break;
    case JERRY_TYPEDARRAY_BIGINT64:
      *type = js_bigint64array;
      break;
    case JERRY_TYPEDARRAY_BIGUINT64:
      *type = js_biguint64array;
      break;
    }
  }

  if (data) *data = jerry_arraybuffer_data(buffer) + byte_offset;

  if (len) *len = jerry_typedarray_length(js__value_from_abi(typedarray));

  if (arraybuffer == NULL) jerry_value_free(buffer);
  else {
    *arraybuffer = js__value_to_abi(buffer);

    js__attach_to_handle_scope(env, env->scope, *arraybuffer);
  }

  if (offset) *offset = byte_offset;

  return 0;
}

int
js_get_dataview_info(js_env_t *env, js_value_t *dataview, void **data, size_t *len, js_value_t **arraybuffer, size_t *offset) {
  // Allow continuing even with a pending exception

  jerry_length_t byte_offset, byte_len;

  jerry_value_t buffer = jerry_dataview_buffer(js__value_from_abi(dataview), &byte_offset, &byte_len);

  if (data) *data = jerry_arraybuffer_data(buffer) + byte_offset;

  if (len) *len = byte_len;

  if (arraybuffer == NULL) jerry_value_free(buffer);
  else {
    *arraybuffer = js__value_to_abi(buffer);

    js__attach_to_handle_scope(env, env->scope, *arraybuffer);
  }

  if (offset) *offset = byte_offset;

  return 0;
}

int
js_call_function(js_env_t *env, js_value_t *receiver, js_value_t *function, size_t argc, js_value_t *const argv[], js_value_t **result) {
  if (env->exception) return js__error(env);

  jerry_value_t *args = malloc(argc * sizeof(jerry_value_t));

  for (size_t i = 0; i < argc; i++) {
    args[i] = js__value_from_abi(argv[i]);
  }

  env->depth++;

  jerry_value_t value = jerry_call(js__value_from_abi(function), js__value_from_abi(receiver), args, argc);

  free(args);

  if (env->depth == 1) js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result == NULL) jerry_value_free(value);
  else {
    *result = js__value_to_abi(value);

    js__attach_to_handle_scope(env, env->scope, *result);
  }

  return 0;
}

int
js_call_function_with_checkpoint(js_env_t *env, js_value_t *receiver, js_value_t *function, size_t argc, js_value_t *const argv[], js_value_t **result) {
  if (env->exception) return js__error(env);

  jerry_value_t *args = malloc(argc * sizeof(jerry_value_t));

  for (size_t i = 0; i < argc; i++) {
    args[i] = js__value_from_abi(argv[i]);
  }

  env->depth++;

  jerry_value_t value = jerry_call(js__value_from_abi(function), js__value_from_abi(receiver), args, argc);

  free(args);

  js__run_microtasks(env);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result == NULL) jerry_value_free(value);
  else {
    *result = js__value_to_abi(value);

    js__attach_to_handle_scope(env, env->scope, *result);
  }

  return 0;
}

int
js_new_instance(js_env_t *env, js_value_t *constructor, size_t argc, js_value_t *const argv[], js_value_t **result) {
  if (env->exception) return js__error(env);

  jerry_value_t *args = malloc(argc * sizeof(jerry_value_t));

  for (size_t i = 0; i < argc; i++) {
    args[i] = js__value_from_abi(argv[i]);
  }

  env->depth++;

  jerry_value_t value = jerry_construct(js__value_from_abi(constructor), args, argc);

  free(args);

  env->depth--;

  if (jerry_value_is_exception(value)) {
    if (env->depth) {
      env->exception = value;
    } else {
      js__uncaught_exception(env, value);
    }

    return js__error(env);
  }

  if (result == NULL) jerry_value_free(value);
  else {
    *result = js__value_to_abi(value);

    js__attach_to_handle_scope(env, env->scope, *result);
  }

  return 0;
}

int
js_create_threadsafe_function(js_env_t *env, js_value_t *function, size_t queue_limit, size_t initial_thread_count, js_finalize_cb finalize_cb, void *finalize_hint, void *context, js_threadsafe_function_cb cb, js_threadsafe_function_t **result) {
  int err;

  err = js_throw_error(env, NULL, "Unsupported operation");
  assert(err == 0);

  return js__error(env);
}

int
js_get_threadsafe_function_context(js_threadsafe_function_t *function, void **result) {
  return -1;
}

int
js_call_threadsafe_function(js_threadsafe_function_t *function, void *data, js_threadsafe_function_call_mode_t mode) {
  return -1;
}

int
js_acquire_threadsafe_function(js_threadsafe_function_t *function) {
  return -1;
}

int
js_release_threadsafe_function(js_threadsafe_function_t *function, js_threadsafe_function_release_mode_t mode) {
  return -1;
}

int
js_ref_threadsafe_function(js_env_t *env, js_threadsafe_function_t *function) {
  int err;

  err = js_throw_error(env, NULL, "Unsupported operation");
  assert(err == 0);

  return js__error(env);
}

int
js_unref_threadsafe_function(js_env_t *env, js_threadsafe_function_t *function) {
  int err;

  err = js_throw_error(env, NULL, "Unsupported operation");
  assert(err == 0);

  return js__error(env);
}

int
js_add_teardown_callback(js_env_t *env, js_teardown_cb callback, void *data) {
  if (env->exception) return js__error(env);

  js_teardown_task_t *task = malloc(sizeof(js_teardown_task_t));

  task->type = js_immediate_teardown;
  task->immediate.cb = callback;
  task->data = data;

  intrusive_list_prepend(&env->teardown_queue.tasks, &task->list);

  return 0;
}

int
js_remove_teardown_callback(js_env_t *env, js_teardown_cb callback, void *data) {
  if (env->exception) return js__error(env);

  if (env->destroying) return 0;

  intrusive_list_for_each(next, &env->teardown_queue.tasks) {
    js_teardown_task_t *task = intrusive_entry(next, js_teardown_task_t, list);

    if (task->type == js_immediate_teardown && task->immediate.cb == callback && task->data == data) {
      intrusive_list_remove(&env->teardown_queue.tasks, &task->list);

      free(task);

      return 0;
    }
  }

  return 0;
}

int
js_add_deferred_teardown_callback(js_env_t *env, js_deferred_teardown_cb callback, void *data, js_deferred_teardown_t **result) {
  if (env->exception) return js__error(env);

  js_teardown_task_t *task = malloc(sizeof(js_teardown_task_t));

  task->type = js_deferred_teardown;
  task->deferred.cb = callback;
  task->deferred.handle.env = env;
  task->data = data;

  intrusive_list_prepend(&env->teardown_queue.tasks, &task->list);

  env->refs++;

  if (result) *result = &task->deferred.handle;

  return 0;
}

int
js_finish_deferred_teardown_callback(js_deferred_teardown_t *handle) {
  // Allow continuing even with a pending exception

  int err;

  js_env_t *env = handle->env;

  intrusive_list_for_each(next, &env->teardown_queue.tasks) {
    js_teardown_task_t *task = intrusive_entry(next, js_teardown_task_t, list);

    if (task->type == js_deferred_teardown && &task->deferred.handle == handle) {
      intrusive_list_remove(&env->teardown_queue.tasks, &task->list);

      if (--env->refs == 0 && env->destroying) {
        err = uv_async_send(&env->teardown);
        assert(err == 0);
      }

      free(task);

      return 0;
    }
  }

  return -1;
}

int
js_throw(js_env_t *env, js_value_t *error) {
  if (env->exception) return js__error(env);

  env->exception = jerry_throw_value(js__value_from_abi(error), false);

  return 0;
}

int
js_vformat(char **result, size_t *size, const char *message, va_list args) {
  va_list args_copy;
  va_copy(args_copy, args);

  int res = vsnprintf(NULL, 0, message, args_copy);

  va_end(args_copy);

  if (res < 0) return res;

  *size = res + 1 /* NULL */;
  *result = malloc(*size);

  va_copy(args_copy, args);

  vsnprintf(*result, *size, message, args_copy);

  va_end(args_copy);

  return 0;
}

int
js_throw_error(js_env_t *env, const char *code, const char *message) {
  if (env->exception) return js__error(env);

  jerry_value_t error = jerry_error_sz(JERRY_ERROR_COMMON, message);

  if (code) {
    jerry_value_t value = jerry_string_sz(code);

    jerry_value_t exception = jerry_object_set_sz(error, "code", value);

    jerry_value_free(value);

    if (jerry_value_is_exception(exception)) {
      jerry_value_free(error);

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  env->exception = jerry_throw_value(error, true);

  return 0;
}

int
js_throw_verrorf(js_env_t *env, const char *code, const char *message, va_list args) {
  size_t len;
  char *formatted;
  js_vformat(&formatted, &len, message, args);

  int err = js_throw_error(env, code, formatted);

  free(formatted);

  return err;
}

int
js_throw_errorf(js_env_t *env, const char *code, const char *message, ...) {
  va_list args;
  va_start(args, message);

  int err = js_throw_verrorf(env, code, message, args);

  va_end(args);

  return err;
}

int
js_throw_type_error(js_env_t *env, const char *code, const char *message) {
  if (env->exception) return js__error(env);

  jerry_value_t error = jerry_error_sz(JERRY_ERROR_TYPE, message);

  if (code) {
    jerry_value_t value = jerry_string_sz(code);

    jerry_value_t exception = jerry_object_set_sz(error, "code", value);

    jerry_value_free(value);

    if (jerry_value_is_exception(exception)) {
      jerry_value_free(error);

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  env->exception = jerry_throw_value(error, true);

  return 0;
}

int
js_throw_type_verrorf(js_env_t *env, const char *code, const char *message, va_list args) {
  size_t len;
  char *formatted;
  js_vformat(&formatted, &len, message, args);

  int err = js_throw_type_error(env, code, formatted);

  free(formatted);

  return err;
}

int
js_throw_type_errorf(js_env_t *env, const char *code, const char *message, ...) {
  va_list args;
  va_start(args, message);

  int err = js_throw_type_verrorf(env, code, message, args);

  va_end(args);

  return err;
}

int
js_throw_range_error(js_env_t *env, const char *code, const char *message) {
  if (env->exception) return js__error(env);

  jerry_value_t error = jerry_error_sz(JERRY_ERROR_RANGE, message);

  if (code) {
    jerry_value_t value = jerry_string_sz(code);

    jerry_value_t exception = jerry_object_set_sz(error, "code", value);

    jerry_value_free(value);

    if (jerry_value_is_exception(exception)) {
      jerry_value_free(error);

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  env->exception = jerry_throw_value(error, true);

  return 0;
}

int
js_throw_range_verrorf(js_env_t *env, const char *code, const char *message, va_list args) {
  size_t len;
  char *formatted;
  js_vformat(&formatted, &len, message, args);

  int err = js_throw_range_error(env, code, formatted);

  free(formatted);

  return err;
}

int
js_throw_range_errorf(js_env_t *env, const char *code, const char *message, ...) {
  va_list args;
  va_start(args, message);

  int err = js_throw_range_verrorf(env, code, message, args);

  va_end(args);

  return err;
}

int
js_throw_syntax_error(js_env_t *env, const char *code, const char *message) {
  if (env->exception) return js__error(env);

  jerry_value_t error = jerry_error_sz(JERRY_ERROR_SYNTAX, message);

  if (code) {
    jerry_value_t value = jerry_string_sz(code);

    jerry_value_t exception = jerry_object_set_sz(error, "code", value);

    jerry_value_free(value);

    if (jerry_value_is_exception(exception)) {
      jerry_value_free(error);

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  env->exception = jerry_throw_value(error, true);

  return 0;
}

int
js_throw_syntax_verrorf(js_env_t *env, const char *code, const char *message, va_list args) {
  size_t len;
  char *formatted;
  js_vformat(&formatted, &len, message, args);

  int err = js_throw_syntax_error(env, code, formatted);

  free(formatted);

  return err;
}

int
js_throw_syntax_errorf(js_env_t *env, const char *code, const char *message, ...) {
  va_list args;
  va_start(args, message);

  int err = js_throw_syntax_verrorf(env, code, message, args);

  va_end(args);

  return err;
}

int
js_throw_reference_error(js_env_t *env, const char *code, const char *message) {
  if (env->exception) return js__error(env);

  jerry_value_t error = jerry_error_sz(JERRY_ERROR_REFERENCE, message);

  if (code) {
    jerry_value_t value = jerry_string_sz(code);

    jerry_value_t exception = jerry_object_set_sz(error, "code", value);

    jerry_value_free(value);

    if (jerry_value_is_exception(exception)) {
      jerry_value_free(error);

      if (env->depth) {
        env->exception = exception;
      } else {
        js__uncaught_exception(env, exception);
      }

      return js__error(env);
    }

    jerry_value_free(exception);
  }

  env->exception = jerry_throw_value(error, true);

  return 0;
}

int
js_throw_reference_verrorf(js_env_t *env, const char *code, const char *message, va_list args) {
  size_t len;
  char *formatted;
  js_vformat(&formatted, &len, message, args);

  int err = js_throw_reference_error(env, code, formatted);

  free(formatted);

  return err;
}

int
js_throw_reference_errorf(js_env_t *env, const char *code, const char *message, ...) {
  va_list args;
  va_start(args, message);

  int err = js_throw_reference_verrorf(env, code, message, args);

  va_end(args);

  return err;
}

int
js_is_exception_pending(js_env_t *env, bool *result) {
  // Allow continuing even with a pending exception

  *result = env->exception != 0;

  return 0;
}

int
js_get_and_clear_last_exception(js_env_t *env, js_value_t **result) {
  // Allow continuing even with a pending exception

  js_value_t *exception;

  if (env->exception) {
    exception = js__value_to_abi(jerry_exception_value(env->exception, true));
  } else {
    exception = js__value_to_abi(jerry_undefined());
  }

  env->exception = 0;

  *result = exception;

  js__attach_to_handle_scope(env, env->scope, *result);

  return 0;
}

int
js_fatal_exception(js_env_t *env, js_value_t *error) {
  // Allow continuing even with a pending exception

  jerry_value_free(env->exception);

  env->exception = 0;

  js__uncaught_exception(env, js__value_from_abi(error));

  return 0;
}

int
js_terminate_execution(js_env_t *env) {
  // Allow continuing even with a pending exception

  jerry_value_free(env->exception);

  env->exception = jerry_throw_abort(jerry_error_sz(JERRY_ERROR_COMMON, "Execution terminated"), true);

  return 0;
}

int
js_adjust_external_memory(js_env_t *env, int64_t change_in_bytes, int64_t *result) {
  // Allow continuing even with a pending exception

  env->external_memory += change_in_bytes;

  if (result) *result = env->external_memory;

  return 0;
}

int
js_request_garbage_collection(js_env_t *env) {
  // Allow continuing even with a pending exception

  jerry_heap_gc(JERRY_GC_PRESSURE_LOW);

  return 0;
}

int
js_get_heap_statistics(js_env_t *env, js_heap_statistics_t *result) {
  int err;

  jerry_heap_stats_t stats;
  err = jerry_heap_stats(&stats);

  if (err != 1) {
    err = js_throw_error(env, NULL, "Unable to get heap statistics");
    assert(err == 0);

    return js__error(env);
  }

  result->total_heap_size = stats.size;
  result->used_heap_size = stats.allocated_bytes;

  if (result->version >= 1) {
    result->external_memory = env->external_memory;
  }

  return 0;
}

int
js_create_inspector(js_env_t *env, js_inspector_t **result) {
  int err;

  err = js_throw_error(env, NULL, "Unsupported operation");
  assert(err == 0);

  return js__error(env);
}

int
js_destroy_inspector(js_env_t *env, js_inspector_t *inspector) {
  int err;

  err = js_throw_error(env, NULL, "Unsupported operation");
  assert(err == 0);

  return js__error(env);
}

int
js_on_inspector_response(js_env_t *env, js_inspector_t *inspector, js_inspector_message_cb cb, void *data) {
  return 0;
}

int
js_on_inspector_paused(js_env_t *env, js_inspector_t *inspector, js_inspector_paused_cb cb, void *data) {
  return 0;
}

int
js_connect_inspector(js_env_t *env, js_inspector_t *inspector) {
  int err;

  err = js_throw_error(env, NULL, "Unsupported operation");
  assert(err == 0);

  return js__error(env);
}

int
js_send_inspector_request(js_env_t *env, js_inspector_t *inspector, js_value_t *message) {
  int err;

  err = js_throw_error(env, NULL, "Unsupported operation");
  assert(err == 0);

  return js__error(env);
}
