/*
 *  Copyright (c) 2009 Facebook
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  Fork edition by Sensiolabs
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef linux
/* To enable CPU_ZERO and CPU_SET, etc.     */
# define _GNU_SOURCE
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "Zend/zend_extensions.h"
#include "ext/standard/php_rand.h"
#include "php_uprofiler.h"
#include "ext/standard/basic_functions.h"
#if IS_PHP_53
#include "main/SAPI.h"
#endif

/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_uprofiler_enable, 0, 0, 0)
  ZEND_ARG_INFO(0, flags)
  ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_uprofiler_disable, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_uprofiler_sample_enable, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_uprofiler_sample_disable, 0)
ZEND_END_ARG_INFO()

#if IS_PHP_53
ZEND_BEGIN_ARG_INFO(arginfo_http_response_code, 0)
	ZEND_ARG_INFO(0, response_code)
ZEND_END_ARG_INFO()
#endif
/* }}} */

/**
 * *********************
 * PHP EXTENSION GLOBALS
 * *********************
 */
/* List of functions implemented/exposed by uprofiler */
zend_function_entry uprofiler_functions[] = {
  PHP_FE(uprofiler_enable, arginfo_uprofiler_enable)
  PHP_FE(uprofiler_disable, arginfo_uprofiler_disable)
#if IS_PHP_53
  PHP_FE(http_response_code, arginfo_http_response_code)
#endif
  PHP_FE(uprofiler_sample_enable, arginfo_uprofiler_sample_enable)
  PHP_FE(uprofiler_sample_disable, arginfo_uprofiler_sample_disable)
  PHP_FE_END
};

/* Callback functions for the uprofiler extension */
zend_module_entry uprofiler_module_entry = {
  STANDARD_MODULE_HEADER,
  "uprofiler",                        /* Name of the extension */
  uprofiler_functions,                /* List of functions exposed */
  PHP_MINIT(uprofiler),               /* Module init callback */
  PHP_MSHUTDOWN(uprofiler),           /* Module shutdown callback */
  PHP_RINIT(uprofiler),               /* Request init callback */
  PHP_RSHUTDOWN(uprofiler),           /* Request shutdown callback */
  PHP_MINFO(uprofiler),               /* Module info callback */
  PHP_UPROFILER_VERSION,
  STANDARD_MODULE_PROPERTIES
};

PHP_INI_BEGIN()

/* output directory:
 * Currently this is not used by the extension itself.
 * But some implementations of iXHProfRuns interface might
 * choose to save/restore XHProf profiler runs in the
 * directory specified by this ini setting.
 */
PHP_INI_ENTRY("uprofiler.output_dir", "", PHP_INI_ALL, NULL)

PHP_INI_END()

/* Init module */
ZEND_GET_MODULE(uprofiler)

static inline void begin_profiling(hp_entry_t **entries, up_function *upfunction)
{
	char profile_curr = 0;
	uint8 hash_code   = hp_inline_hash(upfunction->name);
	profile_curr      = !hp_ignore_entry(hash_code, upfunction->name);
	if (profile_curr) {
		hp_entry_t *cur_entry = hp_fast_alloc_hprof_entry();
		cur_entry->hash_code = hash_code;
		cur_entry->function = upfunction;
		cur_entry->prev_hprof = *entries;
		hp_mode_common_beginfn(entries, cur_entry TSRMLS_CC);
		hp_globals.mode_cb.begin_fn_cb(entries, cur_entry TSRMLS_CC);
		*entries = cur_entry;
	} else {
		up_function_free(upfunction);
	}
}

static inline void end_profiling(hp_entry_t **entries)
{
	if (*entries) {
		hp_entry_t *cur_entry;
		hp_globals.mode_cb.end_fn_cb(entries TSRMLS_CC);
		cur_entry = *entries;
		hp_mode_common_endfn(entries, cur_entry TSRMLS_CC);
		*entries = (*entries)->prev_hprof;
		if (cur_entry->function) {
			up_function_free(cur_entry->function);
		}
		memset(cur_entry, 0, sizeof(*cur_entry));
		cur_entry->prev_hprof = hp_globals.entry_free_list;
		hp_globals.entry_free_list = cur_entry;
	}
}

static void up_function_free(up_function *f)
{
	if (f->name) {
		efree(f->name);
	}
	efree(f);
}

static up_function *up_function_create(char *function_name)
{
	up_function *f = NULL;

	f = ecalloc(1, sizeof(up_function));
	if (function_name) {
		f->name = function_name;
	}

	return f;
}

/**
 * **********************************
 * PHP EXTENSION FUNCTION DEFINITIONS
 * **********************************
 */

/**
 * Start Uprofiler profiling in hierarchical mode.
 *
 * @param  long $flags  flags for hierarchical mode
 * @return void
 * @author kannan
 */
PHP_FUNCTION(uprofiler_enable) {
  long  uprofiler_flags = 0;                                    /* Uprofiler flags */
  zval *optional_array = NULL;         /* optional array arg: for future use */

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            "|lz", &uprofiler_flags, &optional_array) == FAILURE) {
    return;
  }

  if(hp_globals.enabled == 1) {
	  php_error(E_NOTICE, "uprofiler is already enabled");
	  RETURN_FALSE;
  }

  if (uprofiler_flags < 0) {
	  php_error(E_WARNING, "Can't use negative values for $flags, assuming 0");
	  uprofiler_flags = 0;
  }

  if (EXPECTED(hp_begin(UPROFILER_MODE_HIERARCHICAL, uprofiler_flags, optional_array TSRMLS_CC) == SUCCESS)) {
	  RETURN_TRUE;
  }

  RETURN_FALSE;
}

/**
 * Stops Uprofiler from profiling in hierarchical mode anymore and returns the
 * profile info.
 *
 * @param  void
 * @return array  hash-array of Uprofiler's profile info
 * @author kannan, hzhao
 */
PHP_FUNCTION(uprofiler_disable) {
  if (hp_globals.enabled) {
    hp_stop(TSRMLS_C);
    RETURN_ZVAL(hp_globals.stats_count, 1, 0);
  }
}

/**
 * Start Uprofiler profiling in sampling mode.
 *
 * @return void
 * @author cjiang
 */
PHP_FUNCTION(uprofiler_sample_enable) {
	RETVAL_FALSE;

	if(hp_globals.enabled == 1) {
		php_error(E_NOTICE, "uprofiler is already enabled");
		return;
	}

	if (EXPECTED(hp_begin(UPROFILER_MODE_SAMPLED, 0 /* Uprofiler flags */, NULL TSRMLS_CC) == SUCCESS)) {
		RETURN_TRUE;
	}
}

/**
 * Stops Uprofiler from profiling in sampling mode anymore and returns the profile
 * info.
 *
 * @param  void
 * @return array  hash-array of Uprofiler's profile info
 * @author cjiang
 */
PHP_FUNCTION(uprofiler_sample_disable) {
  if (hp_globals.enabled) {
    hp_stop(TSRMLS_C);
    RETURN_ZVAL(hp_globals.stats_count, 1, 0);
  }
}

#if IS_PHP_53
PHP_FUNCTION(http_response_code)
{
    long response_code = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &response_code) == FAILURE) {
        return;
    }

    if (response_code)
    {
        long old_response_code;

        old_response_code = SG(sapi_headers).http_response_code;
        SG(sapi_headers).http_response_code = response_code;

        if (old_response_code) {
            RETURN_LONG(old_response_code);
        }

        RETURN_TRUE;
    }

    if (!SG(sapi_headers).http_response_code) {
        RETURN_FALSE;
    }

    RETURN_LONG(SG(sapi_headers).http_response_code);
}
#endif

/**
 * Module init callback.
 *
 * @author cjiang
 */
PHP_MINIT_FUNCTION(uprofiler)
{

	REGISTER_INI_ENTRIES();

  hp_register_constants(INIT_FUNC_ARGS_PASSTHRU);

  /* Get the number of available logical CPUs. */
#ifndef PHP_WIN32
  hp_globals.cpu_num = sysconf(_SC_NPROCESSORS_CONF);
#else
  GetSystemInfo(&sysinfo);
  hp_globals.cpu_num = sysinfo.dwNumberOfProcessors;
#endif

	if (UNEXPECTED(get_all_cpu_frequencies() == FAILURE)) {
		return FAILURE;
	}

	if (!BG(mt_rand_is_seeded)) {
		php_mt_srand(GENERATE_SEED() TSRMLS_CC);
	}

	return SUCCESS;
}

/**
 * Module shutdown callback.
 */
PHP_MSHUTDOWN_FUNCTION(uprofiler) {
  /* Make sure cpu_frequencies is free'ed. */
  clear_frequencies();

  UNREGISTER_INI_ENTRIES();

  return SUCCESS;
}

PHP_RINIT_FUNCTION(uprofiler)
{
	return SUCCESS;
}

/**
 * Request shutdown callback. Stop profiling and return.
 */
PHP_RSHUTDOWN_FUNCTION(uprofiler) {
    hp_stop();
	hp_end(TSRMLS_C);
  /* free any remaining items in the free list */
  hp_free_the_free_list();

  return SUCCESS;
}

/**
 * Module info callback. Returns the uprofiler version.
 */
PHP_MINFO_FUNCTION(uprofiler)
{
  char buf[SCRATCH_BUF_LEN];
  char tmp[SCRATCH_BUF_LEN];
  size_t i, len;

  php_info_print_table_start();
  php_info_print_table_row(2, "uprofiler", "enabled");
  php_info_print_table_header(2, "uprofiler", PHP_UPROFILER_VERSION);
  len = (size_t)snprintf(buf, SCRATCH_BUF_LEN, "%d", hp_globals.cpu_num);
  buf[len] = 0;
  php_info_print_table_row(2, "CPU num", buf);
  /* information about the cpu the process is bound to */
  len = (size_t)snprintf(tmp, SCRATCH_BUF_LEN, "%d", hp_globals.cur_cpu_id);
  tmp[len] = 0;
  php_info_print_table_row(2, "process bound to CPU", tmp);

  if (hp_globals.cpu_frequencies) {
    /* Print available cpu frequencies here. */
    php_info_print_table_header(2, "CPU logical id", " Clock Rate (MHz) ");
    for (i = 0; i < (size_t)hp_globals.cpu_num; ++i) {
      len = (size_t)snprintf(buf, SCRATCH_BUF_LEN, " CPU %zd ", i);
      buf[len] = 0;
      len = (size_t)snprintf(tmp, SCRATCH_BUF_LEN, "%-.0f", hp_globals.cpu_frequencies[i]);
      tmp[len] = 0;
      php_info_print_table_row(2, buf, tmp);
    }
  }

  php_info_print_table_end();
}


/**
 * ***************************************************
 * COMMON HELPER FUNCTION DEFINITIONS AND LOCAL MACROS
 * ***************************************************
 */

static void hp_register_constants(INIT_FUNC_ARGS) {
  REGISTER_LONG_CONSTANT("UPROFILER_FLAGS_NO_BUILTINS",
		  	  	  	  	 UPROFILER_FLAGS_NO_BUILTINS,
                         CONST_CS | CONST_PERSISTENT);

  REGISTER_LONG_CONSTANT("UPROFILER_FLAGS_CPU",
		                 UPROFILER_FLAGS_CPU,
                         CONST_CS | CONST_PERSISTENT);

  REGISTER_LONG_CONSTANT("UPROFILER_FLAGS_MEMORY",
		  	  	  	  	 UPROFILER_FLAGS_MEMORY,
                         CONST_CS | CONST_PERSISTENT);

  REGISTER_LONG_CONSTANT("UPROFILER_FLAGS_FUNCTION_INFOS",
		  	  	  	  	 UPROFILER_FLAGS_FUNCTION_INFOS,
                         CONST_CS | CONST_PERSISTENT);
}

/**
 * A hash function to calculate a 8-bit hash code for a function name.
 * This is based on a small modification to 'zend_inline_hash_func' by summing
 * up all bytes of the ulong returned by 'zend_inline_hash_func'.
 *
 * @param str, char *, string to be calculated hash code for.
 *
 * @author cjiang
 */
static inline uint8 hp_inline_hash(char * str) {
  ulong h = 5381;
  uint i = 0;
  uint8 res = 0;

  while (*str) {
    h += (h << 5);
    h ^= (ulong) *str++;
  }

  for (i = 0; i < sizeof(ulong); i++) {
    res += ((uint8 *)&h)[i];
  }
  return res;
}

/**
 * Parse the list of ignored functions from the zval argument.
 *
 * @author mpal
 */
static void hp_get_ignored_functions_from_arg(zval *args) {
  if (args) {
    zval **zresult = NULL;
    if (Z_TYPE_P(args) == IS_ARRAY) {
    	if (zend_hash_find(Z_ARRVAL_P(args), "ignored_functions", sizeof("ignored_functions"), (void**)&zresult) == FAILURE) {
    		goto nullify_functions_names;
    	}
    	hp_globals.ignored_function_names = hp_strings_in_zval(*zresult);
    } else {
    	goto nullify_functions_names;
    }
  } else {
nullify_functions_names:
	  hp_globals.ignored_function_names = NULL;
  }
}

/**
 * Initialize filter for ignored functions using bit vector.
 *
 * @author mpal
 */
static void hp_ignored_functions_filter_init() {
  if (hp_globals.ignored_function_names != NULL) {
    size_t i = 0;
    for(; hp_globals.ignored_function_names[i] != NULL; i++) {
      char *str  = hp_globals.ignored_function_names[i];
      uint8 hash = hp_inline_hash(str);
      int   idx  = INDEX_2_BYTE(hash);
      hp_globals.ignored_function_filter[idx] |= INDEX_2_BIT(hash);
    }
  }
}

/**
 * Check if function collides in filter of functions to be ignored.
 *
 * @author mpal
 */
int hp_ignored_functions_filter_collision(uint8 hash) {
  uint8 mask = INDEX_2_BIT(hash);
  return hp_globals.ignored_function_filter[INDEX_2_BYTE(hash)] & mask;
}

/**
 * Initialize profiler state
 *
 * @author kannan, veeve
 */
int hp_init_profiler_state(char level TSRMLS_DC) {
  /* Setup globals */
  if (!hp_globals.ever_enabled) {
    hp_globals.ever_enabled  = 1;
    hp_globals.entries       = NULL;
  }
  hp_globals.profiler_level = level;

  /* bind to a random cpu so that we can use rdtsc instruction. */
  if (UNEXPECTED(bind_to_cpu((int) (php_rand() % (long)hp_globals.cpu_num)) == FAILURE)) {
	  return FAILURE;
  }

  /* Call current mode's init cb */
  hp_globals.mode_cb.init_cb(TSRMLS_C);

  /* Set up filter of functions which may be ignored during profiling */
  hp_ignored_functions_filter_init();

  /* Init stats_count */
    if (hp_globals.stats_count) {
      zval_dtor(hp_globals.stats_count);
      FREE_ZVAL(hp_globals.stats_count);
    }
    MAKE_STD_ZVAL(hp_globals.stats_count);
    array_init(hp_globals.stats_count);

    return SUCCESS;
}

/**
 * Cleanup profiler state
 *
 * @author kannan, veeve
 */
static void hp_clean_profiler_state(TSRMLS_D) {
  /* Call current mode's exit cb */
  hp_globals.mode_cb.exit_cb(TSRMLS_C);

  /* Clear globals */
  if (hp_globals.stats_count) {
    zval_dtor(hp_globals.stats_count);
    FREE_ZVAL(hp_globals.stats_count);
    hp_globals.stats_count = NULL;
  }
  hp_globals.entries = NULL;
  hp_globals.profiler_level = 1;
  hp_globals.ever_enabled = 0;

  /* Delete the array storing ignored function names */
  CLEAR_IGNORED_FUNC_NAMES;
}

/**
 * Returns formatted function name
 *
 * @param  entry        hp_entry
 * @param  result_buf   ptr to result buf
 * @param  result_len   max size of result buf
 * @return total size of the function name returned in result_buf
 * @author veeve
 */
static size_t hp_get_entry_name(hp_entry_t  *entry,
                         char           *result_buf,
                         size_t          result_len) {

  /* Validate result_len */
  if (result_len <= 1) {
    /* Insufficient result_bug. Bail! */
    return 0;
  }

  /* Add '@recurse_level' if required */
  /* NOTE:  Dont use snprintf's return val as it is compiler dependent */
  if (entry->rlvl_hprof) {
    snprintf(result_buf, result_len,
             "%s@%d",
             entry->function->name, entry->rlvl_hprof);
  }
  else {
    snprintf(result_buf, result_len,
             "%s",
             entry->function->name);
  }

  /* Force null-termination at MAX */
  result_buf[result_len - 1] = 0;

  return strlen(result_buf);
}

/**
 * Check if this entry should be ignored, first with a conservative Bloomish
 * filter then with an exact check against the function names.
 *
 * @author mpal
 */
static int  hp_ignore_entry_work(uint8 hash_code, char *curr_func) {
  int ignore = 0;
  if (hp_ignored_functions_filter_collision(hash_code)) {
    size_t i = 0;
    for (; hp_globals.ignored_function_names[i] != NULL; i++) {
      char *name = hp_globals.ignored_function_names[i];
      if ( !strcmp(curr_func, name)) {
        ignore++;
        break;
      }
    }
  }

  return ignore;
}

static inline char  hp_ignore_entry(uint8 hash_code, char *curr_func) {
  /* First check if ignoring functions is enabled */
  return hp_globals.ignored_function_names != NULL &&
         hp_ignore_entry_work(hash_code, curr_func);
}

/**
 * Build a caller qualified name for a callee.
 *
 * For example, if A() is caller for B(), then it returns "A==>B".
 * Recursive invokations are denoted with @<n> where n is the recursion
 * depth.
 *
 * For example, "foo==>foo@1", and "foo@2==>foo@3" are examples of direct
 * recursion. And  "bar==>foo@1" is an example of an indirect recursive
 * call to foo (implying the foo() is on the call stack some levels
 * above).
 *
 * @author kannan, veeve
 */
static size_t hp_get_function_stack(hp_entry_t *entry,
                             int            level,
                             char          *result_buf,
                             size_t         result_len) {
  size_t         len = 0;

  /* End recursion if we dont need deeper levels or we dont have any deeper
   * levels */
  if (!entry->prev_hprof || (level <= 1)) {
    return hp_get_entry_name(entry, result_buf, result_len);
  }

  /* Take care of all ancestors first */
  len = hp_get_function_stack(entry->prev_hprof,
                              level - 1,
                              result_buf,
                              result_len);

  /* Append the delimiter */
# define    HP_STACK_DELIM        "==>"
# define    HP_STACK_DELIM_LEN    (sizeof(HP_STACK_DELIM) - 1)

  if (result_len < (len + HP_STACK_DELIM_LEN)) {
    /* Insufficient result_buf. Bail out! */
    return len;
  }

  /* Add delimiter only if entry had ancestors */
  if (len) {
    strncat(result_buf + len,
            HP_STACK_DELIM,
            result_len - len);
    len += HP_STACK_DELIM_LEN;
  }

# undef     HP_STACK_DELIM_LEN
# undef     HP_STACK_DELIM

  /* Append the current function name */
  return len + hp_get_entry_name(entry,
                                 result_buf + len,
                                 result_len - len);
}

/**
 * Takes an input of the form /a/b/c/d/foo.php and returns
 * a pointer to one-level directory and basefile name
 * (d/foo.php) in the same string.
 */
static const char *hp_get_base_filename(const char *filename) {
  const char *ptr;
  short   found = 0;

  if (!filename)
    return "";

  /* reverse search for "/" and return a ptr to the next char */
  for (ptr = filename + strlen(filename) - 1; ptr >= filename; ptr--) {
    if (*ptr == '/') {
      found++;
    }
    if (found == 2) {
      return ptr + 1;
    }
  }

  /* no "/" char found, so return the whole string */
  return filename;
}

/**
 * Get the name of the current function. The name is qualified with
 * the class name if the function is in a class.
 *
 * @author kannan, hzhao
 */
static up_function *hp_get_function_name(void) {
  zend_execute_data *data;
  const char        *func = NULL;
  const char        *cls = NULL;
  zend_uint         cls_name_length;
  up_function       *ret = NULL;
  size_t            len;
  zend_function     *curr_func = NULL;

  TSRMLS_FETCH();

  data = EG(current_execute_data);

  if (data) {
    /* shared meta data for function on the call stack */
    curr_func = data->function_state.function;

    /* extract function name from the meta info */
    func = curr_func->common.function_name;

    ret = up_function_create(NULL);

    if (func) {
      /* previously, the order of the tests in the "if" below was
       * flipped, leading to incorrect function names in profiler
       * reports. When a method in a super-type is invoked the
       * profiler should qualify the function name with the super-type
       * class name (not the class name based on the run-time type
       * of the object.
       */
      if (curr_func->common.scope) {
        cls = curr_func->common.scope->name;
        cls_name_length = curr_func->common.scope->name_length;
      } else if (data->object) {
        cls = Z_OBJCE(*data->object)->name;
        cls_name_length = Z_OBJCE(*data->object)->name_length;
      }

      if (cls) {
        if (curr_func->common.fn_flags & ZEND_ACC_CLOSURE) {
            spprintf(&ret->name, 0, "%s::{closure}/%d-%d", cls, curr_func->op_array.line_start, curr_func->op_array.line_end);
        } else {
            spprintf(&ret->name, 0, "%s::%s", cls, func);
        }
      } else {
          if (curr_func->common.fn_flags & ZEND_ACC_CLOSURE) {
              spprintf(&ret->name, 0, "{closure}::%s/%d-%d", curr_func->op_array.filename, curr_func->op_array.line_start, curr_func->op_array.line_end);
          } else {
              spprintf(&ret->name, 0, "%s", func);
          }
      }

      ret->zend_function_type = curr_func->type;

      if ((hp_globals.uprofiler_flags & UPROFILER_FLAGS_FUNCTION_INFOS) && (ret->zend_function_type & ZEND_USER_FUNCTION)) {
    	  ret->filename = curr_func->op_array.filename;
    	  ret->lineno   = curr_func->op_array.line_start;
      }

    } else {
      /* we are dealing with a special directive/function like
       * include, eval, etc.
       * We'll add the filename as part of the function
       * name to make the reports more useful. So rather than just "include"
       * you'll see something like "run_init::foo.php" in your reports.
       */
      const char *filename = NULL;
      size_t   len;
      filename = hp_get_base_filename((curr_func->op_array).filename);
      len      = sizeof("run_init::") + strlen(filename);
      spprintf(&ret->name, len, "run_init::%s", filename);
    }
  }
  return ret;
}

/**
 * Free any items in the free list.
 */
static void hp_free_the_free_list() {
  hp_entry_t *p = hp_globals.entry_free_list;
  hp_entry_t *cur;

  while (p) {
    cur = p;
    p = p->prev_hprof;
    efree(cur);
  }
  hp_globals.entry_free_list = NULL;
}

/**
 * Fast allocate a hp_entry_t structure. Picks one from the
 * free list if available, else does an actual allocate.
 *
 * Doesn't bother initializing allocated memory.
 *
 * @author kannan
 */
static hp_entry_t *hp_fast_alloc_hprof_entry() {
  hp_entry_t *p;

  p = hp_globals.entry_free_list;

  if (p) {
    hp_globals.entry_free_list = p->prev_hprof;
    return p;
  } else {
    return (hp_entry_t *)ecalloc(1, sizeof(hp_entry_t));
  }
}

/**
 * Increment the count of the given stat with the given count
 * If the stat was not set before, inits the stat to the given count
 *
 * @param  zval *counts   Zend hash table pointer
 * @param  char *name     Name of the stat
 * @param  long  count    Value of the stat to incr by
 * @return void
 * @author kannan
 */
static void hp_inc_count(zval *counts, char *name, long count TSRMLS_DC) {
  HashTable *ht;
  void *data;

  if (!counts) return;
  ht = HASH_OF(counts);
  if (!ht) return;

  if (zend_hash_find(ht, name, strlen(name) + 1, &data) == SUCCESS) {
    ZVAL_LONG(*(zval**)data, Z_LVAL_PP((zval**)data) + count);
  } else {
    add_assoc_long(counts, name, count);
  }
}

/**
 * Looksup the hash table for the given symbol
 * Initializes a new array() if symbol is not present
 *
 * @author kannan, veeve
 */
static zval * hp_hash_lookup(char *symbol  TSRMLS_DC) {
  HashTable   *ht;
  void        *data;
  zval        *counts = (zval *) 0;

  /* Bail if something is goofy */
  if (!hp_globals.stats_count || !(ht = HASH_OF(hp_globals.stats_count))) {
    return (zval *) 0;
  }

  /* Lookup our hash table */
  if (zend_hash_find(ht, symbol, strlen(symbol) + 1, &data) == SUCCESS) {
    /* Symbol already exists */
    counts = *(zval **) data;
  }
  else {
    /* Add symbol to hash table */
    MAKE_STD_ZVAL(counts);
    array_init(counts);
    add_assoc_zval(hp_globals.stats_count, symbol, counts);
  }

  return counts;
}

/**
 * Truncates the given timeval to the nearest slot begin, where
 * the slot size is determined by intr
 *
 * @param  tv       Input timeval to be truncated in place
 * @param  intr     Time interval in microsecs - slot width
 * @return void
 * @author veeve
 */
static void hp_trunc_time(struct timeval *tv,
                   uint64          intr) {
  uint64 time_in_micro;

  /* Convert to microsecs and trunc that first */
  time_in_micro = (tv->tv_sec * 1000000) + tv->tv_usec;
  time_in_micro /= intr;
  time_in_micro *= intr;

  /* Update tv Note(bcarl): added explicit typecasting (long) warning C4244 */
  tv->tv_sec  = (long)(time_in_micro / 1000000);
  tv->tv_usec = (long)(time_in_micro % 1000000);
}

/**
 * Sample the stack. Add it to the stats_count global.
 *
 * @param  tv            current time
 * @param  entries       func stack as linked list of hp_entry_t
 * @return void
 * @author veeve
 */
static void hp_sample_stack(hp_entry_t  **entries  TSRMLS_DC) {
  char key[SCRATCH_BUF_LEN];
  char symbol[SCRATCH_BUF_LEN * 1000];

  /* Build key */
  snprintf(key, sizeof(key),
           "%d.%06d",
           hp_globals.last_sample_time.tv_sec,
           hp_globals.last_sample_time.tv_usec);

  /* Init stats in the global stats_count hashtable */
  hp_get_function_stack(*entries,
                        INT_MAX,
                        symbol,
                        sizeof(symbol));

  add_assoc_string(hp_globals.stats_count,
                   key,
                   symbol,
                   1);
  return;
}

/**
 * Checks to see if it is time to sample the stack.
 * Calls hp_sample_stack() if its time.
 *
 * @param  entries        func stack as linked list of hp_entry_t
 * @param  last_sample    time the last sample was taken
 * @param  sampling_intr  sampling interval in microsecs
 * @return void
 * @author veeve
 */
static void hp_sample_check(hp_entry_t **entries  TSRMLS_DC) {
  /* Validate input */
  if (!entries || !(*entries)) {
    return;
  }

  /* See if its time to sample.  While loop is to handle a single function
   * taking a long time and passing several sampling intervals. */
  while ((cycle_timer() - hp_globals.last_sample_tsc)
         > hp_globals.sampling_interval_tsc) {

    /* bump last_sample_tsc */
    hp_globals.last_sample_tsc += hp_globals.sampling_interval_tsc;

    /* bump last_sample_time - HAS TO BE UPDATED BEFORE calling hp_sample_stack */
    incr_us_interval(&hp_globals.last_sample_time, UPROFILER_SAMPLING_INTERVAL);

    /* sample the stack */
    hp_sample_stack(entries  TSRMLS_CC);
  }

  return;
}


/**
 * ***********************
 * High precision timer related functions.
 * ***********************
 */

/**
 * Get time stamp counter (TSC) value via 'rdtsc' instruction.
 *
 * @return 64 bit unsigned integer
 * @author cjiang
 */
static inline uint64 cycle_timer() {
#if defined(PHP_WIN32) && defined(_WIN64)
  return __rdtsc();
#else
  uint32 __a,__d;
  uint64 val;

# ifdef PHP_WIN32
  __asm {
    cpuid
    rdtsc
    mov __a, eax
    mov __d, edx
  }
# else
  asm volatile("rdtsc" : "=a" (__a), "=d" (__d));
# endif

  (val) = ((uint64)__a) | (((uint64)__d)<<32);
  return val;
#endif
}

/**
 * Bind the current process to a specified CPU. This function is to ensure that
 * the OS won't schedule the process to different processors, which would make
 * values read by rdtsc unreliable.
 *
 * @param uint32 cpu_id, the id of the logical cpu to be bound to.
 * @return int, 0 on success, and -1 on failure.
 *
 * @author cjiang
 */
static int bind_to_cpu(uint32 cpu_id) {
  cpu_set_t new_mask;

  CPU_ZERO(&new_mask);
  CPU_SET(cpu_id, &new_mask);

  if (GET_AFFINITY(0, sizeof(cpu_set_t), &hp_globals.cpu_prev_mask) < 0) {
	  return FAILURE;
  }
  if (SET_AFFINITY(0, sizeof(cpu_set_t), &new_mask) < 0) {
    return FAILURE;
  }

  /* record the cpu_id the process is bound to. */
  hp_globals.cur_cpu_id = cpu_id;

  return SUCCESS;
}

/**
 * Get time delta in microseconds.
 */
static long get_us_interval(struct timeval *start, struct timeval *end) {
  return (((end->tv_sec - start->tv_sec) * 1000000)
          + (end->tv_usec - start->tv_usec));
}

/**
 * Incr time with the given microseconds.
 */
static void incr_us_interval(struct timeval *start, uint64 incr) {
  incr += (start->tv_sec * 1000000 + start->tv_usec);
  start->tv_sec  = (long)(incr/1000000);
  start->tv_usec = (long)(incr%1000000);
  return;
}

/**
 * Convert from TSC counter values to equivalent microseconds.
 *
 * @param uint64 count, TSC count value
 * @param double cpu_frequency, the CPU clock rate (MHz)
 * @return 64 bit unsigned integer
 *
 * @author cjiang
 */
static inline double get_us_from_tsc(uint64 count, double cpu_frequency) {
  return count / cpu_frequency;
}

/**
 * Convert microseconds to equivalent TSC counter ticks
 *
 * @param uint64 microseconds
 * @param double cpu_frequency, the CPU clock rate (MHz)
 * @return 64 bit unsigned integer
 *
 * @author veeve
 */
static inline uint64 get_tsc_from_us(uint64 usecs, double cpu_frequency) {
  return (uint64) (usecs * cpu_frequency);
}

/**
 * This is a microbenchmark to get cpu frequency the process is running on. The
 * returned value is used to convert TSC counter values to microseconds.
 *
 * @return double.
 * @author cjiang
 */
static double get_cpu_frequency() {
  struct timeval start;
  struct timeval end;
  uint64 tsc_start;
  uint64 tsc_end;

  if (gettimeofday(&start, 0)) {
    return 0.0;
  }
  
  tsc_start = cycle_timer();

  /* Sleep for 5 miliseconds. Comparaing with gettimeofday's few microseconds
   * execution time, this should be enough. */
  usleep(5000);
  if (gettimeofday(&end, 0)) {
    return 0.0;
  }
  
  tsc_end = cycle_timer();

  return (tsc_end - tsc_start) * 1.0 / (get_us_interval(&start, &end));
}

/**
 * Calculate frequencies for all available cpus.
 *
 * @author cjiang
 */
static int get_all_cpu_frequencies() {
  uint32 id;
  double frequency;

  hp_globals.cpu_frequencies = pemalloc(sizeof(double) * hp_globals.cpu_num, 1);

  /* Iterate over all cpus found on the machine. */
  for (id = 0; id < hp_globals.cpu_num; ++id) {
    /* Only get the previous cpu affinity mask for the first call. */
    if (UNEXPECTED(bind_to_cpu(id) == FAILURE)) {
      clear_frequencies();
      return FAILURE;
    }

    /* Make sure the current process gets scheduled to the target cpu. This
     * might not be necessary though. */
    usleep(0);

    frequency = get_cpu_frequency();
    if (UNEXPECTED(frequency == 0.0)) {
      clear_frequencies();
      return FAILURE;
    }
    hp_globals.cpu_frequencies[id] = frequency;

    if (restore_cpu_affinity(&hp_globals.cpu_prev_mask) == FAILURE) { /* bind_to_cpu() changes the current affinity */
      return FAILURE;
    }
  }

  return SUCCESS;
}

/**
 * Restore cpu affinity mask to a specified value. It returns 0 on success and
 * -1 on failure.
 *
 * @param cpu_set_t * prev_mask, previous cpu affinity mask to be restored to.
 * @return int, 0 on success, and -1 on failure.
 *
 * @author cjiang
 */
static int restore_cpu_affinity(cpu_set_t * prev_mask) {
  if (SET_AFFINITY(0, sizeof(cpu_set_t), prev_mask) < 0) {
    return FAILURE;
  }

  hp_globals.cur_cpu_id = 0;
  return SUCCESS;
}

/**
 * Reclaim the memory allocated for cpu_frequencies.
 *
 * @author cjiang
 */
static void clear_frequencies() {
  if (hp_globals.cpu_frequencies) {
    pefree(hp_globals.cpu_frequencies, 1);
    hp_globals.cpu_frequencies = NULL;
  }
}


/**
 * ***************************
 * UPROFILER DUMMY CALLBACKS
 * ***************************
 */
static void hp_mode_dummy_init_cb(TSRMLS_D) { }


static void hp_mode_dummy_exit_cb(TSRMLS_D) { }


static void hp_mode_dummy_beginfn_cb(hp_entry_t **entries,
                              hp_entry_t *current  TSRMLS_DC) { }

static void hp_mode_dummy_endfn_cb(hp_entry_t **entries   TSRMLS_DC) { }


/**
 * ****************************
 * UPROFILER COMMON CALLBACKS
 * ****************************
 */
/**
 * Uprofiler universal begin function.
 * This function is called for all modes before the
 * mode's specific begin_function callback is called.
 *
 * @param  hp_entry_t **entries  linked list (stack)
 *                                  of hprof entries
 * @param  hp_entry_t  *current  hprof entry for the current fn
 * @return void
 * @author kannan, veeve
 */
static void hp_mode_common_beginfn(hp_entry_t **entries,
                            hp_entry_t  *current  TSRMLS_DC) {
  hp_entry_t   *p;

  /* This symbol's recursive level */
  int    recurse_level = 0;

  if (hp_globals.func_hash_counters[current->hash_code] > 0) {
    /* Find this symbols recurse level */
    for(p = (*entries); p; p = p->prev_hprof) {
      if (!strcmp(current->function->name, p->function->name)) {
        recurse_level = (p->rlvl_hprof) + 1;
        break;
      }
    }
  }
  hp_globals.func_hash_counters[current->hash_code]++;

  /* Init current function's recurse level */
  current->rlvl_hprof = recurse_level;
}

/**
 * Uprofiler universal end function.  This function is called for all modes after
 * the mode's specific end_function callback is called.
 *
 * @param  hp_entry_t **entries  linked list (stack) of hprof entries
 * @return void
 * @author kannan, veeve
 */
static void hp_mode_common_endfn(hp_entry_t **entries, hp_entry_t *current TSRMLS_DC) {
  hp_globals.func_hash_counters[current->hash_code]--;
}


/**
 * *********************************
 * UPROFILER INIT MODULE CALLBACKS
 * *********************************
 */
/**
 * UPROFILER_MODE_SAMPLED's init callback
 *
 * @author veeve
 */
static void hp_mode_sampled_init_cb(TSRMLS_D) {
  struct timeval  now;
  uint64 truncated_us;
  uint64 truncated_tsc;
  double cpu_freq = hp_globals.cpu_frequencies[hp_globals.cur_cpu_id];

  /* Init the last_sample in tsc */
  hp_globals.last_sample_tsc = cycle_timer();

  /* Find the microseconds that need to be truncated */
  gettimeofday(&hp_globals.last_sample_time, 0);
  now = hp_globals.last_sample_time;
  hp_trunc_time(&hp_globals.last_sample_time, UPROFILER_SAMPLING_INTERVAL);

  /* Subtract truncated time from last_sample_tsc */
  truncated_us  = get_us_interval(&hp_globals.last_sample_time, &now);
  truncated_tsc = get_tsc_from_us(truncated_us, cpu_freq);
  if (hp_globals.last_sample_tsc > truncated_tsc) {
    /* just to be safe while subtracting unsigned ints */
    hp_globals.last_sample_tsc -= truncated_tsc;
  }

  /* Convert sampling interval to ticks */
  hp_globals.sampling_interval_tsc =
    get_tsc_from_us(UPROFILER_SAMPLING_INTERVAL, cpu_freq);
}


/**
 * ************************************
 * UPROFILER BEGIN FUNCTION CALLBACKS
 * ************************************
 */

/**
 * UPROFILER_MODE_HIERARCHICAL's begin function callback
 *
 * @author kannan
 */
static void hp_mode_hier_beginfn_cb(hp_entry_t **entries,
                             hp_entry_t  *current  TSRMLS_DC) {
  /* Get start tsc counter */
  current->tsc_start = cycle_timer();

  /* Get CPU usage */
  if (hp_globals.uprofiler_flags & UPROFILER_FLAGS_CPU) {
    getrusage(RUSAGE_SELF, &(current->ru_start_hprof));
  }

  /* Get memory usage */
  if (hp_globals.uprofiler_flags & UPROFILER_FLAGS_MEMORY) {
    current->mu_start_hprof  = zend_memory_usage(0 TSRMLS_CC);
    current->pmu_start_hprof = zend_memory_peak_usage(0 TSRMLS_CC);
  }
}


/**
 * UPROFILER_MODE_SAMPLED's begin function callback
 *
 * @author veeve
 */
static void hp_mode_sampled_beginfn_cb(hp_entry_t **entries,
                                hp_entry_t  *current  TSRMLS_DC) {
  /* See if its time to take a sample */
  hp_sample_check(entries  TSRMLS_CC);
}


/**
 * **********************************
 * UPROFILER END FUNCTION CALLBACKS
 * **********************************
 */

/**
 * UPROFILER shared end function callback
 *
 * @author kannan
 */
static zval * hp_mode_shared_endfn_cb(hp_entry_t *top,
                               char          *symbol  TSRMLS_DC) {
  zval    *counts;
  uint64   tsc_end;

  /* Get end tsc counter */
  tsc_end = cycle_timer();

  /* Get the stat array */
  if (!(counts = hp_hash_lookup(symbol TSRMLS_CC))) {
    return (zval *) 0;
  }

  /* Bump stats in the counts hashtable */
  hp_inc_count(counts, "ct", 1  TSRMLS_CC);

  hp_inc_count(counts, "wt", (long)get_us_from_tsc(tsc_end - top->tsc_start,
        hp_globals.cpu_frequencies[hp_globals.cur_cpu_id]) TSRMLS_CC);
  return counts;
}

/**
 * UPROFILER_MODE_HIERARCHICAL's end function callback
 *
 * @author kannan
 */
static void hp_mode_hier_endfn_cb(hp_entry_t **entries  TSRMLS_DC) {
  hp_entry_t   *top = (*entries);
  zval            *counts;
  struct rusage    ru_end;
  char             symbol[SCRATCH_BUF_LEN];
  long int         mu_end;
  long int         pmu_end;

  /* Get the stat array */
  hp_get_function_stack(top, 2, symbol, sizeof(symbol));
  if (!(counts = hp_mode_shared_endfn_cb(top,
                                         symbol  TSRMLS_CC))) {
    return;
  }

  if (hp_globals.uprofiler_flags & UPROFILER_FLAGS_CPU) {
    /* Get CPU usage */
    getrusage(RUSAGE_SELF, &ru_end);

    /* Bump CPU stats in the counts hashtable */
    hp_inc_count(counts, "cpu", (get_us_interval(&(top->ru_start_hprof.ru_utime),
                                              &(ru_end.ru_utime)) +
                              get_us_interval(&(top->ru_start_hprof.ru_stime),
                                              &(ru_end.ru_stime)))
              TSRMLS_CC);
  }

  if (hp_globals.uprofiler_flags & UPROFILER_FLAGS_MEMORY) {
    /* Get Memory usage */
    mu_end  = zend_memory_usage(0 TSRMLS_CC);
    pmu_end = zend_memory_peak_usage(0 TSRMLS_CC);

    /* Bump Memory stats in the counts hashtable */
    hp_inc_count(counts, "mu",  mu_end - top->mu_start_hprof    TSRMLS_CC);
    hp_inc_count(counts, "pmu", pmu_end - top->pmu_start_hprof  TSRMLS_CC);
  }

  if ((hp_globals.uprofiler_flags & UPROFILER_FLAGS_FUNCTION_INFOS) && (top->function->zend_function_type & ZEND_USER_FUNCTION)) {
	add_assoc_string(counts, "filename", (char *)top->function->filename, 1);
	add_assoc_long(counts, "lineno", top->function->lineno);
  }
}

/**
 * UPROFILER_MODE_SAMPLED's end function callback
 *
 * @author veeve
 */
static void hp_mode_sampled_endfn_cb(hp_entry_t **entries  TSRMLS_DC) {
  /* See if its time to take a sample */
  hp_sample_check(entries  TSRMLS_CC);
}



#if IS_AT_LEAST_PHP_55
ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data TSRMLS_DC) {
#else
  ZEND_DLEXPORT void hp_execute (zend_op_array *ops TSRMLS_DC) {
#endif
  up_function *func = NULL;

  func = hp_get_function_name();
  if (!func) {
#if IS_AT_LEAST_PHP_55
	_zend_execute_ex(execute_data TSRMLS_CC);
#else
	_zend_execute(ops TSRMLS_CC);
#endif
    return;
  }

  BEGIN_PROFILING(func);
#if IS_AT_LEAST_PHP_55
  _zend_execute_ex(execute_data TSRMLS_CC);
#else
  _zend_execute(ops TSRMLS_CC);
#endif
    END_PROFILING();
}

#if IS_AT_LEAST_PHP_55
#define EX_T(offset) (*EX_TMP_VAR(execute_data, offset))

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data,
                                       struct _zend_fcall_info *fci, int ret TSRMLS_DC) {
#else
#define EX_T(offset) (*(temp_variable *)((char *) EX(Ts) + offset))

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data,
                                       int ret TSRMLS_DC) {
#endif

  zend_execute_data *current_data;
  up_function       *func = NULL;

  current_data = EG(current_execute_data);
  func = hp_get_function_name();

  if (func) {
    BEGIN_PROFILING(func);
  }

  if (!_zend_execute_internal) { /* no old override to begin with. so invoke the builtin's implementation  */
	zend_op *opline = EX(opline);
#if IS_PHP_54
    temp_variable *retvar = &EX_T(opline->result.var);
    ((zend_internal_function *) EX(function_state).function)->handler(
                       opline->extended_value,
                       retvar->var.ptr,
                       (EX(function_state).function->common.fn_flags & ZEND_ACC_RETURN_REFERENCE) ?
                       &retvar->var.ptr:NULL,
                       EX(object), ret TSRMLS_CC);
#elif IS_AT_LEAST_PHP_55
    execute_internal(execute_data, fci, ret TSRMLS_CC);
#else
    ((zend_internal_function *) EX(function_state).function)->handler(
                       opline->extended_value,
                       EX_T(opline->result.u.var).var.ptr,
                       EX(function_state).function->common.return_reference ?
                       &EX_T(opline->result.u.var).var.ptr:NULL,
                       EX(object), ret TSRMLS_CC);
#endif

  } else {
    /* call the old override */
#if IS_AT_LEAST_PHP_55
	_zend_execute_internal(execute_data, fci, ret TSRMLS_CC);
#else
	_zend_execute_internal(execute_data, ret TSRMLS_CC);
#endif
  }

  if (func) {
    END_PROFILING();
  }

}

ZEND_DLEXPORT zend_op_array* hp_compile_file(zend_file_handle *file_handle,
                                             int type TSRMLS_DC) {

  const char     *filename;
  up_function    *func;
  char           *func_name;
  int             len;
  zend_op_array  *ret;

  filename = hp_get_base_filename(file_handle->filename);
  spprintf(&func_name, 0, "load::%s", filename);
  func = up_function_create(func_name);

  BEGIN_PROFILING(func);
  ret = _zend_compile_file(file_handle, type TSRMLS_CC);
  END_PROFILING();

  return ret;
}

ZEND_DLEXPORT zend_op_array* hp_compile_string(zval *source_string, char *filename TSRMLS_DC) {

    up_function   *func;
    char          *func_name;
    int           len;
    zend_op_array *ret;

    spprintf(&func_name, 0, "eval::%s", filename);
    func = up_function_create(func_name);

    BEGIN_PROFILING(func);
    ret = _zend_compile_string(source_string, filename TSRMLS_CC);
    END_PROFILING();

    return ret;
}

/**
 * **************************
 * MAIN UPROFILER CALLBACKS
 * **************************
 */

/**
 * This function gets called once when uprofiler gets enabled.
 * It replaces all the functions like zend_execute, zend_execute_internal,
 * etc that needs to be instrumented with their corresponding proxies.
 */
static int hp_begin(char level, long uprofiler_flags, zval *options TSRMLS_DC)
{
	if (hp_globals.enabled) {
		return SUCCESS;
	}

	hp_globals.mode_cb.init_cb     = hp_mode_dummy_init_cb;
	hp_globals.mode_cb.exit_cb     = hp_mode_dummy_exit_cb;
	hp_globals.mode_cb.begin_fn_cb = hp_mode_dummy_beginfn_cb;
	hp_globals.mode_cb.end_fn_cb   = hp_mode_dummy_endfn_cb;

	switch(level) {
		case UPROFILER_MODE_HIERARCHICAL:
			hp_globals.mode_cb.begin_fn_cb = hp_mode_hier_beginfn_cb;
			hp_globals.mode_cb.end_fn_cb   = hp_mode_hier_endfn_cb;
		break;
		case UPROFILER_MODE_SAMPLED:
			hp_globals.mode_cb.init_cb     = hp_mode_sampled_init_cb;
			hp_globals.mode_cb.begin_fn_cb = hp_mode_sampled_beginfn_cb;
			hp_globals.mode_cb.end_fn_cb   = hp_mode_sampled_endfn_cb;
		break;
	}

	if (UNEXPECTED(hp_init_profiler_state(level TSRMLS_CC) == FAILURE)) {
		return FAILURE;
	}

	hp_get_ignored_functions_from_arg(options);

    hp_globals.enabled         = 1;
    hp_globals.uprofiler_flags = uprofiler_flags;

    _zend_compile_file   = zend_compile_file;
    zend_compile_file    = hp_compile_file;
    _zend_compile_string = zend_compile_string;
    zend_compile_string  = hp_compile_string;

    /* Replace zend_execute with our proxy */
#if IS_AT_LEAST_PHP_55
    _zend_execute_ex = zend_execute_ex;
    zend_execute_ex  = hp_execute_ex;
#else
    _zend_execute = zend_execute;
    zend_execute  = hp_execute;
#endif

    if (!(hp_globals.uprofiler_flags & UPROFILER_FLAGS_NO_BUILTINS)) {
    	_zend_execute_internal = zend_execute_internal;
    	zend_execute_internal  = hp_execute_internal;
    }

    BEGIN_PROFILING(up_function_create(estrdup(ROOT_SYMBOL)));

    return SUCCESS;
}

/**
 * Called at request shutdown time. Cleans the profiler's global state.
 */
static void hp_end(TSRMLS_D) {
  /* Bail if not ever enabled */
  if (!hp_globals.ever_enabled || hp_globals.enabled) {
    return;
  }

  /* Clean up state */
  hp_clean_profiler_state(TSRMLS_C);
}

/**
 * Called from uprofiler_disable(). Removes all the proxies setup by
 * hp_begin() and restores the original values.
 */
static void hp_stop(TSRMLS_D) {

	if (!hp_globals.enabled) {
		return;
	}

  /* End any unfinished calls */
  while (hp_globals.entries) {
	  end_profiling(&hp_globals.entries);
  }

  /* Remove proxies, restore the originals */
#if IS_AT_LEAST_PHP_55
  zend_execute_ex       = _zend_execute_ex;
#else
  zend_execute          = _zend_execute;
#endif
  if (!(hp_globals.uprofiler_flags & UPROFILER_FLAGS_NO_BUILTINS)) {
	  zend_execute_internal = _zend_execute_internal;
  }
  zend_compile_file     = _zend_compile_file;
  zend_compile_string   = _zend_compile_string;

  restore_cpu_affinity(&hp_globals.cpu_prev_mask);

  CLEAR_IGNORED_FUNC_NAMES

  hp_globals.enabled = 0;
}


/**
 * *****************************
 * UPROFILER ZVAL UTILITY FUNCTIONS
 * *****************************
 */

/** Convert the PHP array of strings to an emalloced array of strings. Note,
 *  this method duplicates the string data in the PHP array.
 *
 *  @author mpal
 **/
static char **hp_strings_in_zval(zval  *values) {
  char   **result;
  size_t   count;
  size_t   ix = 0;

  if (!values) {
    return NULL;
  }

  if (values->type == IS_ARRAY) {
    HashTable *ht;

    ht    = Z_ARRVAL_P(values);
    count = zend_hash_num_elements(ht);

    if((result =
         (char**)emalloc(sizeof(char*) * (count + 1))) == NULL) {
      return result;
    }

    for (zend_hash_internal_pointer_reset(ht);
         zend_hash_has_more_elements(ht) == SUCCESS;
         zend_hash_move_forward(ht)) {
      char  *str;
      uint   len;
      ulong  idx;
      int    type;
      zval **data;

      type = zend_hash_get_current_key_ex(ht, &str, &len, &idx, 0, NULL);
      /* Get the names stored in a standard array */
      if(type == HASH_KEY_IS_LONG) {
        if ((zend_hash_get_current_data(ht, (void**)&data) == SUCCESS) &&
            Z_TYPE_PP(data) == IS_STRING &&
            strcmp(Z_STRVAL_PP(data), ROOT_SYMBOL)) { /* do not ignore "main" */
          result[ix] = estrdup(Z_STRVAL_PP(data));
          ix++;
        }
      }
    }
  } else if(values->type == IS_STRING) {
    if((result = (char**)emalloc(sizeof(char*) * 2)) == NULL) {
      return result;
    }
    result[0] = estrdup(Z_STRVAL_P(values));
    ix = 1;
  } else {
    result = NULL;
  }

  /* NULL terminate the array */
  if (result != NULL) {
    result[ix] = NULL;
  }

  return result;
}

/* Free this memory at the end of profiling */
static inline void hp_array_del(char **name_array) {
  if (name_array != NULL) {
    size_t i = 0;
    for(; name_array[i] != NULL && i < UPROFILER_MAX_IGNORED_FUNCTIONS; i++) {
      efree(name_array[i]);
    }
    efree(name_array);
  }
}
