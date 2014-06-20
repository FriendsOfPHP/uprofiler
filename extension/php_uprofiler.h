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
 */

#ifndef PHP_XHPROF_H
#define PHP_XHPROF_H

#define	PHP_UPROFILER_VERSION "0.11"

extern zend_module_entry uprofiler_module_entry;
#define phpext_uprofiler_ptr &uprofiler_module_entry

#ifdef PHP_WIN32
#define PHP_XHPROF_API __declspec(dllexport)
#include "win32/php_uprofiler_win32.h"
#include "win32/php_uprofiler_win32.c"
#else
#define PHP_XHPROF_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#ifdef PHP_WIN32
# include "win32/time.h"
# include "win32/unistd.h"
#else
# include <sys/time.h>
# include <sys/resource.h>
# include <unistd.h>
#endif

#include <stdlib.h>

#ifdef __FreeBSD__
# if __FreeBSD_version >= 700110
#   include <sys/resource.h>
#   include <sys/cpuset.h>
#   define cpu_set_t cpuset_t
#   define SET_AFFINITY(pid, size, mask) \
           cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, size, mask)
#   define GET_AFFINITY(pid, size, mask) \
           cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, size, mask)
# else
#   error "This version of FreeBSD does not support cpusets"
# endif /* __FreeBSD_version */
#elif __APPLE__
/*
 * Patch for compiling in Mac OS X Leopard
 * @author Svilen Spasov <s.spasov@gmail.com>
 */
#    include <mach/mach_init.h>
#    include <mach/thread_policy.h>
#    define cpu_set_t thread_affinity_policy_data_t
#    define CPU_SET(cpu_id, new_mask) \
        (*(new_mask)).affinity_tag = (cpu_id + 1)
#    define CPU_ZERO(new_mask)                 \
        (*(new_mask)).affinity_tag = THREAD_AFFINITY_TAG_NULL; return 0;
#   define SET_AFFINITY(pid, size, mask)       \
        thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY, mask, \
                          THREAD_AFFINITY_POLICY_COUNT)
#define GET_AFFINITY(pid, size, mask) CPU_ZERO(mask)

#elif PHP_WIN32
/*
 * Patch for compiling in Win32/64
 * @author Benjamin Carl <opensource@clickalicious.de>
 */
#    define CPU_SET(cpu_id, new_mask) (*(new_mask)) = (cpu_id + 1)
#    define CPU_ZERO(new_mask) (*(new_mask)) = 0
#    define SET_AFFINITY(pid, size, mask) SetProcessAffinityMask(GetCurrentProcess(), (DWORD_PTR)mask)
#    define GET_AFFINITY(pid, size, mask) \
                      GetProcessAffinityMask(GetCurrentProcess(), mask, &s_mask)
#else
/* For sched_getaffinity, sched_setaffinity */
# include <sched.h>
# define SET_AFFINITY(pid, size, mask) sched_setaffinity(0, size, mask)
# define GET_AFFINITY(pid, size, mask) sched_getaffinity(0, size, mask)
#endif /* __FreeBSD__ */


#define CLEAR_IGNORED_FUNC_NAMES do { \
		hp_array_del(hp_globals.ignored_function_names); \
		hp_globals.ignored_function_names = NULL; \
} while (0);

#define BEGIN_PROFILING(function) begin_profiling(&hp_globals.entries, function)
#define END_PROFILING() end_profiling(&hp_globals.entries)


/**
 * COMPAT
 */

#define PHP_5_0_X_API_NO		220040412
#define PHP_5_1_X_API_NO		220051025
#define PHP_5_2_X_API_NO		220060519
#define PHP_5_3_X_API_NO		220090626
#define PHP_5_4_X_API_NO		220100525
#define PHP_5_5_X_API_NO		220121212


#define IS_PHP_55 ZEND_EXTENSION_API_NO == PHP_5_5_X_API_NO
#define IS_AT_LEAST_PHP_55 ZEND_EXTENSION_API_NO >= PHP_5_5_X_API_NO

#define IS_PHP_54 ZEND_EXTENSION_API_NO == PHP_5_4_X_API_NO
#define IS_AT_LEAST_PHP_54 ZEND_EXTENSION_API_NO >= PHP_5_4_X_API_NO

#define IS_PHP_53 ZEND_EXTENSION_API_NO == PHP_5_3_X_API_NO
#define IS_AT_LEAST_PHP_53 ZEND_EXTENSION_API_NO >= PHP_5_3_X_API_NO

/**
 * **********************
 * GLOBAL MACRO CONSTANTS
 * **********************
 */

/* Fictitious function name to represent top of the call tree. The paranthesis
 * in the name is to ensure we don't conflict with user function names.  */
#define ROOT_SYMBOL                "main()"

/* Size of a temp scratch buffer            */
#define SCRATCH_BUF_LEN            512

/* Various XHPROF modes. If you are adding a new mode, register the appropriate
 * callbacks in hp_begin() */
#define UPROFILER_MODE_HIERARCHICAL            1
#define UPROFILER_MODE_SAMPLED                 2

/* Hierarchical profiling flags.
 *
 * Note: Function call counts and wall (elapsed) time are always profiled.
 * The following optional flags can be used to control other aspects of
 * profiling.
 */
#define UPROFILER_FLAGS_NO_BUILTINS    0x0001         /* do not profile builtins */
#define UPROFILER_FLAGS_CPU            0x0002      /* gather CPU times for funcs */
#define UPROFILER_FLAGS_MEMORY         0x0004   /* gather memory usage for funcs */
#define UPROFILER_FLAGS_FUNCTION_INFO  0x0008   /* gather more function informations */

/* Constants for UPROFILER_MODE_SAMPLED        */
#define UPROFILER_SAMPLING_INTERVAL       100000      /* In microsecs        */

/* Constant for ignoring functions, transparent to hierarchical profile */
#define UPROFILER_MAX_IGNORED_FUNCTIONS  256
#define UPROFILER_IGNORED_FUNCTION_FILTER_SIZE                           \
               ((UPROFILER_MAX_IGNORED_FUNCTIONS + 7)/8)
#define UPROFILER_FUNC_HASH_COUNTER 256

#if !defined(uint64)
typedef unsigned long long uint64;
#endif
#if !defined(uint32)
typedef unsigned int uint32;
#endif
#if !defined(uint8)
typedef unsigned char uint8;
#endif

/**
 * *****************************
 * GLOBAL DATATYPES AND TYPEDEFS
 * *****************************
 */


typedef struct up_function {
	char       *name;
	const char *filename;
	zend_uint  lineno;
	int zend_function_type;
} up_function;

/* XHProf maintains a stack of entries being profiled. The memory for the entry
 * is passed by the layer that invokes BEGIN_PROFILING(), e.g. the hp_execute()
 * function. Often, this is just C-stack memory.
 *
 * This structure is a convenient place to track start time of a particular
 * profile operation, recursion depth, and the name of the function being
 * profiled. */
typedef struct hp_entry_t {
  up_function             *function;                       /* function name */
  int                     rlvl_hprof;        /* recursion level for function */
  uint64                  tsc_start;         /* start value for TSC counter  */
  long int                mu_start_hprof;                    /* memory usage */
  long int                pmu_start_hprof;              /* peak memory usage */
  struct rusage           ru_start_hprof;             /* user/sys time start */
  struct hp_entry_t      *prev_hprof;    /* ptr to prev entry being profiled */
  uint8                   hash_code;     /* hash_code for the function name  */
} hp_entry_t;

/* Various types for XHPROF callbacks       */
typedef void (*hp_init_cb)           (TSRMLS_D);
typedef void (*hp_exit_cb)           (TSRMLS_D);
typedef void (*hp_begin_function_cb) (hp_entry_t **entries,
                                      hp_entry_t *current   TSRMLS_DC);
typedef void (*hp_end_function_cb)   (hp_entry_t **entries  TSRMLS_DC);

/* Struct to hold the various callbacks for a single uprofiler mode */
typedef struct hp_mode_cb {
  hp_init_cb             init_cb;
  hp_exit_cb             exit_cb;
  hp_begin_function_cb   begin_fn_cb;
  hp_end_function_cb     end_fn_cb;
} hp_mode_cb;

/* Xhprof's global state.
 *
 * This structure is instantiated once.  Initialize defaults for attributes in
 * hp_init_profiler_state() Cleanup/free attributes in
 * hp_clean_profiler_state() */
typedef struct hp_global_t {

  /*       ----------   Global attributes:  -----------       */

  /* Indicates if uprofiler is currently enabled */
  char              enabled;

  /* Indicates if uprofiler was ever enabled during this request */
  char              ever_enabled;

  /* Holds all the uprofiler statistics */
  zval            *stats_count;

  /* Indicates the current uprofiler mode or level */
  char              profiler_level;

  /* Top of the profile stack */
  hp_entry_t      *entries;

  /* freelist of hp_entry_t chunks for reuse... */
  hp_entry_t      *entry_free_list;

  /* Callbacks for various uprofiler modes */
  hp_mode_cb       mode_cb;

  /*       ----------   Mode specific attributes:  -----------       */

  /* Global to track the time of the last sample in time and ticks */
  struct timeval   last_sample_time;
  uint64           last_sample_tsc;
  /* XHPROF_SAMPLING_INTERVAL in ticks */
  uint64           sampling_interval_tsc;

  /* This array is used to store cpu frequencies for all available logical
   * cpus.  For now, we assume the cpu frequencies will not change for power
   * saving or other reasons. If we need to worry about that in the future, we
   * can use a periodical timer to re-calculate this arrary every once in a
   * while (for example, every 1 or 5 seconds). */
  double *cpu_frequencies;

  /* The number of logical CPUs this machine has. */
  uint32 cpu_num;

  cpu_set_t cpu_prev_mask;

  /* The cpu id current process is bound to. (default 0) */
  uint32 cur_cpu_id;

  /* XHProf flags */
  long uprofiler_flags;

  /* counter table indexed by hash value of function names. */
  uint8  func_hash_counters[UPROFILER_FUNC_HASH_COUNTER];

  /* Table of ignored function names and their filter */
  char  **ignored_function_names;
  uint8   ignored_function_filter[UPROFILER_IGNORED_FUNCTION_FILTER_SIZE];

} hp_global_t;

/**
 * *********************
 * FUNCTION PROTOTYPES
 * *********************
 */
static int restore_cpu_affinity(cpu_set_t * prev_mask);
static int bind_to_cpu(uint32 cpu_id);

/**
 * ****************************
 * STATIC FUNCTION DECLARATIONS
 * ****************************
 */
static void hp_register_constants(INIT_FUNC_ARGS);

static int hp_begin(char level, long uprofiler_flags, zval *options TSRMLS_DC);
static void hp_stop(TSRMLS_D);
static void hp_end(TSRMLS_D);
int hp_init_profiler_state(char level TSRMLS_DC);
static void up_function_free(up_function *f);
static up_function *up_function_create(char *function_name);

static inline uint64 cycle_timer();
static double get_cpu_frequency();
static int get_all_cpu_frequencies();
static void clear_frequencies();
static inline double get_us_from_tsc(uint64 count, double cpu_frequency);

static void hp_free_the_free_list();
static hp_entry_t *hp_fast_alloc_hprof_entry();
static inline uint8 hp_inline_hash(char * str);
static long get_us_interval(struct timeval *start, struct timeval *end);
static void incr_us_interval(struct timeval *start, uint64 incr);
static inline uint64 get_tsc_from_us(uint64 usecs, double cpu_frequency);

static void hp_get_ignored_functions_from_arg(zval *args);
static up_function *hp_get_function_name(void);
static size_t hp_get_entry_name(hp_entry_t  *entry, char *result_buf, size_t result_len);
static int  hp_ignore_entry_work(uint8 hash_code, char *curr_func);

static inline char **hp_strings_in_zval(zval  *values);
static inline void   hp_array_del(char **name_array);
static inline char  hp_ignore_entry(uint8 hash_code, char *curr_func);
static void hp_clean_profiler_state(TSRMLS_D);
static size_t hp_get_function_stack(hp_entry_t *entry, int level, char *result_buf, size_t result_len);
static const char *hp_get_base_filename(const char *filename);
static void hp_inc_count(zval *counts, char *name, long count TSRMLS_DC);
static zval * hp_hash_lookup(char *symbol  TSRMLS_DC);
static void hp_trunc_time(struct timeval *tv, uint64 intr);

static void hp_sample_stack(hp_entry_t  **entries  TSRMLS_DC);
static void hp_sample_check(hp_entry_t **entries  TSRMLS_DC);

static void hp_mode_common_beginfn(hp_entry_t **entries,
                            hp_entry_t  *current  TSRMLS_DC);
static void hp_mode_common_endfn(hp_entry_t **entries, hp_entry_t *current TSRMLS_DC);
static void hp_mode_sampled_init_cb(TSRMLS_D);
static void hp_mode_hier_beginfn_cb(hp_entry_t **entries,
                             hp_entry_t  *current  TSRMLS_DC);
static void hp_mode_sampled_beginfn_cb(hp_entry_t **entries,
                                hp_entry_t  *current  TSRMLS_DC);
static zval * hp_mode_shared_endfn_cb(hp_entry_t *top,
                               char          *symbol  TSRMLS_DC);
static void hp_mode_hier_endfn_cb(hp_entry_t **entries  TSRMLS_DC);
static void hp_mode_sampled_endfn_cb(hp_entry_t **entries  TSRMLS_DC);

static inline void begin_profiling(hp_entry_t **entries, up_function *function_name);
static inline void end_profiling(hp_entry_t **entries);

/**
 * ***********************
 * GLOBAL STATIC VARIABLES
 * ***********************
 */
/* XHProf global state */
static hp_global_t       hp_globals = {0};

#if IS_AT_LEAST_PHP_55
/* Pointer to the original execute function */
static void (*_zend_execute_ex) (zend_execute_data *execute_data TSRMLS_DC);

/* Pointer to the original execute_internal function */
static void (*_zend_execute_internal) (zend_execute_data *data,
                      struct _zend_fcall_info *fci, int ret TSRMLS_DC);

#else
/* Pointer to the original execute function */
ZEND_DLEXPORT void (*_zend_execute) (zend_op_array *ops TSRMLS_DC);

/* Pointer to the origianl execute_internal function */
ZEND_DLEXPORT void (*_zend_execute_internal) (zend_execute_data *data,
                           int ret TSRMLS_DC);
#endif

/* Pointer to the original compile function */
static zend_op_array * (*_zend_compile_file) (zend_file_handle *file_handle,
                                              int type TSRMLS_DC);

/* Pointer to the original compile string function (used by eval) */
static zend_op_array * (*_zend_compile_string) (zval *source_string, char *filename TSRMLS_DC);

/* Bloom filter for function names to be ignored */
#define INDEX_2_BYTE(index)  (index >> 3)
#define INDEX_2_BIT(index)   (1 << (index & 0x7));
#undef EX
#define EX(element) ((execute_data)->element)

PHP_MINIT_FUNCTION(uprofiler);
PHP_MSHUTDOWN_FUNCTION(uprofiler);
PHP_RINIT_FUNCTION(uprofiler);
PHP_RSHUTDOWN_FUNCTION(uprofiler);
PHP_MINFO_FUNCTION(uprofiler);

PHP_FUNCTION(uprofiler_enable);
PHP_FUNCTION(uprofiler_disable);
PHP_FUNCTION(uprofiler_sample_enable);
PHP_FUNCTION(uprofiler_sample_disable);
#if IS_PHP_53
PHP_FUNCTION(http_response_code);
#endif

#endif	/* PHP_XHPROF_H */
