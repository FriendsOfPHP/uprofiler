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

#define	PHP_UPROFILER_VERSION "0.9.2"

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

PHP_MINIT_FUNCTION(uprofiler);
PHP_MSHUTDOWN_FUNCTION(uprofiler);
PHP_RINIT_FUNCTION(uprofiler);
PHP_RSHUTDOWN_FUNCTION(uprofiler);
PHP_MINFO_FUNCTION(uprofiler);

PHP_FUNCTION(uprofiler_enable);
PHP_FUNCTION(uprofiler_disable);
PHP_FUNCTION(uprofiler_sample_enable);
PHP_FUNCTION(uprofiler_sample_disable);

#endif	/* PHP_XHPROF_H */
