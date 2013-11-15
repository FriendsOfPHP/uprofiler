
PHP_ARG_ENABLE(uprofiler, whether to enable uprofiler support,
[ --enable-uprofiler      Enable uprofiler support])

if test "$PHP_uprofiler" != "no"; then
  PHP_NEW_EXTENSION(uprofiler, uprofiler.c, $ext_shared)
fi
