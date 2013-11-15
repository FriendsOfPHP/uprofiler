<?php

function bar($x) {
  if ($x > 0) {
    bar($x - 1);
  }
}

function foo() {
  for ($idx = 0; $idx < 5; $idx++) {
    bar($idx);
    $x = strlen("abc");
  }
}

// start profiling
uprofiler_enable();

// run program
foo();

// stop profiler
$uprofiler_data = uprofiler_disable();

// display raw uprofiler data for the profiler run
print_r($uprofiler_data);


$uprofiler_ROOT = realpath(dirname(__FILE__) .'/..');
include_once $uprofiler_ROOT . "/uprofiler_lib/utils/uprofiler_lib.php";
include_once $uprofiler_ROOT . "/uprofiler_lib/utils/uprofiler_runs.php";

// save raw data for this profiler run using default
// implementation of iuprofilerRuns.
$uprofiler_runs = new uprofilerRuns_Default();

// save the run under a namespace "uprofiler_foo"
$run_id = $uprofiler_runs->save_run($uprofiler_data, "uprofiler_foo");

echo "---------------\n".
     "Assuming you have set up the http based UI for \n".
     "uprofiler at some address, you can view run at \n".
     "http://<uprofiler-ui-address>/index.php?run=$run_id&source=uprofiler_foo\n".
     "---------------\n";
