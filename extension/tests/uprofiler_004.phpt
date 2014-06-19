--TEST--
Uprofiler: Test Include File (load/run_init operations)
Author: Kannan
--FILE--
<?php

include_once dirname(__FILE__).'/common.phpp';

uprofiler_enable();

// Include File:
//
// Note: the 2nd and 3rd attempts should be no-ops and
// will not show up in the profiler data. Only the first
// one should.

include_once dirname(__FILE__).'/uprofiler_004_inc.phpp';
include_once dirname(__FILE__).'/uprofiler_004_inc.phpp';
include_once dirname(__FILE__).'/uprofiler_004_inc.phpp';


// require_once:
// Note: the 2nd and 3rd attempts should be no-ops and
// will not show up in the profiler data. Only the first
// one should.

require_once dirname(__FILE__).'/uprofiler_004_require.phpp';
require_once dirname(__FILE__).'/uprofiler_004_require.phpp';
require_once dirname(__FILE__).'/uprofiler_004_require.phpp';

$output = uprofiler_disable();

echo "Test for 'include_once' & 'require_once' operation\n";
print_canonical($output);
echo "\n";

?>
--EXPECTF--
abc,def,ghi
I am in foo()...
11
I am in bar()...
Test for 'include_once' & 'require_once' operation
main()                                  : ct=       1; wt=*;
main()==>dirname                        : ct=       6; wt=*;
main()==>load::%Stests%euprofiler_004_inc.phpp: ct=       1; wt=*;
main()==>load::%Stests%euprofiler_004_require.phpp: ct=       1; wt=*;
main()==>run_init::%Stests%euprofiler_004_inc.phpp: ct=       1; wt=*;
main()==>run_init::%Stests%euprofiler_004_require.phpp: ct=       1; wt=*;
main()==>uprofiler_disable              : ct=       1; wt=*;
run_init::%Stests%euprofiler_004_inc.phpp==>explode: ct=       1; wt=*;
run_init::%Stests%euprofiler_004_inc.phpp==>foo: ct=       1; wt=*;
run_init::%Stests%euprofiler_004_inc.phpp==>implode: ct=       1; wt=*;
run_init::%Stests%euprofiler_004_require.phpp==>bar: ct=       1; wt=*;
run_init::%Stests%euprofiler_004_require.phpp==>explode: ct=       1; wt=*;
run_init::%Stests%euprofiler_004_require.phpp==>implode: ct=       1; wt=*;
run_init::%Stests%euprofiler_004_require.phpp==>strlen: ct=       1; wt=*;
