#!/bin/bash

declare -i threads_nr=10
declare -i test_time=300

declare -i i=0

if [ $# -gt 0 ]; then
	threads_nr=$1
fi

if [ $# -gt 1 ]; then
	test_time=$2
fi

echo "Start $threads_nr threads, ${threads_nr}k new connections per second"
echo "Test time is ${test_time} seconds"

while ((i < threads_nr)); do
	http_load -rate 1000 -seconds ${test_time} ./url.txt 1>/dev/null 2>&1 & 
	let ++i
done

echo "Press any key to exit"
read 

killall http_load
killall -9 http_load

echo "All test tasks are finished"

