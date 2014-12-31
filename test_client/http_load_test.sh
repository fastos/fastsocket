#!/bin/bash

declare -i i=0
declare -i threads_nr=10

while ((i < threads_nr)); do
	http_load -rate 1000 -seconds 300 ./url.txt 1>/dev/null 2>&1 & 
	let ++i
done

