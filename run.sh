#!/usr/bin/env bash

# This is shell script to execute my process_log.py file
# users should enter 6 path with file name as the following order:
# path of 1. process_log file name, 2. input log file, 3. output hosts.txt, 4. output hours.txt, 5. output resources.txt, 6. output blocked.txt

dir=$(PWD)
echo "current path: $dir"
python ./src/process_log.py ./log_input/log.txt ./log_output/hosts.txt ./log_output/hours.txt ./log_output/resources.txt ./log_output/blocked.txt



