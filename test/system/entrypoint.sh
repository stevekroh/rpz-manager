#!/bin/sh -l

time=$(date)
echo "::set-output name=time::$time"

. /etc/os-release

python3 -m unittest -c test/system/tests.py
