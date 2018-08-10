#!/bin/sh
set -e
./check1.py $1 $2 && ./check2.py $1 $2 && ./check3.py $1 $2
