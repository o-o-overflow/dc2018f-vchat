#!/bin/sh
set -e
echo "basic test"
./check1.py $1 $2
echo "speak test"
./check2.py $1 $2
echo "qrcode test"
./check3.py $1 $2
