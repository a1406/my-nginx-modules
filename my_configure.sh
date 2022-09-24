#!/bin/sh
./configure --with-debug --with-cc-opt='-g -O0 -fno-strict-aliasing' --add-module='mymodules/check_auth/' --add-module='mymodules/mycurl/'

