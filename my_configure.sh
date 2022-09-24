#!/bin/sh
./configure --with-debug --with-cc-opt='-g -O0 -fno-strict-aliasing -fsanitize=address' --with-ld-opt='-fsanitize=address' --add-module='mymodules/check_auth/' --add-module='mymodules/mycurl/'

