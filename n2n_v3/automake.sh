#!/bin/sh
NAME=linux_x86
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
sed 's/CC=gcc/CC=\/home\/yyqt\/n2n\/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu\/bin\/aarch64-none-linux-gnu-gcc/g' /Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode
