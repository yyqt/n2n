#!/bin/sh
NAME=linux_x86
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode

NAME=linux_aarch64_10
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
sed -i 's/CC=gcc/CC=\/data\/n2n\/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu\/bin\/aarch64-none-linux-gnu-gcc/g' ./Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode


NAME=linux_aarch64_8
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
sed -i 's/CC=gcc/CC=\/data\/n2n\/gcc-arm-8.3-2019.03-x86_64-aarch64-linux-gnu\/bin\/aarch64-linux-gnu-cpp/g' ./Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode

NAME=openwrt_15_ar71xx
mkdir -p ./outs/$NAME
export STAGING_DIR=/data/n2n/OpenWrt-SDK-15.05.1-ar71xx-generic_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64/staging_dir
cp ./Makefile ./Makefile_tmp
make clean
sed -i 's/CC=gcc/CC=\/data\/n2n\/OpenWrt-SDK-15.05.1-ar71xx-generic_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64\/staging_dir\/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2\/bin\/mips-openwrt-linux-uclibc-gcc/g' ./Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode


NAME=openwrt_15_mt7620
export STAGING_DIR=/data/n2n/OpenWrt-SDK-15.05.1-ramips-mt7620_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64/staging_dir
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
sed -i 's/CC=gcc/CC=\/data\/n2n\/OpenWrt-SDK-15.05.1-ramips-mt7620_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64\/staging_dir\/toolchain-mipsel_24kec+dsp_gcc-4.8-linaro_uClibc-0.9.33.2\/bin\/mipsel-openwrt-linux-gcc/g' ./Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode

NAME=openwrt_19_x86
export STAGING_DIR=/data/n2n/openwrt-sdk-19.07.2-x86-generic_gcc-7.5.0_musl.Linux-x86_64/staging_dir
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
sed -i 's/CC=gcc/CC=\/data\/n2n\/openwrt-sdk-19.07.2-x86-generic_gcc-7.5.0_musl.Linux-x86_64\/staging_dir\/toolchain-i386_pentium4_gcc-7.5.0_musl\/bin\/i486-openwrt-linux-gcc/g' ./Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode


NAME=openwrt_19_ipq40xx
export STAGING_DIR=/data/n2n/openwrt-sdk-19.07.3-ipq40xx-generic_gcc-7.5.0_musl_eabi.Linux-x86_64/staging_dir
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
sed -i 's/CC=gcc/CC=\/data\/n2n\/openwrt-sdk-19.07.3-ipq40xx-generic_gcc-7.5.0_musl_eabi.Linux-x86_64\/staging_dir\/toolchain-arm_cortex-a7+neon-vfpv4_gcc-7.5.0_musl_eabi\/bin\/arm-openwrt-linux-gcc/g' ./Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode


NAME=openwrt_21_ipq40xx
export STAGING_DIR=/data/n2n/openwrt-sdk-21.02.1-ipq40xx-generic_gcc-8.4.0_musl_eabi.Linux-x86_64/staging_dir
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
sed -i 's/CC=gcc/CC=\/data\/n2n\/openwrt-sdk-21.02.1-ipq40xx-generic_gcc-8.4.0_musl_eabi.Linux-x86_64\/staging_dir\/toolchain-arm_cortex-a7+neon-vfpv4_gcc-8.4.0_musl_eabi\/bin\/arm-openwrt-linux-gcc/g' ./Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode



NAME=openwrt_18_mt7621
export STAGING_DIR=/data/n2n/openwrt-sdk-18.06.1-ramips-mt7621_gcc-7.3.0_musl.Linux-x86_64/staging_dir
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
sed -i 's/CC=gcc/CC=\/data\/n2n\/openwrt-sdk-18.06.1-ramips-mt7621_gcc-7.3.0_musl.Linux-x86_64\/staging_dir\/toolchain-mipsel_24kc_gcc-7.3.0_musl\/bin\/mipsel-openwrt-linux-gcc/g' ./Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode

NAME=openwrt_18_mt7620
export STAGING_DIR=/data/n2n/openwrt-sdk-18.06.1-ramips-mt7620_gcc-7.3.0_musl.Linux-x86_64/staging_dir
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
sed -i 's/CC=gcc/CC=\/data\/n2n\/openwrt-sdk-18.06.1-ramips-mt7620_gcc-7.3.0_musl.Linux-x86_64\/staging_dir\/toolchain-mipsel_24kc_gcc-7.3.0_musl\/bin\/mipsel-openwrt-linux-cpp/g' ./Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode


NAME=openwrt_18_ar71xx
export STAGING_DIR=/data/n2n/openwrt-sdk-18.06.1-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/staging_dir
mkdir -p ./outs/$NAME
cp ./Makefile ./Makefile_tmp
make clean
sed -i 's/CC=gcc/CC=\/data\/n2n\/openwrt-sdk-18.06.1-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64\/staging_dir\/toolchain-mips_24kc_gcc-7.3.0_musl\/bin\/mips-openwrt-linux-cpp/g' ./Makefile_tmp
make -f ./Makefile_tmp
cp ./edge ./outs/$NAME/edge
cp ./supernode ./outs/$NAME/supernode

