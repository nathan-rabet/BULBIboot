#!/bin/bash

version=$(git describe --tags --always --dirty 2>/dev/null)
if [ ! -e ".git" ] || [ -z $version ]
then
   version=$(grep "^VERSION=" makefile_include.mk | sed "s/.*=//")
fi
echo "Testing version:" $version
#grep "VERSION=" makefile | perl -e "@a = split('=', <>); print @a[1];"`

# get uname
echo "uname="`uname -a`

# get gcc name
if [ -z ${CC} ]
then
   CC="gcc"
fi
echo "${CC}="`${CC} -dumpversion`
echo

# ref:         HEAD -> develop
# git commit:  29986d04f2dca985ee64fbca1c7431ea3e3422f4
# commit time: 2022-11-15 16:23:23 +0100
