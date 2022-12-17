#!/bin/bash

# output version
bash .ci/printinfo.sh

make clean > /dev/null

echo "checking..."
./helper.pl --check-all || exit 1

exit 0

# ref:         HEAD -> develop
# git commit:  29986d04f2dca985ee64fbca1c7431ea3e3422f4
# commit time: 2022-11-15 16:23:23 +0100
