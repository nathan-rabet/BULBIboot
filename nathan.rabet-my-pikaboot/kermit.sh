FILE=$1
PTS=$2


# Replace \n with ", "
KERMIT_CONFIG="set line /dev/pts/$PTS, set speed 115200, set parity none, set carrier-watch off, set handshake none, set flow-control none, robust, set file type bin, set file name lit, set rec pack 1000, set send pack 1000, set window 5, set transmit linefeed on, send $FILE"

# Replace \n with ", "

kermit -C "$KERMIT_CONFIG"
