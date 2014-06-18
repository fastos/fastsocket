#!/bin/sh
#
# Generate a module signature note source file
#
# mod-sign.sh <sig-file> ><note-src-file>
#

SIG=$1

cat <<EOF
#include <linux/modsign.h>

ELFNOTE(MODSIGN_NOTE_NAME, MODSIGN_NOTE_TYPE, .incbin "$SIG")
EOF

exit 0
