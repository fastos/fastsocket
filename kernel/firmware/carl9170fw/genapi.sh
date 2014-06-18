#!/bin/sh

cat <<EOF > include/shared/version.h
#ifndef __CARL9170_SHARED_VERSION_H
#define __CARL9170_SHARED_VERSION_H
#define CARL9170FW_VERSION_YEAR $((100`date +%Y`%100))
#define CARL9170FW_VERSION_MONTH $((100`date +%m`%100))
#define CARL9170FW_VERSION_DAY $((100`date +%d`%100))
#define CARL9170FW_VERSION_GIT "`git describe 2>/dev/null`"
#endif /* __CARL9170_SHARED_VERSION_H */
EOF
