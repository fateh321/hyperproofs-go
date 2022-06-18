#!/usr/bin/env bash
set -e
shopt -s expand_aliases
alias time='date; time'

scriptdir=$(cd $(dirname $0); pwd -P)
sourcedir=$(cd $scriptdir/..; pwd -P)

CGO_ENABLED=1 go build -buildmode=c-shared -o libshard.so shard.go