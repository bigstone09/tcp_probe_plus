#!/bin/bash
USAGE="$0 <src file>"
if (( $# < 1 )); then
	echo $USAGE
	exit 0
fi
awk '$5==50 && $4 != $6 {print $0}' $1
