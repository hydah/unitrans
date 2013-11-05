#!/bin/sh

UNITRANS_DIR="/home/jianing/unitrans/unitrans-0.4"
SPEC_DIR="/home/jianing/unitrans/ref-static"
CONF=opt-def.h

function set_val
{
	echo "$1 $2"
	if[$1 == "true"]; then
		sed -i "s/.*define.*\<$1\>.*/#define\t$1/" $CONF
	else
		sed -i "s/.*define.*\<$1\>.*/\/\/#define\t$1/" $CONF
	fi
		
}

function chg_val 
{
	echo "$1, $2"
	sed "s/\(.*\<$1\>\).*/\1\t$2/"
}

function build
{
	cd $UNITRANS_DIR
	make
	if [$? != 0]; then
		echo build err
		exit
	fi
}

function run_spec
{
	cd $SPEC_DIR
        ./ind-prof-run.sh
}

chg_val PATH_DEPTH 2


