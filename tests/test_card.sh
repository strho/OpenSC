#! /bin/sh

usage() { 
	printf "\nUsage:\n\t $0 -m module_path -t [PKCS15, PIV] [-s so_pin]\n"
	printf "\t -m  module_path:\tpath to tested module (e.g. /usr/lib64/opensc-pkcs11.so)\n"
	printf "\t -s  so_pin:\t\tSecurity Officer PIN to token\n"
	printf "\t -t  card_type:\t\tcard type, supported are PKCS15 and PIV\n\n"
	exit 1; 
}

echo
echo "Current directory: $(pwd)"

MODULE=
TYPE=
SO_PIN=""
OPT_ARGS=
TEST_APP="./pkcs11_tests"

while getopts "m:t:s:" o; do
    case "${o}" in
    m)
        MODULE=${OPTARG}
	    ;;
	t)
        if test $OPTARG == "PIV"; then
            TYPE=$OPTARG
        elif test $OPTARG == "PKCS15"; then
		    TYPE=$OPTARG
		else
		    echo "Wrong card type."
		    usage
		    exit 77
		fi
	    ;;
	s)
        SO_PIN=${OPTARG}
	    ;;
    *)
        usage
        ;;
    esac
done
shift $((OPTIND-1))

echo "Module: $MODULE"
echo "Card type: $TYPE"

if test "x$MODULE" == "x"; then
	echo "Module is required parameter"
	usage
	exit 77
fi

if test "x$TYPE" == "x"; then
	echo "Card type is required parameter"
	usage
	exit 77
fi

if test "$TYPE" == "PIV"; then
    if ! type "yubico-piv-tool" > /dev/null 2>&1; then
        echo "Command line tool 'yubico-piv-tool' doesn't exists and has to be installed."
        exit 77
    fi
elif test "$TYPE" == "PKCS15"; then

    if test "x$SO_PIN" == "x"; then
        echo "SO PIN has to be specified for PKCS#15 tokens"
        exit 77
    else
        OPT_ARGS="-s $SO_PIN"
    fi

    if ! type "pkcs15-init" > /dev/null 2>&1; then
        echo "Command line tool 'pkcs15-init' doesn't exists and has to be installed."
        exit 77
    fi

    if ! type "pkcs11-tool" > /dev/null 2>&1; then
        echo "Command line tool 'pkcs11-tool' doesn't exists and has to be installed."
        exit 77
    fi
fi

if ! test -x $MODULE; then
	echo "Module '$MODULE' doesn't exists"
	exit 77
fi

echo "Module for testing is: $MODULE"
echo

if ! test -x $TEST_APP; then
	echo "Smartcard test suite has to be build first"
	echo "Run 'cmake . && make'"
	exit 77
fi

$TEST_APP -m $MODULE -t $TYPE $OPT_ARGS
