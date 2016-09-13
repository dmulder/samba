# Common tests
# Pulled out of existing tests to prevent duplication.
#
test_smbclient() {
	name="$1"
	cmd="$2"
	unc="$3"
	shift
	shift
	shift
	echo "test: $name"
	$VALGRIND $smbclient $CONFIGURATION "$unc" -c "$cmd" $@
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

test_smbclient_expect_failure() {
	name="$1"
	cmd="$2"
	unc="$3"
	shift
	shift
	shift
	echo "test: $name"
	$VALGRIND $smbclient $CONFIGURATION "$unc" -c "$cmd" $@
	status=$?
	if [ x$status = x0 ]; then
		echo "failure: $name"
	else
		echo "success: $name"
	fi
	return $status
}

kerberos_kinit() {
	kinit_tool="${1}"
	principal="${2}"
	password="${3}"
	shift 3
	kbase=$(basename ${kinit_tool})
	if [ ${kase} = "samba4kinit" ]; then
		kpassfile=$(mktemp)
		echo $password > ${kpassfile}
		$kinit_tool --password-file=$PREFIX/tmpuserpassfile $principal $@
		rm -f ${kpassfile}
	else
		echo $password | $kinit_tool $principal $@
	fi
}
