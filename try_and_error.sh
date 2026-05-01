# 手元の テストコードを、ocp-jump8 に送り込み、make openshift-tests を実施してビルド、実行する。

TSTAMP=$(date +%y%m%d_%H%M%S)

diff="$(git diff)"
if [ "$diff" ] ; then
	stg new -m "$TSTAMP"
	stg refresh pkg/monitortests/monitoring/hapolicymanagement || exit 1
	git push ocp-jump8:tmp/origin/.git HEAD:tmp_$TSTAMP || exit 1
	cmd="cd tmp/origin ; git checkout tmp_$TSTAMP ; make openshift-tests"
	ssh ocp-jump8 "$cmd" || exit 1
fi
cmd="mkdir -p tmp/origin/tmp_$TSTAMP ; cd tmp/origin/tmp_$TSTAMP ; ../openshift-tests run-monitor --monitor ha-policy-management-checker 2>&1 | tee stdout.log"
ssh ocp-jump8 "$cmd" &
sleep 8
cmd="cd tmp/origin/tmp_$TSTAMP ; pkill -f -SIGINT '../openshift-tests run-monitor --monitor ha-policy-management-checker' ; sleep 20s ; ls -ltra > list"
ssh ocp-jump8 "$cmd"

# なんで二回実行しているんだっけ?
