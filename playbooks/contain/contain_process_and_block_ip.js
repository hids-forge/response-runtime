// Safe-default playbook.
// Purpose: kill a suspicious process and block a related source IP when both are present.

const pidValue =
  alert && (alert.pid || alert.process_id || (alert.payload && alert.payload.pid));
const pid = Number(pidValue || 0);
const sourceIp =
  alert &&
  (alert.srcip ||
    alert.source_ip ||
    (alert.payload && (alert.payload.srcip || alert.payload.source_ip)));

const result = {
  ok: true,
  action: "contain_process_and_block_ip",
};

if (pid) {
  result.process = killProcess(pid);
  reportProgress({
    stage: "process-contained",
    pid,
  });
}

if (sourceIp) {
  firewall.blockIp(sourceIp);
  result.blockedIp = sourceIp;
  reportProgress({
    stage: "ip-blocked",
    ip: sourceIp,
  });
}

if (!pid && !sourceIp) {
  throw new Error("contain_process_and_block_ip: missing pid and source IP");
}

console.log(JSON.stringify(result));
