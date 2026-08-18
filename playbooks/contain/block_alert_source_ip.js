// Safe-default playbook.
// Purpose: block a source IP from alert context using the built-in firewall helper.

const sourceIp =
  alert &&
  (alert.srcip ||
    alert.source_ip ||
    (alert.payload && (alert.payload.srcip || alert.payload.source_ip)));

if (!sourceIp) {
  throw new Error("block_alert_source_ip: missing source IP");
}

firewall.blockIp(sourceIp);

reportProgress({
  stage: "blocked",
  ip: sourceIp,
});

console.log(
  JSON.stringify({
    ok: true,
    action: "block_alert_source_ip",
    blockedIp: sourceIp,
  })
);
