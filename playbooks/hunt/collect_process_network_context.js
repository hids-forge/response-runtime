// Safe-default playbook.
// Purpose: collect process details and network connections for a PID from alert context.

const pidValue =
  alert && (alert.pid || alert.process_id || (alert.payload && alert.payload.pid));
const pid = Number(pidValue || 0);

if (!pid) {
  throw new Error("collect_process_network_context: missing alert pid");
}

const processInfo = getProcessInfo(pid);
let connections = [];
let connectionError = "";

try {
  connections = processConnections(pid);
} catch (err) {
  connectionError = String(err);
}

reportProgress({
  stage: "collected",
  pid,
  connectionCount: connections.length,
});

console.log(
  JSON.stringify({
    ok: true,
    action: "collect_process_network_context",
    process: processInfo,
    connections,
    connectionError,
  })
);
