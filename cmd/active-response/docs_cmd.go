package main

// docSubcommands returns a concise description of CLI/agent subcommands and payload expectations.
func docSubcommands() string {
	return `active-response modes:
  - CLI: active-response -h | active-response update [--check|--manifest-url ...] | active-response docs
  - Agent: reads JSON from stdin; payload.parameters.extraArgs[0] selects subcommand
Subcommands:
  ar-updater              no payload (requires enable_remote_updates build tag)
  block-ip <ip>           payload.parameters.extraArgs[1]=IP
  unblock-ip <ip>         payload.parameters.extraArgs[1]=IP
  get-info-av             none
  kill-ramsomeware        none (file deletion requires unsafe_features build tag)
  get-md5 <path>          payload.parameters.extraArgs[1]=file path
  run-command             alert.data.command executes via shell (requires unsafe_features build tag)
  js                      alert.data.script (string), mqtt-url/username/password, agent/manager, reply_to, correlation_id (results sent via MQTT reply_to; helper availability depends on build tags)
Examples (stdin payloads):
{"payload":{"parameters":{"extraArgs":["run-command"],"alert":{"data":{"command":"whoami"}}}}}
{"payload":{"parameters":{"extraArgs":["block-ip","1.2.3.4"]}}}
{"payload":{"parameters":{"extraArgs":["js"],"alert":{"data":{"script":"console.log('hi')","mqtt-url":"mqtt://broker","mqtt-username":"u","mqtt-password":"p","agent":"agent-1","manager":"mgr","reply_to":"resp","correlation_id":"cid-123"}}}}}`
}
