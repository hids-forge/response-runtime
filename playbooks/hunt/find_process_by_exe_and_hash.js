// Safe-default playbook.
// Purpose: find running processes for an executable path and hash the executable when readable.

const exePath =
  (alert && (alert.exe || alert.path || (alert.payload && alert.payload.exe))) || "";

if (!exePath) {
  throw new Error("find_process_by_exe_and_hash: missing executable path");
}

const pids = pathToPid(exePath);
const details = [];

for (const pid of pids) {
  details.push(pidToPath(pid));
}

const hashes = {
  md5: getFileMd5(exePath),
  sha256: getFileSha256(exePath),
};

reportProgress({
  stage: "matched",
  exePath,
  pidCount: pids.length,
});

console.log(
  JSON.stringify({
    ok: true,
    action: "find_process_by_exe_and_hash",
    exePath,
    pids,
    details,
    hashes,
  })
);
