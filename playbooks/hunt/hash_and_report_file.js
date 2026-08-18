// Safe-default playbook.
// Requires: read access to the target path.
// Purpose: collect file metadata and hashes for a suspicious path from alert context.

const target =
  (alert && (alert.file_path || alert.path || (alert.payload && alert.payload.path))) || "";

if (!target) {
  throw new Error("hash_and_report_file: missing alert file path");
}

const info = fileInfo(target, { hash: true });

reportProgress({
  stage: "hashed",
  path: target,
  size: info.size,
});

console.log(
  JSON.stringify({
    ok: true,
    action: "hash_and_report_file",
    file: info,
  })
);
