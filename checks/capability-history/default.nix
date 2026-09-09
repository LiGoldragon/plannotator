{ lib, runCommand, bun, src }:

runCommand "plannotator-capability-history-check" {
  nativeBuildInputs = [ bun ];
  source = lib.fileset.toSource {
    root = src;
    fileset = lib.fileset.unions [
      (src + /package.json)
      (src + /packages/core)
      (src + /packages/capability-history)
    ];
  };
} ''
  cp -R "$source" source
  chmod -R u+w source
  cd source/packages/capability-history
  timeout 30s bun test broker.test.ts private-authority.test.ts unix-server.test.ts
  touch "$out"
''
