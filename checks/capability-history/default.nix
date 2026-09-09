{ lib, runCommand, bun, src }:

runCommand "plannotator-capability-history-check" {
  nativeBuildInputs = [ bun ];
  source = lib.fileset.toSource {
    root = src;
    fileset = lib.fileset.unions [
      (src + /package.json)
      (src + /bunfig.toml)
      (src + /packages/core)
      (src + /packages/capability-history)
    ];
  };
} ''
  cp -R "$source" source
  chmod -R u+w source
  cd source
  timeout 30s bun test \
    packages/capability-history/broker.test.ts \
    packages/capability-history/private-authority.test.ts \
    packages/capability-history/unix-server.test.ts
  touch "$out"
''
