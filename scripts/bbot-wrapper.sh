#!/bin/sh
set -eu

# BBOT couples its writable scan home and its dependency directory.  ARTEX runs
# scanners as an unprivileged executor with a per-deployment writable HOME, while
# production dependencies are immutable under /opt.  Link only the reviewed tool
# directory into the executor home and disable BBOT's runtime installers; scan
# output, cache and temporary files remain in the executor-owned home.
: "${HOME:?HOME must be set for the ARTEX executor}"
bbot_home="$HOME/.bbot"
mkdir -p "$bbot_home/cache" "$bbot_home/logs"

# BBOT 3.0.2 checks this cache marker before it checks
# deps.behavior=disable. The image build above asserts that every core binary
# and header represented by this exact, version-pinned dependency definition is
# already present. Compute the marker with BBOT's own code so a future pinned
# upgrade cannot silently inherit a stale hash, then create it only in the
# executor-owned cache. This prevents an unprivileged scan from attempting
# ansible-galaxy, apt, or sudo at runtime.
core_deps_hash=$(
  /opt/bbot/bin/python -c \
    'import mmh3, orjson; from bbot.core.helpers.depsinstaller.installer import DepsInstaller; print(mmh3.hash(orjson.dumps(DepsInstaller.CORE_DEPS, option=orjson.OPT_SORT_KEYS)))'
)
case "$core_deps_hash" in
  -[0-9]*|[0-9]*) ;;
  *)
    echo "bbot: invalid core dependency cache hash: $core_deps_hash" >&2
    exit 1
    ;;
esac
: >"$bbot_home/cache/$core_deps_hash"

tools_dir="$bbot_home/tools"
if [ -L "$tools_dir" ]; then
  echo "bbot: refusing symlinked writable tools directory: $tools_dir" >&2
  exit 1
fi
mkdir -p "$tools_dir"

# BBOT checks that its tools directory itself is writable even with dependency
# installation disabled. Keep that directory executor-owned and expose only the
# reviewed immutable entries from the image.
for tool_name in gowitness node retirejs; do
  tool_link="$tools_dir/$tool_name"
  immutable_tool="/opt/bbot-home/tools/$tool_name"
  if [ -e "$tool_link" ] && [ ! -L "$tool_link" ]; then
    echo "bbot: refusing non-symlink dependency entry: $tool_link" >&2
    exit 1
  fi
  if [ -L "$tool_link" ]; then
    linked_to=$(readlink "$tool_link")
    if [ "$linked_to" != "$immutable_tool" ]; then
      echo "bbot: refusing unexpected dependency link: $tool_link -> $linked_to" >&2
      exit 1
    fi
  else
    ln -s "$immutable_tool" "$tool_link"
  fi
done

exec /opt/bbot/bin/bbot "$@" --no-deps
