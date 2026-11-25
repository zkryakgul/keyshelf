#!/bin/sh
# keyshelf installer: downloads a release, verifies its SHA-256, installs ks into ~/.local/bin and, on Linux,
# runs it as a systemd user service on 127.0.0.1:7733. Running it again upgrades.
#
#   curl -fsSL https://github.com/zkryakgul/keyshelf/releases/latest/download/install.sh | sh
#
# Environment:  KS_VERSION=v0.1.1   a specific release (default: the latest)
#               KS_BIN_DIR=DIR      where ks goes (default: ~/.local/bin)
#               KS_NO_SERVICE=1     do not install or restart the systemd user service
#               NO_COLOR=1          plain output
# From a checkout:  scripts/install.sh --build      build from source (needs Go)
#                   scripts/install.sh path/to/ks   install a binary you already have
set -eu

REPO="zkryakgul/keyshelf"
BIN_DIR="${KS_BIN_DIR:-$HOME/.local/bin}"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/keyshelf"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/keyshelf"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

# ---- output ---------------------------------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	B=$(printf '\033[1m') D=$(printf '\033[2m') R=$(printf '\033[31m') G=$(printf '\033[32m')
	Y=$(printf '\033[33m') C=$(printf '\033[36m') N=$(printf '\033[0m')
else
	B='' D='' R='' G='' Y='' C='' N=''
fi
step() { printf '  %s→%s %s\n' "$C" "$N" "$*"; }
ok() { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
note() { printf '  %s•%s %s\n' "$D" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die() {
	printf '\n  %s✗ %s%s\n\n' "$R" "$*" "$N" >&2
	exit 1
}
cmd() { printf '      %s$%s %s%s%s\n' "$D" "$N" "$B" "$*" "$N"; }
section() { printf '\n  %s%s%s\n' "$B" "$*" "$N"; }

# ---- helpers --------------------------------------------------------------------------------------------

fetch() { # url dest
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --https-only -O "$2" "$1"
	else
		die "curl or wget is needed"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

latest_tag() {
	if command -v curl >/dev/null 2>&1; then
		url=$(curl -fsSLI --proto '=https' -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") || return 1
		echo "${url##*/}"
	else
		fetch "https://api.github.com/repos/$REPO/releases/latest" "$tmp/latest.json"
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1
	fi
}

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t keyshelf)
trap 'rm -rf "$tmp"' EXIT INT TERM

# ---- start ----------------------------------------------------------------------------------------------

printf '\n  %skeyshelf%s %s· installer%s\n' "$B" "$N" "$D" "$N"

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported system: $(uname -s) (Linux and macOS are supported)" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported CPU: $(uname -m) (amd64 and arm64 are supported)" ;;
esac

previous=""
if [ -x "$BIN_DIR/ks" ]; then
	previous=$("$BIN_DIR/ks" version 2>/dev/null | cut -d' ' -f2 || true)
fi

section "Getting ks"
unit=""
case "${1:-}" in
--build)
	[ -f go.mod ] && [ -d cmd/ks ] || die "--build must run from a keyshelf checkout"
	command -v go >/dev/null 2>&1 || die "Go is needed to build from source"
	tag=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
	step "Building $tag from source"
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$tag" -o "$tmp/ks" ./cmd/ks
	bin="$tmp/ks"
	[ -f deploy/keyshelf.service ] && unit=deploy/keyshelf.service
	ok "Built"
	;;
"")
	tag="${KS_VERSION:-}"
	if [ -z "$tag" ]; then
		step "Looking up the latest release"
		tag=$(latest_tag) || die "cannot reach github.com"
	fi
	case "$tag" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "not a release version: '$tag'" ;; esac
	name="ks_${tag}_${os}_${arch}"
	step "Downloading $name"
	fetch "https://github.com/$REPO/releases/download/$tag/$name.tar.gz" "$tmp/$name.tar.gz" ||
		die "download failed: is there a $tag release for $os/$arch?"
	fetch "https://github.com/$REPO/releases/download/$tag/SHA256SUMS" "$tmp/SHA256SUMS" || die "SHA256SUMS download failed"
	want=$(awk -v f="$name.tar.gz" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
	[ -n "$want" ] || die "SHA256SUMS has no entry for $name.tar.gz"
	[ "$(sha256 "$tmp/$name.tar.gz")" = "$want" ] || die "checksum mismatch: the download is not the published file"
	ok "Checksum verified"
	tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
	bin="$tmp/$name/ks"
	unit="$tmp/$name/keyshelf.service"
	;;
*)
	[ -f "$1" ] || die "no such file: $1"
	bin="$1"
	tag=$("$bin" version 2>/dev/null | cut -d' ' -f2 || echo unknown)
	[ -f deploy/keyshelf.service ] && unit=deploy/keyshelf.service
	;;
esac

section "Installing"
mkdir -p "$BIN_DIR"
cp "$bin" "$tmp/ks.new" && chmod 0755 "$tmp/ks.new" && mv -f "$tmp/ks.new" "$BIN_DIR/ks"
umask 077
mkdir -p "$DATA_DIR" "$CONFIG_DIR"
chmod 0700 "$DATA_DIR" "$CONFIG_DIR"
if [ -n "$previous" ] && [ "$previous" != "$tag" ]; then
	ok "ks $previous → $tag  ${D}($BIN_DIR/ks)${N}"
else
	ok "ks $tag  ${D}($BIN_DIR/ks)${N}"
fi

service=no
if [ "$os" = linux ] && [ -z "${KS_NO_SERVICE:-}" ] && command -v systemctl >/dev/null 2>&1 &&
	systemctl --user show-environment >/dev/null 2>&1; then
	if [ -z "$unit" ]; then
		fetch "https://raw.githubusercontent.com/$REPO/$tag/deploy/keyshelf.service" "$tmp/keyshelf.service" ||
			die "cannot fetch the systemd unit"
		unit="$tmp/keyshelf.service"
	fi
	mkdir -p "$UNIT_DIR"
	sed "s#%h/.local/bin/ks#$BIN_DIR/ks#" "$unit" >"$UNIT_DIR/keyshelf.service"
	chmod 0644 "$UNIT_DIR/keyshelf.service"
	systemctl --user daemon-reload
	systemctl --user enable keyshelf.service >/dev/null 2>&1
	systemctl --user restart keyshelf.service
	service=yes
	ok "Service running  ${D}(systemctl --user status keyshelf)${N}"
elif [ -n "${KS_NO_SERVICE:-}" ]; then
	note "Service skipped (KS_NO_SERVICE); start the server with ${B}ks serve${N}"
elif [ "$os" = darwin ]; then
	note "macOS: no service is installed; run ${B}ks serve${N} in a terminal (launchd support is planned)"
else
	note "No systemd user session here; start the server with ${B}ks serve${N}"
fi

# ---- what next ------------------------------------------------------------------------------------------

state=""
if [ "$service" = yes ]; then
	i=0
	while [ $i -lt 20 ]; do
		state=$("$BIN_DIR/ks" status 2>/dev/null | sed -n 's/^server:.*(\(.*\))$/\1/p') || true
		[ -n "$state" ] && break
		i=$((i + 1))
		sleep 0.25
	done
fi

section "Next"
case "$state" in
"not initialised")
	note "In ${B}your own terminal${N} (the recovery code is printed; do not run this through an agent):"
	cmd "ks init"
	cmd "ks unseal"
	cmd "ks login"
	cmd "ks token create claude --scope :list,read,write --save"
	;;
sealed)
	note "The service restarted and is sealed. Unseal it:"
	cmd "ks unseal"
	;;
unsealed)
	note "Ready."
	;;
*)
	if [ -f "$DATA_DIR/keyshelf.db" ]; then
		note "Start the server, then unseal:"
		cmd "ks unseal"
	else
		note "Start the server, then in your own terminal:"
		cmd "ks init"
	fi
	;;
esac
note "Web UI: ${B}http://127.0.0.1:7733${N}   ·   Updates: ${B}ks update${N}"

case ":$PATH:" in
*":$BIN_DIR:"*) ;;
*)
	warn "$BIN_DIR is not in your PATH. Add it, e.g.:"
	cmd "echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile"
	;;
esac
if [ "$service" = yes ] && command -v loginctl >/dev/null 2>&1 &&
	[ "$(loginctl show-user "$(id -u)" -p Linger --value 2>/dev/null || true)" = no ]; then
	note "The service runs while you are logged in. To keep it up without a session: ${B}loginctl enable-linger${N}"
fi
printf '\n'
