#!/bin/sh
# Install ks into ~/.local/bin and run it as a systemd user service on 127.0.0.1:7733.
# Usage: scripts/install.sh [path/to/ks]   (default: build from this checkout)
set -eu
cd "$(dirname "$0")/.."
bin="${1:-}"
if [ -z "$bin" ]; then
	command -v go >/dev/null || { echo "go is needed to build; or pass a downloaded ks binary" >&2; exit 1; }
	version="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$version" -o ./ks ./cmd/ks
	bin=./ks
fi
install -d -m 0755 "$HOME/.local/bin"
install -m 0755 "$bin" "$HOME/.local/bin/ks"
install -d -m 0700 "$HOME/.local/share/keyshelf" "$HOME/.config/keyshelf"
install -d -m 0755 "$HOME/.config/systemd/user"
install -m 0644 deploy/keyshelf.service "$HOME/.config/systemd/user/keyshelf.service"
systemctl --user daemon-reload
systemctl --user enable keyshelf.service >/dev/null
systemctl --user restart keyshelf.service
echo "keyshelf $("$HOME/.local/bin/ks" version) installed and started (sealed)."
sleep 1
if "$HOME/.local/bin/ks" status 2>/dev/null | grep -q "not initialised"; then
	echo "First time? In your own terminal run:  ks init  then  ks unseal"
else
	echo "Run:  ks unseal"
fi
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "Add ~/.local/bin to your PATH." ;; esac
if [ "$(loginctl show-user "$(id -u)" -p Linger --value 2>/dev/null)" != "yes" ]; then
	echo "Note: the service runs while you are logged in. To keep it running without a session: loginctl enable-linger"
fi
