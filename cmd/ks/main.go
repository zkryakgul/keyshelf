// Command ks is keyshelf: the server (ks serve) and its command-line client in one binary.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	a := &app{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
		getenv: os.Getenv,
		isTTY:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		prompt: ttyPrompt,
		exec:   execReplace,
		copy:   copyToClipboard,
		color:  term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == "",
	}
	os.Exit(a.run(os.Args[1:]))
}

// ttyPrompt reads a line from the controlling terminal without echo. Without a terminal it fails, so
// an agent can never be the one typing a passphrase.
func ttyPrompt(label string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("this needs a terminal: the owner must type it")
	}
	defer tty.Close()
	fmt.Fprint(tty, label)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// execReplace replaces this process with the command, so the values live only in its environment.
func execReplace(argv0 string, argv, env []string) error {
	path, err := exec.LookPath(argv0)
	if err != nil {
		return err
	}
	return syscall.Exec(path, argv, env) // #nosec G204 -- ks run executes the command the user gave, by design
}

func copyToClipboard(v []byte) error {
	for _, c := range [][]string{{"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "--clipboard", "--input"}, {"pbcopy"}} {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		cmd := exec.Command(c[0], c[1:]...) // #nosec G204 -- fixed list of clipboard tools
		cmd.Stdin = strings.NewReader(string(v))
		return cmd.Run()
	}
	return errors.New("no clipboard tool found (wl-copy, xclip, xsel or pbcopy)")
}

func homeDir(getenv func(string) string, xdg, fallback string) string {
	if d := getenv(xdg); d != "" {
		return filepath.Join(d, "keyshelf")
	}
	h, err := os.UserHomeDir()
	if err != nil {
		h = "."
	}
	return filepath.Join(h, fallback, "keyshelf")
}
