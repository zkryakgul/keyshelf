package main

import (
	"fmt"
	"io"
	"strings"

	"rsc.io/qr"
)

// printer writes the CLI's human-facing messages. Colours are used only on a terminal and never when
// NO_COLOR is set, so piped output and logs stay plain.
type printer struct {
	w     io.Writer
	color bool
}

func (a *app) printer() printer { return printer{w: a.stdout, color: a.color} }

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
)

func (p printer) paint(code, s string) string {
	if !p.color {
		return s
	}
	return code + s + cReset
}

func (p printer) line(mark, code, format string, args ...any) {
	fmt.Fprintf(p.w, "%s %s\n", p.paint(code, mark), fmt.Sprintf(format, args...))
}

func (p printer) title(format string, args ...any) {
	fmt.Fprintf(p.w, "\n%s\n", p.paint(cBold, fmt.Sprintf(format, args...)))
}
func (p printer) step(format string, args ...any) { p.line("→", cCyan, format, args...) }
func (p printer) ok(format string, args ...any)   { p.line("✓", cGreen, format, args...) }
func (p printer) warn(format string, args ...any) { p.line("!", cYellow, format, args...) }
func (p printer) info(format string, args ...any) { p.line("•", cDim, format, args...) }
func (p printer) cmd(s string) {
	fmt.Fprintf(p.w, "    %s %s\n", p.paint(cDim, "$"), p.paint(cBold, s))
}

// box prints s framed, for things the owner must copy down (the recovery code).
func (p printer) box(s string) {
	edge := ""
	for range len(s) + 4 {
		edge += "─"
	}
	fmt.Fprintf(p.w, "\n    %s\n    %s  %s  %s\n    %s\n\n",
		p.paint(cYellow, "┌"+edge+"┐"), p.paint(cYellow, "│"), p.paint(cBold, s), p.paint(cYellow, "│"), p.paint(cYellow, "└"+edge+"┘"))
}

// qr draws a QR code with half blocks: each character is two modules stacked. On a terminal the colours are set
// explicitly (black on white) so the code scans on dark and light themes alike.
func (p printer) qr(text string) error {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	const quiet = 2 // modules of white border; Black is false outside the code
	var b strings.Builder
	for y := -quiet; y < code.Size+quiet; y += 2 {
		b.WriteString("    ")
		for x := -quiet; x < code.Size+quiet; x++ {
			top, bottom := code.Black(x, y), code.Black(x, y+1)
			if p.color {
				fmt.Fprintf(&b, "\033[38;5;%dm\033[48;5;%dm▀", shade(top), shade(bottom))
				continue
			}
			// Plain output assumes light text on a dark background: a drawn block is a white module.
			switch {
			case !top && !bottom:
				b.WriteString("█")
			case !top:
				b.WriteString("▀")
			case !bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		if p.color {
			b.WriteString(cReset)
		}
		b.WriteString("\n")
	}
	_, err = fmt.Fprint(p.w, b.String())
	return err
}

func shade(black bool) int {
	if black {
		return 16 // xterm-256 pure black
	}
	return 231 // xterm-256 pure white
}
