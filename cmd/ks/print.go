package main

import (
	"fmt"
	"io"
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
