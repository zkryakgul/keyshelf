package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"rsc.io/qr"
)

// decodeQR turns printer.qr output back into a module grid (true = black), including the quiet zone.
func decodeQR(t *testing.T, out string, color bool) [][]bool {
	t.Helper()
	var grid [][]bool
	cell := regexp.MustCompile(`\x1b\[38;5;(\d+)m\x1b\[48;5;(\d+)m▀`)
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		line = strings.TrimPrefix(line, "    ")
		var top, bottom []bool
		if color {
			for _, m := range cell.FindAllStringSubmatch(line, -1) {
				top, bottom = append(top, m[1] == "16"), append(bottom, m[2] == "16")
			}
		} else {
			for _, r := range line {
				top = append(top, r == ' ' || r == '▄')
				bottom = append(bottom, r == ' ' || r == '▀')
			}
		}
		grid = append(grid, top, bottom)
	}
	return grid
}

func TestQR(t *testing.T) {
	uri := "otpauth://totp/keyshelf:owner?digits=6&issuer=keyshelf&period=30&secret=" + strings.Repeat("A", 32)
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	for _, color := range []bool{true, false} {
		var buf bytes.Buffer
		if err := (printer{w: &buf, color: color}).qr(uri); err != nil {
			t.Fatal(err)
		}
		grid := decodeQR(t, buf.String(), color)
		const quiet = 2
		for y := -quiet; y < code.Size+quiet; y++ {
			for x := -quiet; x < code.Size+quiet; x++ {
				if got := grid[y+quiet][x+quiet]; got != code.Black(x, y) {
					t.Fatalf("color=%v module (%d,%d) = %v, want %v", color, x, y, got, code.Black(x, y))
				}
			}
		}
	}
}

func TestGroupKey(t *testing.T) {
	if got := groupKey("ABCDEFGHIJ"); got != "ABCD EFGH IJ" {
		t.Fatal(got)
	}
}
