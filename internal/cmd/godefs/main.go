// Program godefs invokes CGo to generate static type definitions from C headers.
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/cilium/ebpf/internal"
)

func run(args []string) error {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: godefs <output> [cgo -godefs flags and arguments]")
		return fmt.Errorf("expected at least one argument")
	}

	output := args[0]
	args = args[1:]

	fmt.Println("Generating", output)

	var buf bytes.Buffer
	cgo := exec.Command("go", "tool", "cgo", "-godefs")
	cgo.Args = append(cgo.Args, args...)
	cgo.Stderr = os.Stderr
	cgo.Stdout = &buf
	if err := cgo.Run(); err != nil {
		return err
	}

	formatted, err := internal.FormatGoSource(buf.Bytes())
	if err != nil {
		return err
	}

	return os.WriteFile(output, formatted, 0666)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
