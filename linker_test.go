package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/go-quicktest/qt"
)

func TestFindReferences(t *testing.T) {
	progs := map[string]*ProgramSpec{
		"entrypoint": {
			Type: SocketFilter,
			Instructions: asm.Instructions{
				// Make sure the call doesn't happen at instruction 0
				// to exercise the relative offset calculation.
				asm.Mov.Reg(asm.R0, asm.R1),
				asm.Call.Label("my_func"),
				asm.Return(),
			},
			License: "MIT",
		},
		"my_other_func": {
			Instructions: asm.Instructions{
				asm.LoadImm(asm.R0, 1337, asm.DWord).WithSymbol("my_other_func"),
				asm.Return(),
			},
		},
		"my_func": {
			Instructions: asm.Instructions{
				asm.Call.Label("my_other_func").WithSymbol("my_func"),
				asm.Return(),
			},
		},
	}

	flattenPrograms(progs, []string{"entrypoint"})
	qt.Assert(t, qt.HasLen(progs["entrypoint"].Instructions, 7))
}

func TestSplitSymbols(t *testing.T) {
	// Splitting an empty insns results in an error.
	_, err := splitSymbols(asm.Instructions{})
	qt.Assert(t, qt.IsNotNil(err), qt.Commentf("empty insns"))

	// Splitting non-empty insns without a leading Symbol is an error.
	_, err = splitSymbols(asm.Instructions{
		asm.Return(),
	})
	qt.Assert(t, qt.IsNotNil(err), qt.Commentf("insns without leading Symbol"))

	// Non-empty insns with a single Instruction that is a Symbol.
	insns := asm.Instructions{
		asm.Return().WithSymbol("sym"),
	}
	m, err := splitSymbols(insns)
	qt.Assert(t, qt.IsNil(err), qt.Commentf("insns with a single Symbol"))

	qt.Assert(t, qt.HasLen(m, 1))
	qt.Assert(t, qt.HasLen(m["sym"], 1))

	// Insns containing duplicate Symbols.
	_, err = splitSymbols(asm.Instructions{
		asm.Return().WithSymbol("sym"),
		asm.Return().WithSymbol("sym"),
	})
	qt.Assert(t, qt.IsNotNil(err), qt.Commentf("insns containing duplicate Symbols"))

	// Insns with multiple Symbols and subprogs of various lengths.
	m, err = splitSymbols(asm.Instructions{
		asm.Return().WithSymbol("sym1"),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("sym2"),
		asm.Return(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("sym3"),
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("sym4"),
		asm.Mov.Imm(asm.R0, 1),
		asm.Mov.Imm(asm.R0, 2),
		asm.Return(),
	})
	qt.Assert(t, qt.IsNil(err), qt.Commentf("insns with multiple Symbols"))

	qt.Assert(t, qt.HasLen(m, 4))
	qt.Assert(t, qt.HasLen(m["sym1"], 1))
	qt.Assert(t, qt.HasLen(m["sym2"], 2))
	qt.Assert(t, qt.HasLen(m["sym3"], 3))
	qt.Assert(t, qt.HasLen(m["sym4"], 4))
}
