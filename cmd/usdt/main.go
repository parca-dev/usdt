// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

// usdt is a command-line tool for inspecting USDT probes in ELF binaries.
//
// Usage:
//
//	usdt list <binary> [flags]
//	usdt parse-args <arg-string>
package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/parca-dev/usdt"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "list":
		os.Exit(cmdList(os.Args[2:]))
	case "parse-args":
		os.Exit(cmdParseArgs(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: usdt <command> [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  list <binary>    List USDT probes in an ELF binary")
	fmt.Fprintln(os.Stderr, "  parse-args <str> Parse a USDT argument specification string")
}

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	provider := fs.String("provider", "", "filter by provider name")
	name := fs.String("name", "", "filter by probe name")
	showArgs := fs.Bool("args", false, "show raw argument strings")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: usdt list [flags] <binary>")
		fs.PrintDefaults()
		return 1
	}

	binary := fs.Arg(0)
	probes, err := usdt.ParseProbesFromFile(binary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if *showArgs {
		fmt.Fprintln(w, "PROVIDER\tNAME\tLOCATION\tSEMAPHORE\tARGUMENTS")
	} else {
		fmt.Fprintln(w, "PROVIDER\tNAME\tLOCATION\tSEMAPHORE")
	}

	count := 0
	for _, p := range probes {
		if *provider != "" && p.Provider != *provider {
			continue
		}
		if *name != "" && p.Name != *name {
			continue
		}
		sema := "-"
		if p.SemaphoreOffset != 0 {
			sema = fmt.Sprintf("0x%x", p.SemaphoreOffset)
		}
		if *showArgs {
			fmt.Fprintf(w, "%s\t%s\t0x%x\t%s\t%s\n", p.Provider, p.Name, p.Location, sema, p.Arguments)
		} else {
			fmt.Fprintf(w, "%s\t%s\t0x%x\t%s\n", p.Provider, p.Name, p.Location, sema)
		}
		count++
	}
	w.Flush()

	if count == 0 {
		fmt.Fprintln(os.Stderr, "no probes found")
		return 1
	}
	return 0
}

func cmdParseArgs(args []string) int {
	// No flags for this subcommand — the argument string itself may start
	// with '-' (e.g. "-4@%esi"), so skip flag parsing entirely.
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: usdt parse-args <argument-string>")
		return 1
	}

	argStr := args[0]
	spec, err := usdt.ParseUSDTArguments(argStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fmt.Printf("argument count: %d\n", spec.Arg_cnt)
	for i := 0; i < int(spec.Arg_cnt); i++ {
		a := spec.Args[i]
		argTypeName := "unknown"
		switch a.Arg_type {
		case usdt.ArgConst:
			argTypeName = "const"
		case usdt.ArgReg:
			argTypeName = "reg"
		case usdt.ArgRegDeref:
			argTypeName = "reg_deref"
		}
		signed := ""
		if a.Arg_signed {
			signed = " signed"
		}
		float := ""
		if a.Arg_is_float {
			float = " float"
		}
		fmt.Printf("  [%d] type=%-9s reg=%3d val_off=%-6d bitshift=%d%s%s\n",
			i, argTypeName, a.Reg_id, int64(a.Val_off), a.Arg_bitshift, signed, float)
	}
	return 0
}
