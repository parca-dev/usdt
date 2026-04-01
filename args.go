// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "github.com/parca-dev/usdt"

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unsafe"
)

// x86_64 register name to ID mapping
// Maps all register name variants (64-bit, 32-bit, 16-bit, 8-bit) to register IDs
var x86_64RegNameToID = map[string]Register{
	"rax": RegRax, "eax": RegRax, "ax": RegRax, "al": RegRax,
	"rbx": RegRbx, "ebx": RegRbx, "bx": RegRbx, "bl": RegRbx,
	"rcx": RegRcx, "ecx": RegRcx, "cx": RegRcx, "cl": RegRcx,
	"rdx": RegRdx, "edx": RegRdx, "dx": RegRdx, "dl": RegRdx,
	"rsi": RegRsi, "esi": RegRsi, "si": RegRsi, "sil": RegRsi,
	"rdi": RegRdi, "edi": RegRdi, "di": RegRdi, "dil": RegRdi,
	"rbp": RegRbp, "ebp": RegRbp, "bp": RegRbp, "bpl": RegRbp,
	"rsp": RegRsp, "esp": RegRsp, "sp": RegRsp, "spl": RegRsp,
	"r8": RegR8, "r8d": RegR8, "r8w": RegR8, "r8b": RegR8,
	"r9": RegR9, "r9d": RegR9, "r9w": RegR9, "r9b": RegR9,
	"r10": RegR10, "r10d": RegR10, "r10w": RegR10, "r10b": RegR10,
	"r11": RegR11, "r11d": RegR11, "r11w": RegR11, "r11b": RegR11,
	"r12": RegR12, "r12d": RegR12, "r12w": RegR12, "r12b": RegR12,
	"r13": RegR13, "r13d": RegR13, "r13w": RegR13, "r13b": RegR13,
	"r14": RegR14, "r14d": RegR14, "r14w": RegR14, "r14b": RegR14,
	"r15": RegR15, "r15d": RegR15, "r15w": RegR15, "r15b": RegR15,
	"rip": RegRip, "eip": RegRip, "ip": RegRip,
}

// ARM64 register name to ID mapping
// Maps all register name variants (64-bit and 32-bit) to register IDs
var arm64RegNameToID = map[string]Register{
	"x0": RegX0, "w0": RegX0,
	"x1": RegX1, "w1": RegX1,
	"x2": RegX2, "w2": RegX2,
	"x3": RegX3, "w3": RegX3,
	"x4": RegX4, "w4": RegX4,
	"x5": RegX5, "w5": RegX5,
	"x6": RegX6, "w6": RegX6,
	"x7": RegX7, "w7": RegX7,
	"x8": RegX8, "w8": RegX8,
	"x9": RegX9, "w9": RegX9,
	"x10": RegX10, "w10": RegX10,
	"x11": RegX11, "w11": RegX11,
	"x12": RegX12, "w12": RegX12,
	"x13": RegX13, "w13": RegX13,
	"x14": RegX14, "w14": RegX14,
	"x15": RegX15, "w15": RegX15,
	"x16": RegX16, "w16": RegX16,
	"x17": RegX17, "w17": RegX17,
	"x18": RegX18, "w18": RegX18,
	"x19": RegX19, "w19": RegX19,
	"x20": RegX20, "w20": RegX20,
	"x21": RegX21, "w21": RegX21,
	"x22": RegX22, "w22": RegX22,
	"x23": RegX23, "w23": RegX23,
	"x24": RegX24, "w24": RegX24,
	"x25": RegX25, "w25": RegX25,
	"x26": RegX26, "w26": RegX26,
	"x27": RegX27, "w27": RegX27,
	"x28": RegX28, "w28": RegX28,
	"x29": RegX29, "w29": RegX29, "fp": RegX29,
	"x30": RegX30, "w30": RegX30, "lr": RegX30,
	"sp": RegSP, "wsp": RegSP,
	"pc": RegPC,
}

// lookupRegister looks up a register ID by name based on the runtime architecture
func lookupRegister(regName string) (Register, bool) {
	switch runtime.GOARCH {
	case "amd64":
		if regID, ok := x86_64RegNameToID[regName]; ok {
			return regID, true
		}
	case "arm64":
		if regID, ok := arm64RegNameToID[regName]; ok {
			return regID, true
		}
	}
	return 0, false
}

// Regex patterns for parsing USDT argument specifications
// USDT argument format: SIZE@LOCATION where:
//
//	SIZE: byte size (negative for signed)
//	LOCATION: register (%rax), memory offset(%reg) or [reg, offset], or constant ($123 or 123)
var (
	// Memory dereference with offset - x86_64 syntax: -4@-1204(%rbp) or -4f@-1204(%rbp)
	regexRegDerefWithOffset = regexp.MustCompile(
		`^\s*(-?\d+)(f?)\s*@\s*(-?\d+)\s*\(\s*%([a-z0-9]+)\s*\)\s*$`)
	// Memory dereference with offset - ARM64 syntax: -4@[sp, 60] or 4@[x0, -8]
	regexRegDerefWithOffsetARM = regexp.MustCompile(
		`^\s*(-?\d+)(f?)\s*@\s*\[\s*([a-z0-9]+)\s*,\s*(-?\d+)\s*\]\s*$`)
	// Memory dereference without offset: 8@(%rsp) or 8f@(%rsp)
	regexRegDerefNoOffset = regexp.MustCompile(
		`^\s*(-?\d+)(f?)\s*@\s*\(\s*%([a-z0-9]+)\s*\)\s*$`)
	// Memory dereference without offset - ARM64 syntax: 8@[x0] or 8f@[sp]
	regexRegDerefNoOffsetARM = regexp.MustCompile(
		`^\s*(-?\d+)(f?)\s*@\s*\[\s*([a-z0-9]+)\s*\]\s*$`)
	// Immediate constant with dollar sign: -4@$5 or -4@$-9 or -4f@$5
	regexConst = regexp.MustCompile(`^\s*(-?\d+)(f?)\s*@\s*\$(-?\d+)\s*$`)
	// Bare constant (no dollar sign): -4@100 or 4@0 or -4f@100
	// Note: Must be checked BEFORE regexReg since regexReg would also match bare numbers
	regexBareConst = regexp.MustCompile(`^\s*(-?\d+)(f?)\s*@\s*(-?\d+)\s*$`)
	// Register value: 8@%rax or -4@%edi or -4f@%edi or 8@x0 (ARM64)
	regexReg = regexp.MustCompile(`^\s*(-?\d+)(f?)\s*@\s*%?([a-z0-9]+)\s*$`)
)

// https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
// ParseUSDTArgSpec parses a single USDT argument specification string
// Examples: "-4@-1204(%rbp)", "8@%rax", "-4@$5", "-4@100", "8@(%rsp)", "-8f@%xmm0"
func ParseUSDTArgSpec(argStr string) (*ArgSpec, error) {
	argStr = strings.TrimSpace(argStr)
	if argStr == "" {
		return nil, errors.New("empty argument string")
	}

	spec := &ArgSpec{}

	// Try memory dereference with offset first (x86_64 syntax)
	if matches := regexRegDerefWithOffset.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		offset, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid memory offset: %w", err)
		}
		regName := matches[4]

		spec.Arg_type = ArgRegDeref
		spec.Val_off = uint64(offset)
		regID, ok := lookupRegister(regName)
		if !ok {
			return nil, fmt.Errorf("unknown register: %s", regName)
		}
		spec.Reg_id = regID
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try memory dereference with offset (ARM64 bracket syntax)
	if matches := regexRegDerefWithOffsetARM.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		regName := matches[3]
		offset, err := strconv.ParseInt(matches[4], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid memory offset: %w", err)
		}

		spec.Arg_type = ArgRegDeref
		spec.Val_off = uint64(offset)
		regID, ok := lookupRegister(regName)
		if !ok {
			return nil, fmt.Errorf("unknown register: %s", regName)
		}
		spec.Reg_id = regID
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try memory dereference without offset
	if matches := regexRegDerefNoOffset.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		regName := matches[3]

		spec.Arg_type = ArgRegDeref
		spec.Val_off = 0
		regID, ok := lookupRegister(regName)
		if !ok {
			return nil, fmt.Errorf("unknown register: %s", regName)
		}
		spec.Reg_id = regID
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try memory dereference without offset (ARM64 bracket syntax)
	if matches := regexRegDerefNoOffsetARM.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		regName := matches[3]

		spec.Arg_type = ArgRegDeref
		spec.Val_off = 0
		regID, ok := lookupRegister(regName)
		if !ok {
			return nil, fmt.Errorf("unknown register: %s", regName)
		}
		spec.Reg_id = regID
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try immediate constant with dollar sign
	if matches := regexConst.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		constVal, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid constant value: %w", err)
		}

		spec.Arg_type = ArgConst
		spec.Val_off = uint64(constVal)
		spec.Reg_id = RegNone
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try bare constant (no dollar sign) - must be checked before regexReg
	if matches := regexBareConst.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		constVal, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid constant value: %w", err)
		}

		spec.Arg_type = ArgConst
		spec.Val_off = uint64(constVal)
		spec.Reg_id = RegNone
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try register value
	if matches := regexReg.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		regName := matches[3]

		spec.Arg_type = ArgReg
		spec.Val_off = 0
		regID, ok := lookupRegister(regName)
		if !ok {
			return nil, fmt.Errorf("unknown register: %s", regName)
		}
		spec.Reg_id = regID
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	return nil, fmt.Errorf("unrecognized argument format: %s", argStr)
}

// splitUSDTArgs splits a USDT argument string into individual argument specifications.
// Unlike strings.Fields, this preserves spaces inside brackets for ARM64 syntax like "4@[sp, 44]".
func splitUSDTArgs(argString string) []string {
	var args []string
	var current strings.Builder
	inBrackets := false

	for _, ch := range argString {
		switch ch {
		case '[':
			inBrackets = true
			current.WriteRune(ch)
		case ']':
			inBrackets = false
			current.WriteRune(ch)
		case ' ', '\t', '\n', '\r':
			if inBrackets {
				// Preserve spaces inside brackets
				current.WriteRune(ch)
			} else if current.Len() > 0 {
				// End of argument outside brackets
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(ch)
		}
	}

	// Add final argument if any
	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

// ParseUSDTArguments parses a USDT argument specification string into a Spec.
// The argument string is space-separated (e.g., "-4@%esi -4@-24(%rbp) -4@%ecx").
// For ARM64, brackets can contain spaces (e.g., "4@[sp, 44] 8@[x0, -8]").
func ParseUSDTArguments(argString string) (*Spec, error) {
	argString = strings.TrimSpace(argString)
	if argString == "" {
		// No arguments is valid
		return &Spec{Arg_cnt: 0}, nil
	}

	// Split by whitespace, but preserve spaces inside brackets
	argStrs := splitUSDTArgs(argString)
	if len(argStrs) > 12 {
		return nil, fmt.Errorf("too many arguments: %d (max 12)", len(argStrs))
	}

	spec := &Spec{
		Arg_cnt: int16(len(argStrs)),
	}

	for i, argStr := range argStrs {
		argSpec, err := ParseUSDTArgSpec(argStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse argument %d (%s): %w", i, argStr, err)
		}
		spec.Args[i] = *argSpec
	}

	return spec, nil
}

// SpecToBytes converts Spec to byte slice for BPF map updates.
func SpecToBytes(s *Spec) []byte {
	size := int(unsafe.Sizeof(*s))
	return unsafe.Slice((*byte)(unsafe.Pointer(s)), size)
}
