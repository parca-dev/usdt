// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

package usdt

import (
	"runtime"
	"testing"
)

func TestParseUSDTArgSpec_Common(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ArgSpec
		wantErr  bool
	}{
		{
			name:  "constant with dollar",
			input: "-4@$5",
			expected: ArgSpec{
				Arg_type:   ArgConst,
				Val_off:    5,
				Reg_id:     RegNone,
				Arg_signed: true,
				Arg_bitshift: 32,
			},
		},
		{
			name:  "signed constant negative",
			input: "-4@$-9",
			expected: ArgSpec{
				Arg_type:     ArgConst,
				Val_off:      ^uint64(9 - 1), // uint64(-9)
				Reg_id:       RegNone,
				Arg_signed:   true,
				Arg_bitshift: 32,
			},
		},
		{
			name:  "float constant",
			input: "-4f@$5",
			expected: ArgSpec{
				Arg_type:     ArgConst,
				Val_off:      5,
				Reg_id:       RegNone,
				Arg_signed:   true,
				Arg_is_float: true,
				Arg_bitshift: 32,
			},
		},
		{
			name:  "bare constant",
			input: "-4@100",
			expected: ArgSpec{
				Arg_type:   ArgConst,
				Val_off:    100,
				Reg_id:     RegNone,
				Arg_signed: true,
				Arg_bitshift: 32,
			},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseUSDTArgSpec(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseUSDTArgSpec(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			compareArgSpec(t, tt.input, got, &tt.expected)
		})
	}
}

func TestParseUSDTArgSpec_AMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("AMD64-specific test")
	}

	tests := []struct {
		name     string
		input    string
		expected ArgSpec
		wantErr  bool
	}{
		{
			name:  "register deref with negative offset",
			input: "-4@-1204(%rbp)",
			expected: ArgSpec{
				Arg_type:     ArgRegDeref,
				Val_off:      ^uint64(1204 - 1), // uint64(-1204)
				Reg_id:       RegRbp,
				Arg_signed:   true,
				Arg_bitshift: 32,
			},
		},
		{
			name:  "signed 4-byte argument",
			input: "-4@%esi",
			expected: ArgSpec{
				Arg_type:   ArgReg,
				Reg_id:     RegRsi,
				Arg_signed: true,
				Arg_bitshift: 32,
			},
		},
		{
			name:  "8-byte register",
			input: "8@%rax",
			expected: ArgSpec{
				Arg_type:   ArgReg,
				Reg_id:     RegRax,
				Arg_signed: false,
				Arg_bitshift: 0,
			},
		},
		{
			name:  "memory deref no offset",
			input: "8@(%rsp)",
			expected: ArgSpec{
				Arg_type:   ArgRegDeref,
				Reg_id:     RegRsp,
				Arg_signed: false,
				Arg_bitshift: 0,
			},
		},
		{
			name:  "float memory deref",
			input: "-8f@-8(%rbp)",
			expected: ArgSpec{
				Arg_type:     ArgRegDeref,
				Val_off:      ^uint64(8 - 1), // uint64(-8)
				Reg_id:       RegRbp,
				Arg_signed:   true,
				Arg_is_float: true,
				Arg_bitshift: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseUSDTArgSpec(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseUSDTArgSpec(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			compareArgSpec(t, tt.input, got, &tt.expected)
		})
	}
}

func TestParseUSDTArgSpec_ARM64(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("ARM64-specific test")
	}

	tests := []struct {
		name     string
		input    string
		expected ArgSpec
		wantErr  bool
	}{
		{
			name:  "bracket syntax with offset",
			input: "4@[sp, 60]",
			expected: ArgSpec{
				Arg_type:   ArgRegDeref,
				Val_off:    60,
				Reg_id:     RegSP,
				Arg_signed: false,
				Arg_bitshift: 32,
			},
		},
		{
			name:  "bracket syntax with negative offset",
			input: "4@[x0, -8]",
			expected: ArgSpec{
				Arg_type:     ArgRegDeref,
				Val_off:      ^uint64(8 - 1), // uint64(-8)
				Reg_id:       RegX0,
				Arg_signed:   false,
				Arg_bitshift: 32,
			},
		},
		{
			name:  "register value",
			input: "8@x0",
			expected: ArgSpec{
				Arg_type:   ArgReg,
				Reg_id:     RegX0,
				Arg_signed: false,
				Arg_bitshift: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseUSDTArgSpec(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseUSDTArgSpec(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			compareArgSpec(t, tt.input, got, &tt.expected)
		})
	}
}

func TestParseUSDTArguments(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("AMD64-specific test")
	}

	tests := []struct {
		name    string
		input   string
		argCnt  int
		wantErr bool
	}{
		{
			name:   "empty string",
			input:  "",
			argCnt: 0,
		},
		{
			name:   "single argument",
			input:  "8@%rax",
			argCnt: 1,
		},
		{
			name:   "multiple arguments",
			input:  "-4@%esi -4@-24(%rbp) -4@%ecx",
			argCnt: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseUSDTArguments(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseUSDTArguments(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if int(got.Arg_cnt) != tt.argCnt {
				t.Errorf("arg count = %d, want %d", got.Arg_cnt, tt.argCnt)
			}
		})
	}
}

func TestSplitUSDTArgs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple space-separated",
			input:    "-4@%esi -4@-24(%rbp)",
			expected: []string{"-4@%esi", "-4@-24(%rbp)"},
		},
		{
			name:     "arm64 brackets preserved",
			input:    "4@[sp, 60] 8@[x0, -8]",
			expected: []string{"4@[sp, 60]", "8@[x0, -8]"},
		},
		{
			name:     "empty",
			input:    "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitUSDTArgs(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("splitUSDTArgs(%q) = %v, want %v", tt.input, got, tt.expected)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("arg[%d] = %q, want %q", i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func compareArgSpec(t *testing.T, input string, got, expected *ArgSpec) {
	t.Helper()
	if got.Arg_type != expected.Arg_type {
		t.Errorf("ParseUSDTArgSpec(%q).Arg_type = %d, want %d", input, got.Arg_type, expected.Arg_type)
	}
	if got.Val_off != expected.Val_off {
		t.Errorf("ParseUSDTArgSpec(%q).Val_off = %d, want %d", input, got.Val_off, expected.Val_off)
	}
	if got.Reg_id != expected.Reg_id {
		t.Errorf("ParseUSDTArgSpec(%q).Reg_id = %d, want %d", input, got.Reg_id, expected.Reg_id)
	}
	if got.Arg_signed != expected.Arg_signed {
		t.Errorf("ParseUSDTArgSpec(%q).Arg_signed = %v, want %v", input, got.Arg_signed, expected.Arg_signed)
	}
	if got.Arg_bitshift != expected.Arg_bitshift {
		t.Errorf("ParseUSDTArgSpec(%q).Arg_bitshift = %d, want %d", input, got.Arg_bitshift, expected.Arg_bitshift)
	}
	if got.Arg_is_float != expected.Arg_is_float {
		t.Errorf("ParseUSDTArgSpec(%q).Arg_is_float = %v, want %v", input, got.Arg_is_float, expected.Arg_is_float)
	}
}
