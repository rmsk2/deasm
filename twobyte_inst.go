package main

import (
	"fmt"
	"io"
)

type TwoByteFormatterFunc func(m string, oper byte, addr uint16) (string, int)

type TwoByteInstruction struct {
	opCodes          map[byte]string
	separatorOpCodes map[byte]bool
	formatter        TwoByteFormatterFunc
	name             string
}

func (t *TwoByteInstruction) AddOpCode(o byte, mnemonic string) {
	t.opCodes[o] = mnemonic
}

func (t *TwoByteInstruction) AddOpCodeSeparator(o byte, mnemonic string) {
	t.opCodes[o] = mnemonic
	t.separatorOpCodes[o] = true
}

func (t *TwoByteInstruction) GetName() string {
	return t.name
}

func (t *TwoByteInstruction) GetOpCodes() map[byte]string {
	return t.opCodes
}

func NewTwoByteMode(f TwoByteFormatterFunc, n string) *TwoByteInstruction {
	return &TwoByteInstruction{
		opCodes:          make(map[byte]string),
		separatorOpCodes: make(map[byte]bool),
		formatter:        f,
		name:             n,
	}
}

func NewImmediateMode() *TwoByteInstruction {
	f := func(m string, oper byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s #$%02x", m, oper), IllegalAddress
	}

	return NewTwoByteMode(f, "Immediate")
}

func NewZeroPage() *TwoByteInstruction {
	f := func(m string, oper byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s $%02x", m, oper), IllegalAddress
	}

	return NewTwoByteMode(f, "Zero page")
}

func NewZeroPageX() *TwoByteInstruction {
	f := func(m string, oper byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s $%02x,x", m, oper), IllegalAddress
	}

	return NewTwoByteMode(f, "Zero page, x")
}

func NewZeroPageY() *TwoByteInstruction {
	f := func(m string, oper byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s $%02x,y", m, oper), IllegalAddress
	}

	return NewTwoByteMode(f, "Zero page, y")
}

func NewIndirectY() *TwoByteInstruction {
	f := func(m string, oper byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s ($%02x),y", m, oper), IllegalAddress
	}

	return NewTwoByteMode(f, "Indirect, y")
}

func NewIndirectX() *TwoByteInstruction {
	f := func(m string, oper byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s ($%02x,x)", m, oper), IllegalAddress
	}

	return NewTwoByteMode(f, "Indirect, x")
}

func NewZPIndirect() *TwoByteInstruction {
	f := func(m string, oper byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s ($%02x)", m, oper), IllegalAddress
	}

	return NewTwoByteMode(f, "Zero page indirect")
}

func NewRelative() *TwoByteInstruction {
	f := func(m string, oper byte, addr uint16) (string, int) {
		var offset int8 = int8(oper)

		return m, int(uint16((int16(addr) + 2 + int16(offset))))
	}

	return NewTwoByteMode(f, "Relative")
}

func (t *TwoByteInstruction) Recognize(opCode byte) bool {
	_, ok := t.opCodes[opCode]

	return ok
}

func (t *TwoByteInstruction) Parse(opCode byte, addr uint16, r io.ByteReader, l *LabelMapStruct) (Instruction, error) {
	v, ok := t.opCodes[opCode]
	if !ok {
		return Instruction{}, fmt.Errorf("unparseable instruction %02X", opCode)
	}

	_, sep := t.separatorOpCodes[opCode]

	operand, err := r.ReadByte()
	if err != nil {
		return Instruction{
			Addr:       addr,
			Mnemonic:   fmt.Sprintf("%s ???", v),
			Raw:        []byte{opCode},
			TargetAddr: IllegalAddress,
			Separator:  sep,
		}, nil
	}

	newMnemonic, target := t.formatter(v, operand, addr)

	if target >= 0 {
		l.AddAddress(target)
	}

	return Instruction{
		Addr:       addr,
		Mnemonic:   newMnemonic,
		Raw:        []byte{opCode, operand},
		TargetAddr: target,
		Separator:  sep,
	}, nil
}
