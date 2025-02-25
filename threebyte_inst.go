package main

import (
	"fmt"
	"io"
)

type ThreeByteFormatterFunc func(m string, oper1 byte, oper2 byte, addr uint16) (string, int)

type ThreeByteInstruction struct {
	opCodes          map[byte]string
	separatorOpCodes map[byte]bool
	formatter        ThreeByteFormatterFunc
	name             string
}

func (t *ThreeByteInstruction) AddOpCode(o byte, mnemonic string) {
	t.opCodes[o] = mnemonic
}

func (t *ThreeByteInstruction) GetName() string {
	return t.name
}

func (t *ThreeByteInstruction) GetOpCodes() map[byte]string {
	return t.opCodes
}

func makeAddr[V int | uint16](oper1, oper2 byte) V {
	return V(oper2)*256 + V(oper1)
}

func (t *ThreeByteInstruction) AddOpCodeSeparator(o byte, mnemonic string) {
	t.opCodes[o] = mnemonic
	t.separatorOpCodes[o] = true
}

func NewThreeByteMode(f ThreeByteFormatterFunc, n string) *ThreeByteInstruction {
	return &ThreeByteInstruction{
		opCodes:          make(map[byte]string),
		separatorOpCodes: make(map[byte]bool),
		formatter:        f,
		name:             n,
	}
}

func NewAbsoluteMode() *ThreeByteInstruction {
	f := func(m string, oper1 byte, oper2 byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s $%04x", m, makeAddr[uint16](oper1, oper2)), IllegalAddress
	}

	return NewThreeByteMode(f, "Absolute")
}

func NewAbsoluteXMode() *ThreeByteInstruction {
	f := func(m string, oper1 byte, oper2 byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s $%04x,x", m, makeAddr[uint16](oper1, oper2)), IllegalAddress
	}

	return NewThreeByteMode(f, "Absolute, x")
}

func NewAbsoluteYMode() *ThreeByteInstruction {
	f := func(m string, oper1 byte, oper2 byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s $%04x,y", m, makeAddr[uint16](oper1, oper2)), IllegalAddress
	}

	return NewThreeByteMode(f, "Absolute, y")
}

func NewAbsoluteJmpMode() *ThreeByteInstruction {
	f := func(m string, oper1 byte, oper2 byte, addr uint16) (string, int) {
		return m, makeAddr[int](oper1, oper2)
	}

	return NewThreeByteMode(f, "Absolute")
}

func NewIndirectJmpMode() *ThreeByteInstruction {
	f := func(m string, oper1 byte, oper2 byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s ($%04x)", m, makeAddr[uint16](oper1, oper2)), IllegalAddress
	}

	return NewThreeByteMode(f, "Indirect")
}

func NewRelativeRockwell() *ThreeByteInstruction {
	f := func(m string, oper1 byte, oper2 byte, addr uint16) (string, int) {
		var offset int8 = int8(oper2)

		return fmt.Sprintf("%s, $%02x,", m, oper1), int(uint16((int16(addr) + 3 + int16(offset))))
	}

	return NewThreeByteMode(f, "Relative")
}

func NewAbsXJmpMode() *ThreeByteInstruction {
	f := func(m string, oper1 byte, oper2 byte, addr uint16) (string, int) {
		return fmt.Sprintf("%s ($%04x,x)", m, makeAddr[uint16](oper1, oper2)), IllegalAddress
	}

	return NewThreeByteMode(f, "Indirect absolute, x")
}

func (t *ThreeByteInstruction) Recognize(opCode byte) bool {
	_, ok := t.opCodes[opCode]

	return ok
}

func (t *ThreeByteInstruction) Parse(opCode byte, addr uint16, r io.ByteReader, l *LabelMapStruct) (Instruction, error) {
	v, ok := t.opCodes[opCode]
	if !ok {
		return Instruction{}, fmt.Errorf("unparseable instruction %02X", opCode)
	}

	_, sep := t.separatorOpCodes[opCode]

	operand1, err := r.ReadByte()
	if err != nil {
		return Instruction{
			Addr:       addr,
			Mnemonic:   fmt.Sprintf("%s ????", v),
			Raw:        []byte{opCode},
			TargetAddr: IllegalAddress,
			Separator:  sep,
		}, nil
	}

	operand2, err := r.ReadByte()
	if err != nil {
		return Instruction{
			Addr:       addr,
			Mnemonic:   fmt.Sprintf("%s ??%02x", v, operand1),
			Raw:        []byte{opCode, operand1},
			TargetAddr: IllegalAddress,
			Separator:  sep,
		}, nil
	}

	newMnemonic, target := t.formatter(v, operand1, operand2, addr)

	if target >= 0 {
		l.AddAddress(target)
	}

	return Instruction{
		Addr:       addr,
		Mnemonic:   newMnemonic,
		Raw:        []byte{opCode, operand1, operand2},
		TargetAddr: target,
		Separator:  sep,
	}, nil
}
