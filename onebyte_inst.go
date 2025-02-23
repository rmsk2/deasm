package main

import (
	"fmt"
	"io"
)

type ImplictMode struct {
	opCodes          map[byte]string
	separatorOpCodes map[byte]bool
}

func (i *ImplictMode) AddOpCode(o byte, mnemonic string) {
	i.opCodes[o] = mnemonic
}

func (i *ImplictMode) AddOpCodeSeparator(o byte, mnemonic string) {
	i.opCodes[o] = mnemonic
	i.separatorOpCodes[o] = true
}

func NewImplicitMode() *ImplictMode {
	return &ImplictMode{
		opCodes:          make(map[byte]string),
		separatorOpCodes: make(map[byte]bool),
	}
}

func (i *ImplictMode) Recognize(opCode byte) bool {
	_, ok := i.opCodes[opCode]

	return ok
}

func (i *ImplictMode) Parse(opCode byte, addr uint16, r io.ByteReader, l *LabelMapStruct) (Instruction, error) {
	v, ok := i.opCodes[opCode]
	if !ok {
		return Instruction{}, fmt.Errorf("unparseable instruction %02X", opCode)
	}

	_, sep := i.separatorOpCodes[opCode]

	return Instruction{
		Addr:       addr,
		Mnemonic:   v,
		Raw:        []byte{opCode},
		TargetAddr: IllegalAddress,
		Separator:  sep,
	}, nil
}
