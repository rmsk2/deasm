package main

import (
	"bytes"
	"fmt"
	"os"
)

func loadBinaryWithAddress(fileName string) (loadAddress uint16, prog []byte, err error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to load binary: %v", err)
	}

	if len(data) < 3 {
		return 0, nil, fmt.Errorf("no program data found")
	}

	loadAddress = uint16(data[1])*256 + uint16(data[0])

	return loadAddress, data[2:], nil
}

func loadBinary(fileName string) (prog []byte, err error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("unable to load binary: %v", err)
	}

	return data, nil
}

type AddrByteBuffer struct {
	b       bytes.Buffer
	current uint16
}

func NewAddrByteBuffer(loadAddr uint16, prog []byte, offset uint16) *AddrByteBuffer {
	return &AddrByteBuffer{
		b:       *bytes.NewBuffer(prog[offset:]),
		current: loadAddr - 1 + offset,
	}
}

func (a *AddrByteBuffer) ReadByte() (byte, error) {
	data, err := a.b.ReadByte()
	if err != nil {
		return 0, err
	}

	a.current++

	return data, nil
}
