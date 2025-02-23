package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

const IllegalAddress = -1
const CPU6502 = 0
const CPU65C02 = 1

type Instruction struct {
	Addr               uint16
	Mnemonic           string
	Raw                []byte
	TargetAddr         int
	Separator          bool
	IllegalInstruction bool
}

type LabelMapStruct struct {
	m            map[int]string
	startAddress int
	endAddress   int
}

func (l *LabelMapStruct) AddAddress(addr int) {
	if (addr < l.startAddress) || (addr > l.endAddress) {
		return
	}

	_, ok := l.m[addr]

	if !ok {
		l.m[addr] = fmt.Sprintf("L_%04x", addr)
	}
}

func NewLabelMapStruct(startAddr, endAddr int) *LabelMapStruct {
	return &LabelMapStruct{
		m:            make(map[int]string),
		startAddress: startAddr,
		endAddress:   endAddr,
	}
}

type Renderer interface {
	RenderInstruction(i Instruction, labels *LabelMapStruct) (string, error)
	RenderHeader(addr uint16, machineType int) string
}

type AddrMode interface {
	Recognize(opCode byte) bool
	Parse(opCode byte, addr uint16, r io.ByteReader, l *LabelMapStruct) (Instruction, error)
}

func (a *AddrByteBuffer) GetAddr() uint16 {
	return a.current
}

type Disassembler struct {
	program      []byte
	labels       *LabelMapStruct
	instructions []Instruction
	addrModes    []AddrMode
	loadAddress  uint16
	machineType  int
}

func NewDisassembler(prog []byte, l uint16, t int) *Disassembler {
	res := Disassembler{
		program:      prog,
		labels:       NewLabelMapStruct(int(l), int(l)+len(prog)-1),
		instructions: []Instruction{},
		addrModes:    []AddrMode{},
		loadAddress:  l,
		machineType:  t,
	}

	res.SetConfig()

	return &res
}

func (d *Disassembler) AddAddressingMode(m AddrMode) {
	d.addrModes = append(d.addrModes, m)
}

func (d *Disassembler) ParseBinary(offset uint16) error {
	d.instructions = make([]Instruction, 0)

	if int(offset) >= len(d.program) {
		return fmt.Errorf("offset %d larger than overall length of %d", offset, len(d.program))
	}

	r := NewAddrByteBuffer(d.loadAddress, d.program, offset)

	for {
		opCode, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}

		wasRecognized := false

		for _, k := range d.addrModes {
			if k.Recognize(opCode) {
				wasRecognized = true

				inst, err := k.Parse(opCode, r.GetAddr(), r, d.labels)
				if err != nil {
					return err
				}

				d.instructions = append(d.instructions, inst)
				break
			}
		}

		if !wasRecognized {
			inst := Instruction{
				Addr:               r.GetAddr(),
				Mnemonic:           "***",
				Raw:                []byte{opCode},
				TargetAddr:         IllegalAddress,
				Separator:          true,
				IllegalInstruction: true,
			}
			d.instructions = append(d.instructions, inst)
		}
	}

	return nil
}

func (d *Disassembler) RenderInstructions(w io.Writer, r Renderer, offset uint16) error {
	var header = r.RenderHeader(d.loadAddress+offset, d.machineType)

	if header != "" {
		fmt.Fprintln(w, header)
	}

	for _, j := range d.instructions {
		text, err := r.RenderInstruction(j, d.labels)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\n", text)
	}

	return nil
}

func (d *Disassembler) SetConfig() {
	implicit := NewImplicitMode()
	implicit.AddOpCodeSeparator(0x00, "brk")
	implicit.AddOpCodeSeparator(0x60, "rts")
	implicit.AddOpCodeSeparator(0x40, "rti")
	implicit.AddOpCodeSeparator(0xDB, "stp")
	implicit.AddOpCode(0x18, "clc")
	implicit.AddOpCode(0x38, "sec")
	implicit.AddOpCode(0xb8, "cld")
	implicit.AddOpCode(0xf8, "sed")
	implicit.AddOpCode(0x58, "cli")
	implicit.AddOpCode(0x78, "sei")
	implicit.AddOpCode(0xb8, "clv")
	implicit.AddOpCode(0xca, "dex")
	implicit.AddOpCode(0x88, "dey")
	implicit.AddOpCode(0xe8, "inx")
	implicit.AddOpCode(0xc8, "iny")
	implicit.AddOpCode(0xea, "nop")
	implicit.AddOpCode(0x48, "pha")
	implicit.AddOpCode(0x68, "pla")
	implicit.AddOpCode(0x08, "php")
	implicit.AddOpCode(0x28, "plp")
	implicit.AddOpCode(0xaa, "tax")
	implicit.AddOpCode(0x8a, "txa")
	implicit.AddOpCode(0xa8, "tay")
	implicit.AddOpCode(0x98, "tya")
	implicit.AddOpCode(0xba, "tsx")
	implicit.AddOpCode(0x9a, "txs")
	implicit.AddOpCode(0xcb, "wai")
	implicit.AddOpCode(0x0a, "asl")
	implicit.AddOpCode(0x4a, "lsr")
	implicit.AddOpCode(0x2a, "rol")
	implicit.AddOpCode(0x6a, "ror")

	if d.machineType == CPU65C02 {
		implicit.AddOpCode(0x3a, "dea")
		implicit.AddOpCode(0x1a, "ina")
		implicit.AddOpCode(0xda, "phx")
		implicit.AddOpCode(0xfa, "plx")
		implicit.AddOpCode(0x5a, "phy")
		implicit.AddOpCode(0x7a, "ply")
	}

	immediate := NewImmediateMode()
	immediate.AddOpCode(0xa9, "lda")
	immediate.AddOpCode(0x69, "adc")
	immediate.AddOpCode(0x29, "and")
	immediate.AddOpCode(0xc9, "cmp")
	immediate.AddOpCode(0xe0, "cpx")
	immediate.AddOpCode(0xc0, "cpy")
	immediate.AddOpCode(0x49, "eor")
	immediate.AddOpCode(0xa2, "ldx")
	immediate.AddOpCode(0xa0, "ldy")
	immediate.AddOpCode(0x09, "ora")
	immediate.AddOpCode(0xe9, "sbc")

	if d.machineType == CPU65C02 {
		immediate.AddOpCode(0x89, "bit")
	}

	zp := NewZeroPage()
	zp.AddOpCode(0x65, "adc")
	zp.AddOpCode(0x25, "and")
	zp.AddOpCode(0x06, "asl")
	zp.AddOpCode(0x24, "bit")
	zp.AddOpCode(0xc5, "cmp")
	zp.AddOpCode(0xe4, "cpx")
	zp.AddOpCode(0xc4, "cpy")
	zp.AddOpCode(0xc6, "dec")
	zp.AddOpCode(0x45, "eor")
	zp.AddOpCode(0xe6, "inc")
	zp.AddOpCode(0xa5, "lda")
	zp.AddOpCode(0xa6, "ldx")
	zp.AddOpCode(0xa4, "ldy")
	zp.AddOpCode(0x46, "lsr")
	zp.AddOpCode(0x05, "ora")
	zp.AddOpCode(0x26, "rol")
	zp.AddOpCode(0x66, "ror")
	zp.AddOpCode(0xe5, "sbc")
	zp.AddOpCode(0x85, "sta")
	zp.AddOpCode(0x86, "stx")
	zp.AddOpCode(0x84, "sty")

	if d.machineType == CPU65C02 {
		zp.AddOpCode(0x64, "stz")
		zp.AddOpCode(0x14, "trb")
		zp.AddOpCode(0x04, "tsb")

		zp.AddOpCode(0x87, "smb 0,")
		zp.AddOpCode(0x97, "smb 1,")
		zp.AddOpCode(0xa7, "smb 2,")
		zp.AddOpCode(0xb7, "smb 3,")
		zp.AddOpCode(0xc7, "smb 4,")
		zp.AddOpCode(0xd7, "smb 5,")
		zp.AddOpCode(0xe7, "smb 6,")
		zp.AddOpCode(0xf7, "smb 7,")

		zp.AddOpCode(0x07, "rmb 0,")
		zp.AddOpCode(0x17, "rmb 1,")
		zp.AddOpCode(0x27, "rmb 2,")
		zp.AddOpCode(0x37, "rmb 3,")
		zp.AddOpCode(0x47, "rmb 4,")
		zp.AddOpCode(0x57, "rmb 5,")
		zp.AddOpCode(0x67, "rmb 6,")
		zp.AddOpCode(0x77, "rmb 7,")
	}

	zpx := NewZeroPageX()
	zpx.AddOpCode(0x75, "adc")
	zpx.AddOpCode(0x35, "and")
	zpx.AddOpCode(0x16, "asl")
	zpx.AddOpCode(0xd5, "cmp")
	zpx.AddOpCode(0xd6, "dec")
	zpx.AddOpCode(0x55, "eor")
	zpx.AddOpCode(0xf6, "inc")
	zpx.AddOpCode(0xb5, "lda")
	zpx.AddOpCode(0xb4, "ldy")
	zpx.AddOpCode(0x56, "lsr")
	zpx.AddOpCode(0x15, "ora")
	zpx.AddOpCode(0x36, "rol")
	zpx.AddOpCode(0x76, "ror")
	zpx.AddOpCode(0xf5, "sbc")
	zpx.AddOpCode(0x95, "sta")
	zpx.AddOpCode(0x94, "sty")

	if d.machineType == CPU65C02 {
		zpx.AddOpCode(0x74, "stz")
		zpx.AddOpCode(0x34, "bit")
	}

	zpy := NewZeroPageY()
	zpy.AddOpCode(0xb6, "ldx")
	zpy.AddOpCode(0x96, "stx")

	indirectY := NewIndirectY()

	indirectY.AddOpCode(0x71, "adc")
	indirectY.AddOpCode(0x31, "and")
	indirectY.AddOpCode(0xd1, "cmp")
	indirectY.AddOpCode(0x51, "eor")
	indirectY.AddOpCode(0xb1, "lda")
	indirectY.AddOpCode(0x11, "ora")
	indirectY.AddOpCode(0xf1, "sbc")
	indirectY.AddOpCode(0x91, "sta")

	rel := NewRelative()
	rel.AddOpCode(0x90, "bcc")
	rel.AddOpCode(0xb0, "bcs")
	rel.AddOpCode(0xF0, "beq")
	rel.AddOpCode(0x30, "bmi")
	rel.AddOpCode(0xd0, "bne")
	rel.AddOpCode(0x10, "bpl")
	rel.AddOpCode(0x50, "bvc")
	rel.AddOpCode(0x70, "bvs")

	if d.machineType == CPU65C02 {
		rel.AddOpCode(0x80, "bra")
	}

	bitRelRockwell := NewRelativeRockwell()
	if d.machineType == CPU65C02 {
		bitRelRockwell.AddOpCode(0x0f, "bbr 0")
		bitRelRockwell.AddOpCode(0x1f, "bbr 1")
		bitRelRockwell.AddOpCode(0x2f, "bbr 2")
		bitRelRockwell.AddOpCode(0x3f, "bbr 3")
		bitRelRockwell.AddOpCode(0x4f, "bbr 4")
		bitRelRockwell.AddOpCode(0x5f, "bbr 5")
		bitRelRockwell.AddOpCode(0x6f, "bbr 6")
		bitRelRockwell.AddOpCode(0x7f, "bbr 7")

		bitRelRockwell.AddOpCode(0x8f, "bbs 0")
		bitRelRockwell.AddOpCode(0x9f, "bbs 1")
		bitRelRockwell.AddOpCode(0xaf, "bbs 2")
		bitRelRockwell.AddOpCode(0xbf, "bbs 3")
		bitRelRockwell.AddOpCode(0xcf, "bbs 4")
		bitRelRockwell.AddOpCode(0xdf, "bbs 5")
		bitRelRockwell.AddOpCode(0xef, "bbs 6")
		bitRelRockwell.AddOpCode(0xff, "bbs 7")
	}

	indX := NewIndirectX()

	indX.AddOpCode(0x61, "adc")
	indX.AddOpCode(0x21, "and")
	indX.AddOpCode(0xc1, "cmp")
	indX.AddOpCode(0x41, "eor")
	indX.AddOpCode(0xA1, "lda")
	indX.AddOpCode(0x01, "ora")
	indX.AddOpCode(0xe1, "sbc")
	indX.AddOpCode(0x81, "sta")

	ind := NewZPIndirect()

	if d.machineType == CPU65C02 {
		ind.AddOpCode(0x72, "adc")
		ind.AddOpCode(0x32, "and")
		ind.AddOpCode(0xd2, "cmp")
		ind.AddOpCode(0x52, "eor")
		ind.AddOpCode(0xb2, "lda")
		ind.AddOpCode(0x12, "ora")
		ind.AddOpCode(0xf2, "sbc")
		ind.AddOpCode(0x92, "sta")
	}

	absJmp := NewAbsoluteJmpMode()

	absJmp.AddOpCodeSeparator(0x4c, "jmp")
	absJmp.AddOpCode(0x20, "jsr")

	absMode := NewAbsoluteMode()

	absMode.AddOpCode(0x6d, "adc")
	absMode.AddOpCode(0x2d, "and")
	absMode.AddOpCode(0x0e, "asl")
	absMode.AddOpCode(0x2c, "bit")
	absMode.AddOpCode(0xcd, "cmp")
	absMode.AddOpCode(0xec, "cpx")
	absMode.AddOpCode(0xcc, "cpy")
	absMode.AddOpCode(0xce, "dec")
	absMode.AddOpCode(0x4d, "eor")
	absMode.AddOpCode(0xee, "inc")
	absMode.AddOpCode(0xad, "lda")
	absMode.AddOpCode(0xae, "ldx")
	absMode.AddOpCode(0xac, "ldy")
	absMode.AddOpCode(0x4e, "lsr")
	absMode.AddOpCode(0x0d, "ora")
	absMode.AddOpCode(0x2e, "rol")
	absMode.AddOpCode(0x6e, "ror")
	absMode.AddOpCode(0xed, "sbc")
	absMode.AddOpCode(0x8d, "sta")
	absMode.AddOpCode(0x8e, "stx")
	absMode.AddOpCode(0x8c, "sty")

	if d.machineType == CPU65C02 {
		absMode.AddOpCode(0x9c, "stz")
		absMode.AddOpCode(0x1c, "trb")
		absMode.AddOpCode(0x0c, "tsb")
	}

	absYMode := NewAbsoluteYMode()

	absYMode.AddOpCode(0x79, "adc")
	absYMode.AddOpCode(0x39, "and")
	absYMode.AddOpCode(0xd9, "cmp")
	absYMode.AddOpCode(0x59, "eor")
	absYMode.AddOpCode(0xb9, "lda")
	absYMode.AddOpCode(0xbe, "ldx")
	absYMode.AddOpCode(0x19, "ora")
	absYMode.AddOpCode(0xf9, "sbc")
	absYMode.AddOpCode(0x99, "sta")

	absXMode := NewAbsoluteXMode()

	absXMode.AddOpCode(0x7d, "adc")
	absXMode.AddOpCode(0x3d, "and")
	absXMode.AddOpCode(0x1e, "asl")
	absXMode.AddOpCode(0xdd, "cmp")
	absXMode.AddOpCode(0xde, "dec")
	absXMode.AddOpCode(0x5d, "eor")
	absXMode.AddOpCode(0xfe, "inc")
	absXMode.AddOpCode(0xbd, "lda")
	absXMode.AddOpCode(0xbc, "ldy")
	absXMode.AddOpCode(0x5e, "lsr")
	absXMode.AddOpCode(0x1d, "ora")
	absXMode.AddOpCode(0x3e, "rol")
	absXMode.AddOpCode(0x7e, "ror")
	absXMode.AddOpCode(0xfd, "sbc")
	absXMode.AddOpCode(0x9d, "sta")

	if d.machineType == CPU65C02 {
		absXMode.AddOpCode(0x9e, "stz")
		absXMode.AddOpCode(0x3c, "bit")
	}

	indirectJmp := NewIndirectJmpMode()
	indirectJmp.AddOpCodeSeparator(0x6c, "jmp")

	absXJmp := NewAbsXJmpMode()
	absXJmp.AddOpCodeSeparator(0x7c, "jmp")

	d.AddAddressingMode(implicit)
	d.AddAddressingMode(immediate)
	d.AddAddressingMode(zp)
	d.AddAddressingMode(zpx)
	d.AddAddressingMode(zpy)
	d.AddAddressingMode(indirectY)
	d.AddAddressingMode(rel)
	d.AddAddressingMode(indX)
	d.AddAddressingMode(ind)
	d.AddAddressingMode(absJmp)
	d.AddAddressingMode(absMode)
	d.AddAddressingMode(absYMode)
	d.AddAddressingMode(absXMode)
	d.AddAddressingMode(indirectJmp)
	d.AddAddressingMode(absXJmp)
	d.AddAddressingMode(bitRelRockwell)
}

func makeMachineType(cpuFlag *string) int {
	var allowedCpuTypes map[string]bool = map[string]bool{
		"6502":  true,
		"65c02": true,
	}

	_, ok := allowedCpuTypes[*cpuFlag]
	if !ok {
		fmt.Println("Unsupported CPU type")
		os.Exit(42)
	}

	var machineType int

	if *cpuFlag == "6502" {
		machineType = CPU6502
	} else {
		machineType = CPU65C02
	}

	return machineType
}

func makeRenderer(formatFlag *string) Renderer {
	var allowedFormats map[string]bool = map[string]bool{
		"monitor": true,
		"64tass":  true,
		"acme":    true,
		"ca65":    true,
	}

	var renderer Renderer

	_, ok := allowedFormats[*formatFlag]
	if !ok {
		fmt.Println("Unsupported output format")
		os.Exit(42)
	}

	switch *formatFlag {
	case "acme":
		renderer = NewAcmeRenderer()
	case "64tass":
		renderer = NewAsm64tassRenderer()
	case "ca65":
		renderer = NewAsmCa65Renderer()
	default:
		renderer = NewSimpleRenderer()
	}

	return renderer
}

func showVersion() {
	var hash string
	var time string

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				hash = setting.Value
				continue
			}

			if setting.Key == "vcs.time" {
				time = setting.Value
				continue
			}
		}
	}

	fmt.Println("Version: 1.1.1")
	fmt.Println("Written by Martin Grap in 2025")
	fmt.Println("See https://github.com/rmsk2/deasm")
	fmt.Printf("Commit: %s, from: %s\n", hash, time)
}

func main() {
	runFlags := flag.NewFlagSet("deasm", flag.ContinueOnError)
	binaryFileName := runFlags.String("prg", "", "Path to the program to disassemble")
	loadAddress := runFlags.Int("loadaddr", IllegalAddress, "Address of first byte. Optional. If not present first two bytes are used as load address")
	offsetBytes := runFlags.Uint("offset", 0, "Offset into binary. Optional")
	cpuFlag := runFlags.String("cpu", "65c02", "Processor type: 6502 or 65c02. Optional")
	formatFlag := runFlags.String("format", "monitor", "Output format: monitor, 64tass, ca65 or acme. Optional")
	versionFlag := runFlags.Bool("version", false, "Show version information")
	var err error = nil
	var progData []byte
	var loadAddr uint16

	if err = runFlags.Parse(os.Args[1:]); err != nil {
		os.Exit(42)
	}

	if *versionFlag {
		showVersion()
		os.Exit(0)
	}

	var offset = uint16(*offsetBytes)
	var machineType int = makeMachineType(cpuFlag)
	var renderer Renderer = makeRenderer(formatFlag)

	if *binaryFileName == "" {
		fmt.Println("No program name given")
		os.Exit(42)
	}

	if *loadAddress < 0 {
		loadAddr, progData, err = loadBinaryWithAddress(*binaryFileName)
	} else {
		loadAddr = uint16(*loadAddress)
		progData, err = loadBinary(*binaryFileName)
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(42)
	}

	disAss := NewDisassembler(progData, loadAddr, machineType)

	err = disAss.ParseBinary(offset)
	if err != nil {
		fmt.Println(err)
		os.Exit(42)
	}

	err = disAss.RenderInstructions(os.Stdout, renderer, offset)
	if err != nil {
		fmt.Println(err)
		os.Exit(42)
	}
}
