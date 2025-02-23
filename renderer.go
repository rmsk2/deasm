package main

import (
	"fmt"
	"strings"
)

type SimpleRenderer struct {
}

func NewSimpleRenderer() *SimpleRenderer {
	return new(SimpleRenderer)
}

func (s *SimpleRenderer) RenderHeader(addr uint16, machineType int) string {
	return ""
}

func (s *SimpleRenderer) RenderInstruction(i Instruction, labels *LabelMapStruct) (string, error) {
	var line string
	line = fmt.Sprintf("%04X:  ", i.Addr)

	numBytes := 0

	for _, j := range i.Raw {
		line += fmt.Sprintf("%02X ", j)
		numBytes++
	}

	if numBytes < 3 {
		line += strings.Repeat("   ", 3-numBytes)
	}

	line += " "

	if i.IllegalInstruction {
		line += "???"
	} else {
		if i.TargetAddr >= 0 {
			line += fmt.Sprintf("%s $%04x", i.Mnemonic, i.TargetAddr)
		} else {
			line += i.Mnemonic
		}
	}

	if i.Separator {
		line += "\n-------------------------------------"
	}

	return line, nil
}

type Asm64tassRenderer struct {
	fmt6502  string
	fmt65c02 string
	acme     bool
}

func NewAsm64tassRenderer() *Asm64tassRenderer {
	return &Asm64tassRenderer{
		fmt6502:  ".cpu \"6502\"\n*=$%04x\n",
		fmt65c02: ".cpu \"w65c02\"\n*=$%04x\n",
		acme:     false,
	}
}

func NewAcmeRenderer() *Asm64tassRenderer {
	return &Asm64tassRenderer{
		fmt6502:  "!cpu 6502\n*=$%04x\n",
		fmt65c02: "!cpu w65c02\n*=$%04x\n",
		acme:     true,
	}
}

func (a *Asm64tassRenderer) RenderHeader(addr uint16, machineType int) string {
	if machineType == CPU6502 {
		return fmt.Sprintf(a.fmt6502, addr)
	} else {
		return fmt.Sprintf(a.fmt65c02, addr)
	}
}

func (a *Asm64tassRenderer) transformIfAcme(m string) string {
	if !a.acme {
		return m
	}

	if strings.HasPrefix(m, "rmb") || strings.HasPrefix(m, "smb") {
		h := strings.ReplaceAll(m, " ", "")
		return strings.ReplaceAll(h, ",", " ")
	}

	if strings.HasPrefix(m, "bbr") || strings.HasPrefix(m, "bbs") {
		h := strings.ReplaceAll(m, " ", "")
		return strings.Replace(h, ",", " ", 1)
	}

	if strings.HasPrefix(m, "ina") {
		return strings.ReplaceAll(m, "ina", "inc")
	}

	if strings.HasPrefix(m, "dea") {
		return strings.ReplaceAll(m, "dea", "dec")
	}

	return m
}

func (a *Asm64tassRenderer) RenderInstruction(i Instruction, labels *LabelMapStruct) (string, error) {
	var line string

	if i.IllegalInstruction {
		if !a.acme {
			return fmt.Sprintf(".byte $%02x", i.Raw[0]), nil
		} else {
			return fmt.Sprintf("!byte $%02x", i.Raw[0]), nil
		}
	}

	label, isKnown := labels.m[int(i.Addr)]
	if isKnown {
		line += label + "\n"
	}

	line += "    " + a.transformIfAcme(i.Mnemonic)

	if i.TargetAddr >= 0 {
		targetLabel, isKnown := labels.m[int(i.TargetAddr)]
		if !isKnown {
			line += " " + fmt.Sprintf("$%04x", i.TargetAddr)
		} else {
			line += " " + targetLabel
		}
	}

	if i.Separator {
		line += "\n;-------------------------------------"
	}

	return line, nil
}

type AsmCa65Renderer struct {
}

func NewAsmCa65Renderer() *AsmCa65Renderer {
	return new(AsmCa65Renderer)
}

func (a *AsmCa65Renderer) transform(m string) string {
	if strings.HasPrefix(m, "rmb") || strings.HasPrefix(m, "smb") {
		h := strings.ReplaceAll(m, " ", "")
		return strings.ReplaceAll(h, ",", " ")
	}

	if strings.HasPrefix(m, "bbr") || strings.HasPrefix(m, "bbs") {
		h := strings.ReplaceAll(m, " ", "")
		return strings.Replace(h, ",", " ", 1)
	}

	return m
}

func (a *AsmCa65Renderer) RenderHeader(addr uint16, machineType int) string {
	if machineType == CPU6502 {
		return fmt.Sprintf(".P02\n.org $%04x\n", addr)
	} else {
		return fmt.Sprintf(".PC02\n.org $%04x\n", addr)
	}
}

func (a *AsmCa65Renderer) RenderInstruction(i Instruction, labels *LabelMapStruct) (string, error) {
	var line string

	if i.IllegalInstruction {
		return fmt.Sprintf(".byte $%02x", i.Raw[0]), nil
	}

	label, isKnown := labels.m[int(i.Addr)]
	if isKnown {
		line += label + ":\n"
	}

	line += "    " + a.transform(i.Mnemonic)

	if i.TargetAddr >= 0 {
		targetLabel, isKnown := labels.m[int(i.TargetAddr)]
		if !isKnown {
			line += " " + fmt.Sprintf("$%04x", i.TargetAddr)
		} else {
			line += " " + targetLabel
		}
	}

	if i.Separator {
		line += "\n;-------------------------------------"
	}

	return line, nil
}
