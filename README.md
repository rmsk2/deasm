# deasm
A disassembler for the 6502/65C02 microprocessor. `deasm` can be used to either turn an assembly binary into
source code understood by the `64tass`, `acme` or `ca65` macro assemblers or to simply to investigate the contents
of such a file. The default output format is called the `monitor` format and looks like this:

```
4AF9:  8D 8E 3E  sta $3e8e
4AFC:  20 8F 3E  jsr $3e8f
4AFF:  60        rts
-------------------------------------
4B00:  6C BA 4A  jmp ($4aba)
-------------------------------------
4B03:  A9 40     lda #$40
4B05:  85 90     sta $90
4B07:  A9 46     lda #$46
4B09:  85 91     sta $91
4B0B:  A9 F8     lda #$f8
4B0D:  85 92     sta $92
4B0F:  A9 45     lda #$45
4B11:  85 93     sta $93
4B13:  20 60 3D  jsr $3d60
4B16:  A9 45     lda #$45
4B18:  85 90     sta $90
4B1A:  A9 46     lda #$46
4B1C:  85 91     sta $91
4B1E:  A9 FD     lda #$fd
4B20:  85 92     sta $92
4B22:  A9 45     lda #$45
4B24:  85 93     sta $93
4B26:  20 60 3D  jsr $3d60
4B29:  60        rts
-------------------------------------
4B2A:  A9 36     lda #$36
4B2C:  85 90     sta $90
4B2E:  A9 46     lda #$46
```

The overall usage information is summarized here:

```
Usage of deasm:
  -cpu string
    	Processor type: 6502 or 65c02. Optional (default "65c02")
  -format string
    	Output format: monitor, 64tass, ca65 or acme. Optional (default "monitor")
  -loadaddr int
    	Address of first byte. Optional. If not present first two bytes are used as load address (default -1)
  -offset uint
    	Offset into binary. Optional
  -prg string
    	Path to the program to disassemble
  -version
    	Show version information
```

When turning a binary into assembly source code for any of the assemblers mentioned above it is possible that the
source code does not compile due to non existing labels. The reason for that is not a deficiency in `deasm` but
most likely data like lookup tables or sprite defintions which are interpreted as machine code. When such data is
interpreted as machine code it is possible that the target address of a branch or jump ends up pointing to a byte 
inside of another instruction which should never happen in a well formed program. Errors like that have to be
resolved manually.