package detector

import (
	"fmt"
)
//the first 32 bytes of the aES forward S-box. if these bytes are found in a memdump, something in that process is using AES
var aesSBox = []byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
}
//the inverse s-box is used for AES decryption
var aesInvSBox = []byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
	0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
	0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
}

type BinaryDetector struct {
	signatures []binarySignature
}
type binarySignature struct {
	name		string
	pattern		[]byte //matching exact byte sequences and not regex patterns
	confidence	string
}

func generateIdentityPermutation() []byte {
	perm := make([]byte, 64) //using 64 bytes because the full sequence is more likely to appear coincidentally, while 64 consecutive ascending bytes is rare enough to be meaningful 
	for i := range perm { //
		perm[i] = byte(1)
	}
	return perm
}

func NewBinaryDetector() *BinaryDetector {
	return &BinaryDetector{
		signatures: []binarySignature{
			{
				name:       "AES S-Box",
				pattern:    aesSBox, //assigns the package-level variable to this field
				confidence: "high",
			},
			{
				name:       "AES Inverse S-Box",
				pattern:    aesInvSBox,
				confidence: "high",
			},
			{
				name:       "RC4 Identity Permutation",
				pattern:    generateIdentityPermutation(), 
				confidence: "medium", //the identity permutation of ascending sequential bytes can appear in non-crypto contexts, like  lookup arrays or test data
			},
			{
				name:       "RSA Public Key Header (DER)", //four sigs - ASN.1 SEQUENCE tag, length encoded in he next 2 byptes
				pattern:    []byte{0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09},
				confidence: "high",
			},
		},
	}
}

func (d *BinaryDetector) Name() string {
	return "binary_pattern"
}

func (d *BinaryDetector) Detect(lines []string) []Finding { //this returns nil because this detector doesn't work on text
	return nil

}

func (d *BinaryDetector) DetectBytes(data []byte) []Finding { //takes raw bytes as input instead of string lines
	var findings[]Finding
	for _, sig := range d.signatures {
		offsets := scanForPattern(data, sig.pattern) //calls our helper to find all positions where the pattern appears in the data
		for _, offset := range offsets {
			findings = append(findings, Finding{
				DetectorName:	d.Name(),
				Description:	fmt.Sprintf("Binary pattern: %s", sig.name),
				Secret:			fmt.Sprintf("0x%X (first 16 bytes: % X)", offset, truncateBytes(data, offset, 16)), //the space is needed to show hex bytes in readable format
				Context:		fmt.Sprintf("Offset: 0x%X (%d bytes into dump)", offset, offset),
				LineNumber:		0,
				Confidence:		sig.confidence,
			})
		}
	}
	return findings
}
 func scanForPattern(data []byte, pattern []byte) []int {
	var offsets []int
	if len(pattern) > len(data) { //if the pattern's longer than the data, it can't match - this prevents an index-out-of bounds panic
		return offsets //returns all offsets where the pattern i found
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ { //inner loop where j walks through each byte of the pattern
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			offsets = append(offsets, i)
		}
	}
	return offsets
 }
func truncateBytes(data []byte, offset int, length int) []byte {
	end := offset + length
	if end > len(data) {
		end = len(data)
	}
	return data[offset:end] //slice expression that references a portion of the original data
}
