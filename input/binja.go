package input

import (
	"encoding/json"
	"os"
)

type BinjaReport struct {
	Filename string        `json:"filename"`
	Arch     string        `json:"arch"`
	Platform string        `json:"platform"`
	Strings  []BinjaString `json:"strings"`
}

type BinjaString struct {
	Value   string      `json:"value"`
	Address string      `json:"address"`
	Length  int         `json:"length"`
	Section string      `json:"section"`
	Xrefs   []BinjaXref `json:"xrefs"`
}

type BinjaXref struct {
	Address         string `json:"address"`
	Function        string `json:"function"`
	FunctionAddress string `json:"function_address"`
}

//nearly identical to NewFlOSSReader, check if the file exists > read it > unmarshal it
type BinjaReader struct {
	path	string
	report	BinjaReport
}

func NewBinjaReader(path string) (*BinjaReader, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var report BinjaReport
	err = json.Unmarshal(data, &report)
	if err != nil {
		return nil, err
	}
	
	return &BinjaReader{path: path, report: report}, nil
}

func (b *BinjaReader) ReadLines() ([]string, error) {
	var lines []string
	for _, entry := range b.report.Strings {
		if len(entry.Value) > 0 { //filters out empty strings
			lines = append(lines, entry.Value)
		}
	}
	return lines, nil
}