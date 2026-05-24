package input

import (
	"encoding/json"
	"os"
)

//structs to mirror the FLOSS JSON structure 
type FLOSSReport struct {
	Strings FLOSSStrings `json:"strings"`
}

type FLOSSStrings struct {
	StaticStrings	[]FLOSSEntry `json:"static_strings"`
	DecodedStrings 	[]FLOSSEntry `json:"decoded_strings"`
	StackStrings	[]FLOSSEntry `json:"stack_strings"`
	TightStrings	[]FLOSSEntry `jsno:"tight_strings"`
}
//has the fields any entryp type may have... DecodingRoutine ad Function are tagged omitempty because they only appear in decoded strings or stack strings, respectively
type FLOSSEntry struct {
	String	string `json:"string"`
	Offset	int `json:"offset"`
	Encoding	string `json:"encoding"`
	DecodingRoutine	string `json:"decoding_routine,omitempty"`
	Function	string `json:"function,omitempty"`
}

type FLOSSReader struct {
	path	string
	report	FLOSSReport
}

//parses the JSON at construction time
func NewFLOSSReader (path string) (*FLOSSReader, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //reads the entire file into a []byte all at once becuase json.Unmarshal expects a complete JSON blob
	if err != nil {
		return nil, err
	}
	var report FLOSSReport
	err = json.Unmarshal(data, &report) //JSON decoder, taking raw bytes and a pointer 
	if err != nil {
		return nil, err
	}
	//parsing in the constructor instead of in ReadLines becuase if the JSON is malformed, you want to know immediately
	return &FLOSSReader{path: path, report: report}, nil
}

func (f *FLOSSReader) ReadLines() ([]string, error) {
	var lines []string

	for _, entry := range f.report.Strings.StaticStrings {
		lines = append(lines, entry.String)
	}
	for _, entry := range f.report.Strings.DecodedStrings {
		lines = append(lines, entry.String)
	}
	for _, entry := range f.report.Strings.StackStrings {
		lines = append(lines, entry.String)
	}
	for _, entry := range f.report.Strings.TightStrings {
		lines = append(lines, entry.String)
	}
	return lines, nil
}