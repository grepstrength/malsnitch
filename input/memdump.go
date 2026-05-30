package input

import (
	"os" //just need to read raw bytes
)
//two fields, path is the file location and data is the entire dump as raw bytes
type MemDumpReader struct {
	path	string
	data	[]byte
}

//for large memdumps (in the order of multiple GBs) we can run into issues reading the whole file into memory 
//i can add memory mapped files with mmap
func NewMemDumpReader(path string) (*MemDumpReader, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //os.ReadFile returns slice of bytes with no encoding interpretation... e.g. a null byte is a null byte
	if err != nil {
		return nil, err
	}
	return &MemDumpReader{path: path, data: data}, nil
}

//this satisfies the Reader interface s the text-based detectors can run against memdumps. This extracts printable ASCII strings from raw binary, same as strings.exe
func (m *MemDumpReader) ReadLines() ([]string, error) {
	var lines []string
	current := []byte{} //an empty byte slice that accumulates consecutive printable bytes
	for _, b := range m.data {
		if b >= 0x20 && b <= 0x7E { //this is the printable ASCII range. 0x20 is SPACE and 0x7E is ~. every byte in this range is a visible character on a keyboard. any byte outside of this range is binary data (eg. null terminators or control chars)
			current = append(current, b)
		} else {
			if len(current) >= 8 {
				lines = append(lines, string(current))
			}
			current = []byte{}
		}
	}
	if len(current) >= 8 { //8 is the standard strings.exe default... anything shorter is typically an instruction fragment or coincidental byte pattern, but not a real string
		lines = append(lines, string(current))
	}
	return lines, nil
}

func (m *MemDumpReader) RawBytes() []byte {
	return m.data
}