package input

import (
	"bufio" //sincemalware string dumps could be thousands of lines, buffered reading is ideal
	"os" //needed for file system operations
)

type FileReader struct {
	path string //only using one field is easier to scale than passing a string around
}

//this takes a file path and retrns a pointer to a FileReader or error if the file doesn't exist
func NewFileReader(path string) (*FileReader, error) {
	_, err := os.Stat(path) //calls the Os to get file metadata, like size perms, or modified time... we don't care about the actual metadata, which is why the return value is discarded with the  underscore "_"
	if err != nil {
		return nil, err
	}

	return &FileReader{path: path}, nil
}

//this is where the reading happens
func (r *FileReader) ReadLines() ([]string, error) { //method on FileReader with a recivere of r, the return type is ([]string, error) which is a tuple of a string slice 
	file, err := os.Open(r.path) //opens the file for reading, returns a file handle and an error
	if err != nil {
		return nil, err
	}
	defer file.Close() //this is Go's defer keyword, and it schedules file.Close() to run when the surrounding function returns

	var lines []string
	scanner := bufio.NewScanner(file) //creates a buffered scanner that wraps the file handle, reading line-by-line by default

	for scanner.Scan() { //advances to the next line and returns a boolean = TRUE if it reads a line and FALSE if it hits EOF or an erro
		line := scanner.Text() //returns the currrent line as a stirng
		if len(line) > 0 { //skips blnak lines
			lines = append(lines, line) 
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}