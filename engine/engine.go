package engine

import (
	"github.com/grepstrength/malsnitch/detector"
	"github.com/grepstrength/malsnitch/input"
)

type Reader interface {
	ReadLines() ([]string, error)
}

type Engine struct {
	detectors	[]detector.Detector //slice of detector.Detector... its an interface type and not concrete
	reader	input.Reader //interfaces in Go are already reference types interanlly and hold a pointer to the underlying value
}

//the constructor

func NewFromFile(filePath string) (*Engine, error) {
	reader, err := input.NewFileReader(filePath) //creates a FileReader first. ifthe input.NewFileReader returns and error, and the engine never gets created
	if err != nil {
		return nil, err
	}

	return &Engine{
		detectors:	defaultDetectors(),
		reader:	reader,
	}, nil
}

func NewFromFLOSS(filePath string) (*Engine, error) {
	reader, err := input.NewFLOSSReader(filePath) //creates a FileReader first. ifthe input.NewFileReader returns and error, and the engine never gets created
	if err != nil {
		return nil, err
	}

	return &Engine{
		detectors:	defaultDetectors(),
		reader:	reader,
	}, nil
}

func defaultDetectors() []detector.Detector {
	return []detector.Detector{
		detector.NewCryptoDetector(), //this is unexported
	}
}

//the core of the tool... read input > run every detector > collect the results
func (e *Engine) Run() ([]detector.Finding, error) {
	lines, err := e.reader.ReadLines() //calls the reader that was built and gets back all the non-empty lines from the file
	if err != nil {
		return nil, err
	}
	var findings []detector.Finding

	for _, d := range e.detectors { //loops over every registered detector. 
		results := d.Detect(lines)
		findings = append(findings, results...) //avoids type mismatches
	}
	return findings, nil
}
