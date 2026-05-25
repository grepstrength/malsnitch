package output

import (
	"encoding/csv" //Go's built in CSV writer
	"os"
	"fmt"
	"github.com/grepstrength/malsnitch/detector"
)

type CSVOutput struct {
	findings []detector.Finding
}

func NewCSVOutput(findings []detector.Finding) *CSVOutput {
	return &CSVOutput{findings: findings}
}

func (c *CSVOutput) Print() error {
	writer := csv.NewWriter(os.Stdout) //creates a CSV writer that outputs to stdout 
	defer writer.Flush() //CSV writers buffer their output for performance... Flush pushes everything to stdout... without this, the last few rows might not appear. defer is used to make sure it runs even if there's an early error

	err := writer.Write([]string{ 
		"detector_name",
		"description",
		"secret",
		"line_number",
		"confidence",
	})
	if err != nil {
		return err
	}

	for _, f := range c.findings {
		err := writer.Write([]string{
			f.DetectorName,
			f.Description,
			f.Secret,
			fmt.Sprintf("%d", f.LineNumber),
			f.Confidence,
		})
		if err != nil {
			return err
		}
	}

	return nil
}