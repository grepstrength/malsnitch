package output

import (
	"encoding/json" //Go's built in JSON marshaler
	"os"
	"github.com/grepstrength/not-so-secret/detector"
)

type JSONOutput struct {
	findings []detector.Finding //JSONOutput holds a sliceof findings, but this is lowercase/unexported 
}

//no error because there is no validation, just storing a reference
func NewJSONOutput(findings []detector.Finding) *JSONOutput {
	return &JSONOutput{findings: findings}
}

func (j *JSONOutput) Print() error {
	encoder := json.NewEncoder(os.Stdout) //creates  JSON encoder tat writes directly to standard output
	encoder.SetIndent("", "	") //maeks the output human-readable
	return encoder.Encode(j.findings) //seriealizes the findings to JSON 
}