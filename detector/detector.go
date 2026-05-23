package detector

type Finding struct {
	//im using backticks as struct tags, telling Go's JSON encoder to use detector_name instead of DetectorName, otherwise it would use Go's camelCase
	DetectorName string `json:"detector_name"`
	Description string `json:"description"`
	Secret string `json:"secret"`
	Context string `json:"context,omitempty"`
	LineNumber int `json:"line_number,omitempty"`
	Confidence string `json:"confidence"` 
}

type Detector interface {
	//this defines a set of method signatures
	//my engine doesn't need to know about every detector type, allowing me to iterate and add new credential types without changing the engine code
	Name() string
	Detect(lines []string) []Finding
}
