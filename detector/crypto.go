package detector
//lives with detector.go so they can share the package and see each other's types
import (
	"encoding/hex" //checks if a string is a valid hexadecimal
	"fmt" //for string formatting to build description strings
	"regexp" 
	"strings" 
)

//this is the struct that will implement the Detector interface, holding a slice of cryptoPattern
type CryptoDetector struct {
	patterns []cryptoPattern
}

//this is lowercase, meaning this is unexported and only this package can use it.
type cryptoPattern struct {
	name 	string //the kind of key hat his pattern catches
	regex	*regexp.Regexp // compiled regular expression with a pointer to regex.Regexp. after compiling regexes, you reuse them
	keyLengths	[]int //valid byte lengths for this ey type
	confidence	string //default confidence level for matches on this pattern
}

func NewCryptoDetector() *CryptoDetector {
	return &CryptoDetector{
		patterns: []cryptoPattern{
			{
				name:       "AES-128 Key",
				regex:      regexp.MustCompile(`(?i)([0-9a-f]{32})`),
				keyLengths: []int{16},
				confidence: "medium",
			},
			{
				name:       "AES-256 Key",
				regex:      regexp.MustCompile(`(?i)([0-9a-f]{64})`),
				keyLengths: []int{32},
				confidence: "medium",
			},
			{
				name:       "RC4 Key (hex)",
				regex:      regexp.MustCompile(`(?i)([0-9a-f]{10,64})`),
				keyLengths: []int{5, 8, 16, 32},
				confidence: "low",
			},
		},
	}
}

func (d *CryptoDetector) Detect(lines []string) []Finding {
	var findings []Finding //declares an empty slice

	for lineNum,line := range lines { //iterates over the input with the range on slice giving two values, the lineNum and the line
		for _, pattern := range d.patterns { //iterates over the detector's patterns
			matches := pattern.regex.FindAllString(line, -1) 

			for _, match := range matches {
				if !isLikelyKey(match, pattern.keyLengths) {
					continue
				}
				findings = append(findings, Finding{
					DetectorName:	d.Name(),
					Description:	fmt.Sprintf("Potential %s detected", pattern.name),
					Secret: 		match,
					Context:		buildContext(lines, lineNum, 2),
					LineNumber:		lineNum + 1,
					Confidence:		pattern.confidence,
				})
			}
		}
	}
	return findings
}

//now the helper functions

//this is the false positive filter... hex.DecodeString(match) tries to decode the hext string into raw bytes
func isLikelyKey(match string, validLengths []int) bool {
	decoded, err := hex.DecodeString(match)
	if err != nil {
		return false
	}

	for _, length := range validLengths {
		if len(decoded) == length {
			return true
		}
	}
	return false
}

//grabs the lindes around a match for analyst review, radius of 2 means 2 lines above and 2 below
func buildContext(lines []string, lineNum int, radius int) string {
	start := lineNum - radius
	if start < 0 {
		start = 0
	}

	end := lineNum + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n") //this is a slce expression which creates a new slice from index start up to but not including end
}

func (d *CryptoDetector) Name() string {
	return "crypto_key"
}