package main

import (
	"flag" //Go's native CLI argument parse
	"fmt"
	"os"

	"github.com/grepstrength/malsnitch/engine"
	"github.com/grepstrength/malsnitch/output"
)

func main() {
	filePath := flag.String("file", "", "pth to strings dump or FLOSS output") //registers a flag called -file, and the three arguments are flag name, default value, ad help text
	inputType := flag.String("type", "text", "input type: text or floss")
	flag.Parse() //actually reads os.Args and populates all the registered flags... extremely important
		
	if *filePath == "" {
		fmt.Println("Usage: malsnitch -file <path> [-type text|floss|binja]")
		os.Exit(1)
	}

	var eng *engine.Engine
	var err error
	
	switch *inputType { 
	case "text":
		eng, err = engine.NewFromFile(*filePath)
	case "floss":
		eng, err = engine.NewFromFLOSS(*filePath)
	case "binja":
		eng, err = engine.NewFromBinja(*filePath)
	default:
		fmt.Fprintf(os.Stderr, "Unknown input type: %s\n", inputType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err) //writes to stderr instead of stdout. JSON findings go to stdout and status messages go to stderr
		os.Exit(1)
	}

	findings, err := eng.Run() //reads the file and runs all detectors
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(findings) == 0 { //if no secrets are found, print the message
		fmt.Println("No secrets detected.")
		return
	}

	fmt.Fprintf(os.Stderr, "Found %d potential secrets(s)\n\n", len(findings)) //constructor and method call in one line
	output.NewJSONOutput(findings).Print()
}