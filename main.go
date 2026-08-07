package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/grepstrength/malsnitch/engine"
	"github.com/grepstrength/malsnitch/output"
)

var version = "0.1.0" //package level variable... currently hardcoded, but I might inject at build time

func main() {
	filePath := flag.String("file", "", "path to input file") //registers a flag called -file, and the three arguments are flag name, default value, ad help text
	inputType := flag.String("type", "text", "input type: text, floss, binja or memdump")
	showVersion := flag.Bool("version", false, "print version and exit")
	outputFormat := flag.String("output", "json", "output format: json or csv")
	flag.Usage = func() { //overrides the default help output
		fmt.Fprintf(os.Stderr, "malsnitch v%s\n", version)
		fmt.Fprintf(os.Stderr, "Malware secrets scanner — extracts embedded credentials, crypto keys, and C2 artifacts\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  malsnitch -file <path> [-type text|floss|binja|memdump]\n\n")
		fmt.Fprintf(os.Stderr, "Input types:\n")
		fmt.Fprintf(os.Stderr, "  text    Plain text strings dump (strings.exe, FLOSS raw output)\n")
		fmt.Fprintf(os.Stderr, "  floss   FLOSS JSON output (floss -j sample.exe)\n")
		fmt.Fprintf(os.Stderr, "  binja   Binary Ninja export JSON (bn_export.py)\n")
		fmt.Fprintf(os.Stderr, "  memdump Memory dump\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fmt.Fprintf(os.Stderr, "\nOutput formats:\n")
		fmt.Fprintf(os.Stderr, "  json   Structured JSON (default)\n")
		fmt.Fprintf(os.Stderr, "  csv    Comma-separated values\n\n")
		flag.PrintDefaults() //prins the auto-generated flag descriptions
	}

	flag.Parse() //actually reads os.Args and populates all the registered flags... extremely important
	if *showVersion {
		fmt.Printf("malsnitch v%s\n", version)
		os.Exit(0)
	}

	if *filePath == "" {
		flag.Usage()
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
	case "memdump":
		eng, err = engine.NewFromMemDump(*filePath)
	default:
		fmt.Fprintf(os.Stderr, "Unknown input type: %s\n", *inputType)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err) //writes to stderr instead of stdout. JSON findings go to stdout and status messages go to stderr
		os.Exit(1)
	}
	findings, err := eng.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "No secrets detected.")
		os.Exit(2) //clean scan with no findings
	}
	fmt.Fprintf(os.Stderr, "Found %d potential secret(s)\n\n", len(findings))

		switch *outputFormat {
		case "json":
			output.NewJSONOutput(findings).Print()
		case "csv":
			output.NewCSVOutput(findings).Print()
		default:
			fmt.Fprintf(os.Stderr, "Unknown output format: %s\n", *outputFormat)
			os.Exit(1)
		}

}