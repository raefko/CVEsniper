package main

import (
	"flag"
	"fmt"
	"os"

	utils "github.com/raefko/cvesniper/utils"
	"golang.org/x/mod/modfile"
)

var verbose bool

func init() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose mode")
}

func main() {
	// Check if command line arguments are provided
	if len(os.Args) < 2 {
		fmt.Println("Please provide a module file as an argument")
		os.Exit(1)
	}
	flag.Parse()
	// Read the first command line argument
	moduleFilePath := os.Args[1]

	// Read the module file
	data, err := os.ReadFile(moduleFilePath)
	if err != nil {
		fmt.Println("Error reading module file:", err)
		os.Exit(1)
	}

	// Parse the module file
	file, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		fmt.Println("Error parsing module file:", err)
		os.Exit(1)
	}

	// Apply all replace directives
	for _, r := range file.Replace {
		if r.New.Version == "" {
			continue
		}
		utils.ChangeVersion(file, r.Old.Path, r.New.Version)
	}
	totalVulnerabilities := 0

	// Print all the modules used and their versions
	for _, require := range file.Require {
		if verbose {
			fmt.Printf("├── Module: %s, Version: %s\n", require.Mod.Path, require.Mod.Version)
		}
		totalVulnerabilities += utils.Snyking(require.Mod.Path, require.Mod.Version)
	}
	fmt.Printf("└─Total Vulnerabilities %d: ", totalVulnerabilities)

}
