package main

import (
	"fmt"
	"os"

	"goBastion/internal/dbsandbox"
)

func main() {
	if err := dbsandbox.Worker(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
