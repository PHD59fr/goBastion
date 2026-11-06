package session

import "goBastion/internal/utils/commandline"

func parseCommandLine(line string) ([]string, error) {
	return commandline.Split(line)
}
