package console

import (
	"fmt"
	"strings"

	"goBastion/utils"
)

type ContentBlock struct {
	Title     string
	BlockType string
	Sections  []SectionContent
	Footer    string
}

type SectionContent struct {
	SubTitle      string
	SubTitleColor func(a ...interface{}) string
	SubSubTitle   string
	Body          []string
}

// getTitleColor returns the color function for a block title based on its type.
func getTitleColor(blockType string) func(a ...interface{}) string {
	switch strings.ToLower(blockType) {
	case "error":
		return utils.FgRedB
	case "success":
		return utils.FgGreenB
	case "warning":
		return utils.FgYellowB
	case "info":
		return utils.FgCyanB
	case "help":
		return utils.FgGreenB
	default:
		return utils.FgGreenB
	}
}

// getFrameColor returns the color function for a block frame based on its type.
func getFrameColor(blockType string) func(a ...interface{}) string {
	switch strings.ToLower(blockType) {
	case "error":
		return utils.FgRed
	case "success":
		return utils.FgGreen
	case "warning":
		return utils.FgYellow
	case "info":
		return utils.FgCyan
	case "help":
		return utils.FgCyan
	default:
		return utils.FgCyan
	}
}

// DisplayBlock renders a formatted, colored console output block.
func DisplayBlock(block ContentBlock) {
	if !strings.HasPrefix(block.Title, "▶") {
		block.Title = "▶ " + block.Title
	}
	titleColor := getTitleColor(block.BlockType)
	frameColor := getFrameColor(block.BlockType)
	fmt.Println(frameColor("╭───goBastion──────────────────────────────────────────────"))
	fmt.Println(frameColor("│ ") + titleColor(block.Title))
	fmt.Println(frameColor("├──────────────────────────────────────────────────────────"))
	for i, section := range block.Sections {
		space := "│ "
		if section.SubTitle != "" {
			if i > 0 {
				fmt.Println(frameColor("│"))
			}
			if section.SubTitleColor != nil {
				fmt.Println(frameColor(space) + section.SubTitleColor(section.SubTitle))
			} else {
				fmt.Println(frameColor(space) + utils.FgYellowB(section.SubTitle))
			}
		}
		if section.SubSubTitle != "" {
			fmt.Println(frameColor(space+"  ") + utils.FgWhiteB(section.SubSubTitle))
		}
		for _, line := range section.Body {
			fmt.Println(frameColor(space+"    ") + utils.FgWhite(line))
		}
	}
	if block.Footer != "" {
		fmt.Println(frameColor("├──────────────────────────────────────────────────────────"))
		fmt.Println(frameColor("│ ") + utils.FgWhite(block.Footer))
	}
	fmt.Println(frameColor("╰──────────────────────────────────────────────────────────"))
}
