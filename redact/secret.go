// Package redact contains the one presentation rule used for secrets in ARTEX.
package redact

import (
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

// Secret replaces the final 30 percent of a value with stars, with a minimum
// of three stars. Short values are completely hidden. It is rune-aware.
func Secret(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return ""
	}
	hidden := int(math.Ceil(float64(len(runes)) * 0.30))
	if hidden < 3 {
		hidden = 3
	}
	if hidden >= len(runes) {
		return strings.Repeat("*", len(runes))
	}
	return string(runes[:len(runes)-hidden]) + strings.Repeat("*", hidden)
}

// KnownSecrets replaces exact known secret values in text. Longer values are
// handled first so an overlapping short token cannot expose the remainder.
func KnownSecrets(text string, values []string) string {
	values = append([]string(nil), values...)
	sort.SliceStable(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	unique := values[:0]
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			unique = append(unique, value)
		}
	}
	var out strings.Builder
	for position := 0; position < len(text); {
		matched := ""
		for _, value := range unique {
			if strings.HasPrefix(text[position:], value) {
				matched = value
				break
			}
		}
		if matched != "" {
			out.WriteString(Secret(matched))
			position += len(matched)
			continue
		}
		_, size := utf8.DecodeRuneInString(text[position:])
		out.WriteString(text[position : position+size])
		position += size
	}
	return out.String()
}
