// Package validate holds input validation shared by config and handlers.
package validate

import (
	"errors"
	"fmt"
	"strings"
)

const (
	MaxDomainLen = 253
	MaxLabelLen  = 63
)

// NormalizeDomain trims, validates and lower-cases a domain name.
// Allowed characters: ASCII letters, digits, '-', '_' and '.' as a label
// separator. Non-ASCII input is rejected outright to avoid homoglyph tricks.
func NormalizeDomain(s string) (string, error) {
	d := strings.TrimSpace(s)
	if d == "" {
		return "", errors.New("domain is empty")
	}
	if len(d) > MaxDomainLen {
		return "", fmt.Errorf("domain exceeds %d characters", MaxDomainLen)
	}
	labelLen := 0
	for i := 0; i < len(d); i++ {
		c := d[i]
		switch {
		case c == '.':
			if labelLen == 0 {
				return "", errors.New("domain contains an empty label")
			}
			labelLen = 0
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_':
			labelLen++
			if labelLen > MaxLabelLen {
				return "", fmt.Errorf("domain label exceeds %d characters", MaxLabelLen)
			}
		default:
			return "", errors.New("domain contains invalid characters (allowed: a-z, 0-9, '-', '_', '.')")
		}
	}
	if labelLen == 0 {
		return "", errors.New("domain contains an empty label")
	}
	return strings.ToLower(d), nil
}
