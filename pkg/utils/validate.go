package utils

func ValidateString(src *string) bool {
	return src != nil && *src != ""
}
