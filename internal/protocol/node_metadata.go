package protocol

// Tags are operator labels, never an authorization or execution grant.
func ValidNodeTags(tags []string) bool {
	if tags == nil || len(tags) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, tag := range tags {
		if len(tag) < 1 || len(tag) > 32 || seen[tag] {
			return false
		}
		for _, c := range tag {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == ':') {
				return false
			}
		}
		seen[tag] = true
	}
	return true
}
