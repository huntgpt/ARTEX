package redact

import "testing"

func TestSecretMasksThirtyPercentWithMinimumThree(t *testing.T) {
	for input, want := range map[string]string{
		"P@ssw0rd":   "P@ssw***",
		"1234567890": "1234567***",
		"abcd":       "a***",
		"ab":         "**",
		"":           "",
		"รหัสผ่าน":   "รหัสผ***",
	} {
		if got := Secret(input); got != want {
			t.Errorf("Secret(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestKnownSecretsMasksLongestFirst(t *testing.T) {
	got := KnownSecrets("token=abcdef and abc", []string{"abc", "abcdef"})
	if got != "token=abc*** and ***" {
		t.Fatalf("KnownSecrets = %q", got)
	}
}
