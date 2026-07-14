package config

import "testing"

func TestTemplateToRegexDomainSuffix(t *testing.T) {
	re, err := TemplateToRegex(".example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"example.com", "www.example.com", "a.b.example.com"} {
		if !re.MatchString(host) {
			t.Errorf("suffix pattern did not match %q", host)
		}
	}
	for _, host := range []string{"notexample.com", "example.com.invalid"} {
		if re.MatchString(host) {
			t.Errorf("suffix pattern unexpectedly matched %q", host)
		}
	}
}
