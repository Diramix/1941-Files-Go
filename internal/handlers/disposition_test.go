package handlers

import "testing"

func TestContentDisposition(t *testing.T) {
	cases := []struct {
		name      string
		wantDisp  string
		wantInStr string
	}{
		{"photo.png", "inline", `filename="photo.png"`},
		{"report.pdf", "inline", `filename="report.pdf"`},
		{"evil.html", "attachment", `filename="evil.html"`},
		{"vector.svg", "attachment", `filename="vector.svg"`},
		{"a\"; x=\r\n.txt", "inline", `filename="a_; x=__.txt"`},
		{"отчёт.txt", "inline", `filename*=UTF-8''`},
	}
	for _, c := range cases {
		got := contentDisposition(c.name)
		if len(got) < len(c.wantDisp) || got[:len(c.wantDisp)] != c.wantDisp {
			t.Errorf("%q: disposition = %q, want prefix %q", c.name, got, c.wantDisp)
		}
		if !contains(got, c.wantInStr) {
			t.Errorf("%q: header %q does not contain %q", c.name, got, c.wantInStr)
		}
		if contains(got, "\n") || contains(got, "\r") {
			t.Errorf("%q: header must not contain CR/LF: %q", c.name, got)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
