package monitor

import "testing"

func TestStatusCodeAccepted(t *testing.T) {
	tests := []struct {
		name                string
		statusCode          int
		acceptedStatusCodes string
		want                bool
	}{
		{name: "default accepts 2xx", statusCode: 204, acceptedStatusCodes: "", want: true},
		{name: "default rejects 3xx", statusCode: 302, acceptedStatusCodes: "", want: false},
		{name: "single wildcard accepts matching class", statusCode: 201, acceptedStatusCodes: "2xx", want: true},
		{name: "single wildcard rejects other class", statusCode: 404, acceptedStatusCodes: "2xx", want: false},
		{name: "exact code accepts only exact match", statusCode: 302, acceptedStatusCodes: "302", want: true},
		{name: "comma separated accepts later pattern", statusCode: 404, acceptedStatusCodes: "2xx, 404", want: true},
		{name: "middle wildcard accepts digit range", statusCode: 418, acceptedStatusCodes: "4x8", want: true},
		{name: "case insensitive wildcard", statusCode: 500, acceptedStatusCodes: "5XX", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statusCodeAccepted(tt.statusCode, tt.acceptedStatusCodes); got != tt.want {
				t.Fatalf("statusCodeAccepted(%d, %q) = %t, want %t", tt.statusCode, tt.acceptedStatusCodes, got, tt.want)
			}
		})
	}
}

func TestValidateAcceptedStatusCodes(t *testing.T) {
	valid := []string{"2xx", "200", "2xx,3xx", "20x, 404", "5XX"}
	for _, value := range valid {
		t.Run("valid "+value, func(t *testing.T) {
			if err := validateAcceptedStatusCodes(value); err != nil {
				t.Fatalf("validateAcceptedStatusCodes(%q) returned error: %v", value, err)
			}
		})
	}

	invalid := []string{"20", "2000", "2*x", "ok"}
	for _, value := range invalid {
		t.Run("invalid "+value, func(t *testing.T) {
			if err := validateAcceptedStatusCodes(value); err == nil {
				t.Fatalf("validateAcceptedStatusCodes(%q) returned nil error", value)
			}
		})
	}
}
