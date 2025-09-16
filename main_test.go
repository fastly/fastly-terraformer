package main

import (
	"testing"
)

func TestSanitizeForTerraformResourceName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		prefix   string
		expected string
	}{
		{
			name:     "normal workspace name",
			input:    "Production Workspace",
			prefix:   "ngwaf_workspace",
			expected: "production_workspace",
		},
		{
			name:     "empty workspace name",
			input:    "",
			prefix:   "ngwaf_workspace",
			expected: "ngwaf_workspace_unnamed",
		},
		{
			name:     "workspace name with special characters",
			input:    "Test-Workspace_123!@#",
			prefix:   "ngwaf_workspace",
			expected: "test_workspace_123",
		},
		{
			name:     "workspace name starting with number",
			input:    "123workspace",
			prefix:   "ngwaf_workspace",
			expected: "tf_123workspace",
		},
		{
			name:     "workspace ID for fallback",
			input:    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			prefix:   "ws",
			expected: "a1b2c3d4_e5f6_7890_abcd_ef1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeForTerraformResourceName(tt.input, tt.prefix)
			if result != tt.expected {
				t.Errorf("sanitizeForTerraformResourceName(%q, %q) = %q, want %q", 
					tt.input, tt.prefix, result, tt.expected)
			}
		})
	}
}