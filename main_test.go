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
		// Test cases for NGWAF account list
		{
			name:     "normal list name",
			input:    "IP Blocklist",
			prefix:   "ngwaf_account_list",
			expected: "ip_blocklist",
		},
		{
			name:     "empty list name",
			input:    "",
			prefix:   "ngwaf_account_list",
			expected: "ngwaf_account_list_unnamed",
		},
		{
			name:     "list ID for fallback",
			input:    "list-12345-abcde",
			prefix:   "list",
			expected: "list_12345_abcde",
		},
		// Test cases for NGWAF account rule
		{
			name:     "normal rule description",
			input:    "Block malicious requests",
			prefix:   "ngwaf_account_rule",
			expected: "block_malicious_requests",
		},
		{
			name:     "empty rule description",
			input:    "",
			prefix:   "ngwaf_account_rule",
			expected: "ngwaf_account_rule_unnamed",
		},
		{
			name:     "rule ID for fallback",
			input:    "rule-67890-xyz",
			prefix:   "rule",
			expected: "rule_67890_xyz",
		},
		// Test cases for NGWAF account signal
		{
			name:     "normal signal name",
			input:    "SQL Injection Signal",
			prefix:   "ngwaf_account_signal",
			expected: "sql_injection_signal",
		},
		{
			name:     "empty signal name",
			input:    "",
			prefix:   "ngwaf_account_signal",
			expected: "ngwaf_account_signal_unnamed",
		},
		{
			name:     "signal ID for fallback",
			input:    "signal-abc123-def456",
			prefix:   "signal",
			expected: "signal_abc123_def456",
		},
		// Test cases for NGWAF alert integrations
		{
			name:     "normal alert description",
			input:    "Critical Performance Alert",
			prefix:   "ngwaf_alert_datadog",
			expected: "critical_performance_alert",
		},
		{
			name:     "empty alert description",
			input:    "",
			prefix:   "ngwaf_alert_slack",
			expected: "ngwaf_alert_slack_unnamed",
		},
		{
			name:     "alert ID for fallback",
			input:    "alert-uuid-123",
			prefix:   "alert",
			expected: "alert_uuid_123",
		},
		// Test cases for NGWAF workspace resources
		{
			name:     "normal redaction field",
			input:    "user_password",
			prefix:   "ngwaf_redaction",
			expected: "user_password",
		},
		{
			name:     "empty redaction field",
			input:    "",
			prefix:   "ngwaf_redaction",
			expected: "ngwaf_redaction_unnamed",
		},
		{
			name:     "normal threshold name",
			input:    "Rate Limit Threshold",
			prefix:   "ngwaf_thresholds",
			expected: "rate_limit_threshold",
		},
		{
			name:     "normal virtual patch description",
			input:    "SQL Injection Protection",
			prefix:   "ngwaf_virtual_patches",
			expected: "sql_injection_protection",
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