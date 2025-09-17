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

func TestGenerateWorkspacePrefixedResourceName(t *testing.T) {
	tests := []struct {
		name         string
		workspaceID  string
		resourceName string
		resourceID   string
		basePrefix   string
		expected     string
	}{
		{
			name:         "normal workspace and resource names",
			workspaceID:  "prod_tf_ngwaf_site",
			resourceName: "SQL Injection Protection",
			resourceID:   "CVE-2025-12345",
			basePrefix:   "ngwaf_virtual_patches",
			expected:     "prod_tf_ngwaf_site_sql_injection_protection",
		},
		{
			name:         "workspace ID with special chars and empty resource name",
			workspaceID:  "prod-workspace-123",
			resourceName: "",
			resourceID:   "alert-uuid-456",
			basePrefix:   "ngwaf_alert_slack",
			expected:     "prod_workspace_123_alert_uuid_456",
		},
		{
			name:         "complex workspace ID and resource name",
			workspaceID:  "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			resourceName: "Critical Performance Alert",
			resourceID:   "alert-789",
			basePrefix:   "ngwaf_alert_datadog",
			expected:     "a1b2c3d4_e5f6_7890_abcd_ef1234567890_critical_performance_alert",
		},
		{
			name:         "workspace with numbers and threshold",
			workspaceID:  "123workspace",
			resourceName: "Rate Limit Threshold",
			resourceID:   "threshold-abc",
			basePrefix:   "ngwaf_thresholds",
			expected:     "tf_123workspace_rate_limit_threshold",
		},
		{
			name:         "redaction field with underscores",
			workspaceID:  "dev_workspace",
			resourceName: "user_password",
			resourceID:   "redaction-123",
			basePrefix:   "ngwaf_redaction",
			expected:     "dev_workspace_user_password",
		},
		{
			name:         "empty resource name falls back to ID",
			workspaceID:  "test_ws",
			resourceName: "",
			resourceID:   "virtual-patch-456",
			basePrefix:   "ngwaf_virtual_patches",
			expected:     "test_ws_virtual_patch_456",
		},
		{
			name:         "resource name with problematic characters",
			workspaceID:  "workspace-one",
			resourceName: "Test-Alert!@#$%",
			resourceID:   "alert-999",
			basePrefix:   "ngwaf_alert_webhook",
			expected:     "workspace_one_test_alert",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateWorkspacePrefixedResourceName(tt.workspaceID, tt.resourceName, tt.resourceID, tt.basePrefix)
			if result != tt.expected {
				t.Errorf("generateWorkspacePrefixedResourceName(%q, %q, %q, %q) = %q, want %q", 
					tt.workspaceID, tt.resourceName, tt.resourceID, tt.basePrefix, result, tt.expected)
			}
		})
	}
}

func TestValidateImportMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid mode all",
			input:    "all",
			expected: "all",
		},
		{
			name:     "valid mode ngwaf",
			input:    "ngwaf",
			expected: "ngwaf",
		},
		{
			name:     "invalid mode should default to all",
			input:    "invalid",
			expected: "all",
		},
		{
			name:     "empty mode should default to all",
			input:    "",
			expected: "all",
		},
		{
			name:     "case sensitive - NGWAF should default to all",
			input:    "NGWAF",
			expected: "all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateImportMode(tt.input)
			if result != tt.expected {
				t.Errorf("validateImportMode(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}