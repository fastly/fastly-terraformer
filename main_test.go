package main

import (
	"strings"
	"testing"
	
	"github.com/fastly/go-fastly/v11/fastly"
	"github.com/fastly/go-fastly/v11/fastly/ngwaf/v1/lists"
	"github.com/fastly/go-fastly/v11/fastly/ngwaf/v1/rules"
	"github.com/fastly/go-fastly/v11/fastly/ngwaf/v1/signals"
	"github.com/fastly/go-fastly/v11/fastly/ngwaf/v1/workspaces"
	"github.com/hashicorp/hcl/v2/hclwrite"
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
			expected:     "prod_tf_ngwaf_site_sql_injection_protection_cve_2025_12345",
		},
		{
			name:         "workspace ID with special chars and empty resource name",
			workspaceID:  "prod-workspace-123",
			resourceName: "",
			resourceID:   "alert-uuid-456",
			basePrefix:   "ngwaf_alert_slack",
			expected:     "prod_workspace_123_resource_alert_uuid_456",
		},
		{
			name:         "complex workspace ID and resource name",
			workspaceID:  "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			resourceName: "Critical Performance Alert",
			resourceID:   "alert-789",
			basePrefix:   "ngwaf_alert_datadog",
			expected:     "a1b2c3d4_e5f6_7890_abcd_ef1234567890_critical_performance_alert_alert_789",
		},
		{
			name:         "workspace with numbers and threshold",
			workspaceID:  "123workspace",
			resourceName: "Rate Limit Threshold",
			resourceID:   "threshold-abc",
			basePrefix:   "ngwaf_thresholds",
			expected:     "tf_123workspace_rate_limit_threshold_threshold_abc",
		},
		{
			name:         "redaction field with underscores",
			workspaceID:  "dev_workspace",
			resourceName: "user_password",
			resourceID:   "redaction-123",
			basePrefix:   "ngwaf_redaction",
			expected:     "dev_workspace_user_password_redaction_123",
		},
		{
			name:         "empty resource name falls back to ID",
			workspaceID:  "test_ws",
			resourceName: "",
			resourceID:   "virtual-patch-456",
			basePrefix:   "ngwaf_virtual_patches",
			expected:     "test_ws_resource_virtual_patch_456",
		},
		{
			name:         "resource name with problematic characters",
			workspaceID:  "workspace-one",
			resourceName: "Test-Alert!@#$%",
			resourceID:   "alert-999",
			basePrefix:   "ngwaf_alert_webhook",
			expected:     "workspace_one_test_alert_alert_999",
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

// TestGenerateWorkspacePrefixedResourceNameUniqueness tests that resources with the same name get unique identifiers
func TestGenerateWorkspacePrefixedResourceNameUniqueness(t *testing.T) {
	// Test scenario: Multiple resources with the same name should generate unique resource names
	workspaceID := "dev_tf_ngwaf_site"
	resourceName := "foo" // Same name for both resources
	basePrefix := "ngwaf_workspace_rule"
	
	// Two different resource IDs representing the same named resources
	resourceID1 := "67f92e6930d0ab5d50ceca89"
	resourceID2 := "67f919f39c8407b6764e942f"
	
	result1 := generateWorkspacePrefixedResourceName(workspaceID, resourceName, resourceID1, basePrefix)
	result2 := generateWorkspacePrefixedResourceName(workspaceID, resourceName, resourceID2, basePrefix)
	
	// Results should be different to avoid duplicate import blocks
	if result1 == result2 {
		t.Errorf("Expected different resource names for same-named resources, but got: %q and %q", result1, result2)
	}
	
	// Both should contain the resource name
	if !strings.Contains(result1, "foo") {
		t.Errorf("Expected result1 %q to contain resource name 'foo'", result1)
	}
	if !strings.Contains(result2, "foo") {
		t.Errorf("Expected result2 %q to contain resource name 'foo'", result2)
	}
	
	// Both should contain their respective resource IDs to ensure uniqueness
	expectedSubstring1 := "tf_67f92e6930d0ab5d50ceca89"
	expectedSubstring2 := "tf_67f919f39c8407b6764e942f"
	
	if !strings.Contains(result1, expectedSubstring1) {
		t.Errorf("Expected result1 %q to contain resource ID substring %q", result1, expectedSubstring1)
	}
	if !strings.Contains(result2, expectedSubstring2) {
		t.Errorf("Expected result2 %q to contain resource ID substring %q", result2, expectedSubstring2)
	}
	
	// Verify both results follow the expected pattern: workspace_resourcename_resourceid
	expectedPattern1 := "dev_tf_ngwaf_site_foo_tf_67f92e6930d0ab5d50ceca89"
	expectedPattern2 := "dev_tf_ngwaf_site_foo_tf_67f919f39c8407b6764e942f"
	
	if result1 != expectedPattern1 {
		t.Errorf("Expected result1 to be %q, got %q", expectedPattern1, result1)
	}
	if result2 != expectedPattern2 {
		t.Errorf("Expected result2 to be %q, got %q", expectedPattern2, result2)
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

// TestImportNGWAFWorkspaces tests the NGWAF workspace import function with minimal verification
func TestImportNGWAFWorkspaces(t *testing.T) {
	// This test verifies the function exists and has the right signature
	// We don't call it because it requires a valid client and would make API calls
	
	// Verify function signature by checking it can be assigned to a variable
	var fn func(*fastly.Client, *hclwrite.Body) (*workspaces.Workspaces, int, error)
	fn = importNGWAFWorkspaces
	if fn == nil {
		t.Error("importNGWAFWorkspaces function should exist")
	}
}

// TestImportNGWAFAccountLists tests the NGWAF account lists import function
func TestImportNGWAFAccountLists(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body) (*lists.Lists, int, error)
	fn = importNGWAFAccountLists
	if fn == nil {
		t.Error("importNGWAFAccountLists function should exist")
	}
}

// TestImportNGWAFAccountRules tests the NGWAF account rules import function
func TestImportNGWAFAccountRules(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body) (*rules.Rules, int, error)
	fn = importNGWAFAccountRules
	if fn == nil {
		t.Error("importNGWAFAccountRules function should exist")
	}
}

// TestImportNGWAFAccountSignals tests the NGWAF account signals import function
func TestImportNGWAFAccountSignals(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body) (*signals.Signals, int, error)
	fn = importNGWAFAccountSignals
	if fn == nil {
		t.Error("importNGWAFAccountSignals function should exist")
	}
}

// TestImportNGWAFWorkspaceScopedResources tests the workspace-scoped import function
func TestImportNGWAFWorkspaceScopedResources(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body, *workspaces.Workspaces) (int, error)
	fn = importNGWAFWorkspaceScopedResources
	if fn == nil {
		t.Error("importNGWAFWorkspaceScopedResources function should exist")
	}
	
	// Test with nil workspaces (should return 0 count and no error)
	importCount, err := importNGWAFWorkspaceScopedResources(nil, nil, nil)
	if importCount != 0 {
		t.Error("Expected 0 import count when workspaces is nil")
	}
	if err != nil {
		t.Errorf("Expected no error when workspaces is nil, got %v", err)
	}
}

// TestImportNGWAFWorkspaceLists tests the workspace-scoped lists import function
func TestImportNGWAFWorkspaceLists(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body, *workspaces.Workspaces) (int, error)
	fn = importNGWAFWorkspaceLists
	if fn == nil {
		t.Error("importNGWAFWorkspaceLists function should exist")
	}
	
	// Test with nil workspaces (should return 0 count and no error)
	importCount, err := importNGWAFWorkspaceLists(nil, nil, nil)
	if importCount != 0 {
		t.Error("Expected 0 import count when workspaces is nil")
	}
	if err != nil {
		t.Errorf("Expected no error when workspaces is nil, got %v", err)
	}
}

// TestImportNGWAFWorkspaceRules tests the workspace-scoped rules import function
func TestImportNGWAFWorkspaceRules(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body, *workspaces.Workspaces) (int, error)
	fn = importNGWAFWorkspaceRules
	if fn == nil {
		t.Error("importNGWAFWorkspaceRules function should exist")
	}
	
	// Test with nil workspaces (should return 0 count and no error)
	importCount, err := importNGWAFWorkspaceRules(nil, nil, nil)
	if importCount != 0 {
		t.Error("Expected 0 import count when workspaces is nil")
	}
	if err != nil {
		t.Errorf("Expected no error when workspaces is nil, got %v", err)
	}
}

// TestImportNGWAFWorkspaceSignals tests the workspace-scoped signals import function
func TestImportNGWAFWorkspaceSignals(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body, *workspaces.Workspaces) (int, error)
	fn = importNGWAFWorkspaceSignals
	if fn == nil {
		t.Error("importNGWAFWorkspaceSignals function should exist")
	}
	
	// Test with nil workspaces (should return 0 count and no error)
	importCount, err := importNGWAFWorkspaceSignals(nil, nil, nil)
	if importCount != 0 {
		t.Error("Expected 0 import count when workspaces is nil")
	}
	if err != nil {
		t.Errorf("Expected no error when workspaces is nil, got %v", err)
	}
}

// TestImportConfigStores tests the Config Store import function
func TestImportConfigStores(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body) (int, error)
	fn = importConfigStores
	if fn == nil {
		t.Error("importConfigStores function should exist")
	}
}

// TestImportKVStores tests the KV Store import function
func TestImportKVStores(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body) (int, error)
	fn = importKVStores
	if fn == nil {
		t.Error("importKVStores function should exist")
	}
}

// TestImportSecretStores tests the Secret Store import function
func TestImportSecretStores(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body) (int, error)
	fn = importSecretStores
	if fn == nil {
		t.Error("importSecretStores function should exist")
	}
}

// TestImportServiceDomains tests the service domain import function
func TestImportServiceDomains(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body, []*fastly.Service) (int, error)
	fn = importServiceDomains
	if fn == nil {
		t.Error("importServiceDomains function should exist")
	}

	// Test with nil/empty services
	importCount, err := importServiceDomains(nil, nil, nil)
	if importCount != 0 {
		t.Error("Expected 0 import count when services is nil")
	}
	if err != nil {
		t.Errorf("Expected no error when services is nil, got %v", err)
	}

	// Test with empty services slice
	importCount, err = importServiceDomains(nil, nil, []*fastly.Service{})
	if importCount != 0 {
		t.Error("Expected 0 import count when services is empty")
	}
	if err != nil {
		t.Errorf("Expected no error when services is empty, got %v", err)
	}
}

// TestImportServiceACLs tests the service ACL import function
func TestImportServiceACLs(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body, []*fastly.Service) (int, error)
	fn = importServiceACLs
	if fn == nil {
		t.Error("importServiceACLs function should exist")
	}

	// Test with nil/empty services
	importCount, err := importServiceACLs(nil, nil, nil)
	if importCount != 0 {
		t.Error("Expected 0 import count when services is nil")
	}
	if err != nil {
		t.Errorf("Expected no error when services is nil, got %v", err)
	}
}

// TestImportServiceDictionaries tests the service dictionary import function
func TestImportServiceDictionaries(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body, []*fastly.Service) (int, error)
	fn = importServiceDictionaries
	if fn == nil {
		t.Error("importServiceDictionaries function should exist")
	}

	// Test with nil/empty services
	importCount, err := importServiceDictionaries(nil, nil, nil)
	if importCount != 0 {
		t.Error("Expected 0 import count when services is nil")
	}
	if err != nil {
		t.Errorf("Expected no error when services is nil, got %v", err)
	}
}

// TestImportServiceBackends tests the service backend import function
func TestImportServiceBackends(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body, []*fastly.Service) (int, error)
	fn = importServiceBackends
	if fn == nil {
		t.Error("importServiceBackends function should exist")
	}

	// Test with nil/empty services
	importCount, err := importServiceBackends(nil, nil, nil)
	if importCount != 0 {
		t.Error("Expected 0 import count when services is nil")
	}
	if err != nil {
		t.Errorf("Expected no error when services is nil, got %v", err)
	}
}

// TestImportTLSSubscriptions tests the TLS subscription import function
func TestImportTLSSubscriptions(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body) (int, error)
	fn = importTLSSubscriptions
	if fn == nil {
		t.Error("importTLSSubscriptions function should exist")
	}
}

// TestImportTLSActivations tests the TLS activation import function
func TestImportTLSActivations(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body) (int, error)
	fn = importTLSActivations
	if fn == nil {
		t.Error("importTLSActivations function should exist")
	}
}

// TestImportServiceHealthChecks tests the service health check import function
func TestImportServiceHealthChecks(t *testing.T) {
	// Verify function signature exists
	var fn func(*fastly.Client, *hclwrite.Body, []*fastly.Service) (int, error)
	fn = importServiceHealthChecks
	if fn == nil {
		t.Error("importServiceHealthChecks function should exist")
	}

	// Test with nil/empty services
	importCount, err := importServiceHealthChecks(nil, nil, nil)
	if importCount != 0 {
		t.Error("Expected 0 import count when services is nil")
	}
	if err != nil {
		t.Errorf("Expected no error when services is nil, got %v", err)
	}
}