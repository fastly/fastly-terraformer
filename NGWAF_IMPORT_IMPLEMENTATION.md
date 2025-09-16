# NGWAF Import Implementation

This document describes the implementation of NGWAF (Next-Gen WAF) resource import functionality added to the fastly-terraformer.

## Implemented Resources

### Alert Integration Resources (Workspace-scoped)
All alert integrations are workspace-scoped and require iterating through workspaces:

1. `fastly_ngwaf_alert_datadog_integration`
2. `fastly_ngwaf_alert_jira_integration`
3. `fastly_ngwaf_alert_mailing_list_integration`
4. `fastly_ngwaf_alert_microsoft_teams_integration`
5. `fastly_ngwaf_alert_opsgenie_integration`
6. `fastly_ngwaf_alert_pagerduty_integration`
7. `fastly_ngwaf_alert_slack_integration`
8. `fastly_ngwaf_alert_webhook_integration`

### Workspace-scoped Resources
1. `fastly_ngwaf_redaction`
2. `fastly_ngwaf_thresholds`
3. `fastly_ngwaf_virtual_patches`

### Previously Implemented Resources
- `fastly_ngwaf_workspace` - Workspace management
- `fastly_ngwaf_account_list` - Account-level lists
- `fastly_ngwaf_account_rule` - Account-level rules  
- `fastly_ngwaf_account_signal` - Account-level signals

## Implementation Details

### Import ID Format
- **Workspace resources**: `{workspace_id}/{resource_id}`
- **Account resources**: `{resource_id}` (existing pattern)

### Resource Name Generation
- Uses descriptive names when available (alert description, redaction field, threshold name, etc.)
- Falls back to resource ID when names are empty or problematic
- Applies sanitization for Terraform compatibility (alphanumeric + underscore only)
- **NEW**: For workspace-scoped resources, prefixes resource names with sanitized workspace ID to prevent conflicts
  - Format: `{sanitized_workspace_id}_{resource_name}`
  - Example: `prod_tf_ngwaf_site_sql_injection_protection` instead of just `sql_injection_protection`

### API Integration
- Uses Fastly Go SDK v11 NGWAF packages
- Iterates through all available workspaces for workspace-scoped resources
- Handles API errors gracefully with logging
- Provides detailed progress output

### Error Handling
- Skips resources with empty/invalid IDs
- Logs API errors but continues processing other resources
- Graceful degradation if workspace access fails

## Example Output

```hcl
import {
  id = "workspace-123/alert-456"
  to = fastly_ngwaf_alert_slack_integration.workspace_123_critical_performance_alert
}

import {
  id = "workspace-123/redaction-789"
  to = fastly_ngwaf_redaction.workspace_123_user_password
}

import {
  id = "workspace-123/threshold-abc"
  to = fastly_ngwaf_thresholds.workspace_123_rate_limit_threshold
}

import {
  id = "prod_tf_ngwaf_site/CVE-2025-54236"
  to = fastly_ngwaf_virtual_patches.prod_tf_ngwaf_site_adobe_commerce_and_magento_open_source_unauthenticated_api_access
}
```

## Usage

```bash
# Set your Fastly API token
export FASTLY_API_TOKEN="your-token-here"

# Run the terraformer
go run main.go

# Generated import.tf file will contain all discovered resources
```

## Testing

The implementation includes comprehensive test cases for:
- Resource name sanitization
- Fallback behavior for empty names
- Special character handling
- All new NGWAF resource types

Run tests with:
```bash
go test -v
```

## Notes

- `fastly_ngwaf_workspace_list`, `fastly_ngwaf_workspace_rule`, and `fastly_ngwaf_workspace_signal` from the original requirements are not available as separate workspace-scoped APIs. Lists, rules, and signals are account-level resources already implemented.
- All workspace-scoped resources require valid workspace access
- The implementation follows existing patterns in the codebase for consistency