# fastly-terraformer

`fastly-terraformer` is a specialized tool that generates Terraform import blocks for Fastly Edge Cloud resources. It automatically discovers your existing Fastly infrastructure and creates the necessary Terraform import statements to bring those resources under Terraform management.

## Features

- **Comprehensive Resource Discovery**: Automatically detects and imports multiple types of Fastly resources
- **Two Import Modes**: Choose between importing all resources or only NGWAF (Next-Gen WAF) resources
- **Robust Naming**: Intelligent resource name generation with sanitization for Terraform compatibility
- **Workspace-Scoped NGWAF**: Full support for workspace-scoped NGWAF resources with conflict prevention
- **Error Handling**: Graceful error handling with detailed logging and progress reporting

## Supported Resources (Imported)

### Fastly Core Services
- ✅ **`fastly_service_vcl`** - VCL services
- ✅ **`fastly_service_compute`** - Compute (WASM) services  
- ✅ **`fastly_service_dynamic_snippet_content`** - Dynamic snippets for VCL services

### NGWAF Account-Level Resources
- ✅ **`fastly_ngwaf_workspace`** - NGWAF workspace management
- ✅ **`fastly_ngwaf_account_list`** - Account-level lists
- ✅ **`fastly_ngwaf_account_rule`** - Account-level rules
- ✅ **`fastly_ngwaf_account_signal`** - Account-level signals

### NGWAF Workspace-Scoped Resources
- ✅ **`fastly_ngwaf_workspace_list`** - Workspace-specific lists
- ✅ **`fastly_ngwaf_workspace_rule`** - Workspace-specific rules
- ✅ **`fastly_ngwaf_workspace_signal`** - Workspace-specific signals

### NGWAF Alert Integrations (Workspace-Scoped)
- ✅ **`fastly_ngwaf_alert_datadog_integration`** - Datadog alert integration
- ✅ **`fastly_ngwaf_alert_jira_integration`** - Jira alert integration  
- ✅ **`fastly_ngwaf_alert_mailing_list_integration`** - Mailing list alert integration
- ✅ **`fastly_ngwaf_alert_microsoft_teams_integration`** - Microsoft Teams alert integration
- ✅ **`fastly_ngwaf_alert_opsgenie_integration`** - Opsgenie alert integration
- ✅ **`fastly_ngwaf_alert_pagerduty_integration`** - PagerDuty alert integration
- ✅ **`fastly_ngwaf_alert_slack_integration`** - Slack alert integration
- ✅ **`fastly_ngwaf_alert_webhook_integration`** - Webhook alert integration

### NGWAF Additional Workspace Resources
- ✅ **`fastly_ngwaf_redaction`** - Data redaction rules
- ✅ **`fastly_ngwaf_thresholds`** - Rate limiting thresholds
- ✅ **`fastly_ngwaf_virtual_patches`** - Virtual security patches

## Currently Unsupported Resources (Not Imported)

The following Fastly provider resources are **not currently imported** by this tool:

### Core Fastly Resources
- ❌ **`fastly_service_acl`** - Access Control Lists  
- ❌ **`fastly_service_dictionary`** - Edge dictionaries
- ❌ **`fastly_service_backend`** - Backend configurations
- ❌ **`fastly_service_director`** - Load balancing directors
- ❌ **`fastly_service_health_check`** - Health check configurations
- ❌ **`fastly_service_logging_*`** - Various logging endpoints (S3, Syslog, etc.)
- ❌ **`fastly_service_request_setting`** - Request settings
- ❌ **`fastly_service_response_object`** - Response objects
- ❌ **`fastly_service_snippet`** - Static VCL snippets
- ❌ **`fastly_service_vcl`** - Custom VCL configurations
- ❌ **`fastly_service_waf_configuration`** - Legacy WAF configurations

### TLS and Security
- ❌ **`fastly_tls_activation`** - TLS certificate activations
- ❌ **`fastly_tls_certificate`** - TLS certificates
- ❌ **`fastly_tls_configuration`** - TLS configurations  
- ❌ **`fastly_tls_private_key`** - TLS private keys
- ❌ **`fastly_tls_subscription`** - TLS subscriptions

### Additional Resources
- ❌ **`fastly_user`** - User management
- ❌ **`fastly_service_authorization`** - Service authorization tokens
- ❌ **`fastly_configstore`** - Config store resources
- ❌ **`fastly_secretstore`** - Secret store resources
- ❌ **`fastly_kvstore`** - Key-value store resources

## Prerequisites

- **Go 1.24.4+** (as specified in go.mod)
- **Fastly API Token** with appropriate permissions
- **Terraform** (for applying the generated import configuration)

## Installation

Clone the repository and build the tool:

```bash
git clone https://github.com/fastly/fastly-terraformer.git
cd fastly-terraformer
go mod tidy
go build -o fastly-terraformer
```

## Usage

### Environment Variables

Set your Fastly API token:

```bash
export FASTLY_API_KEY="your-fastly-api-token-here"
```

For Terraform generation with sensitive fields:

```bash
export FASTLY_TF_DISPLAY_SENSITIVE_FIELDS="true"
```

### Command Line Options

The tool supports two import modes:

```bash
# Import all resources (default)
./fastly-terraformer
./fastly-terraformer -import all

# Import only NGWAF resources  
./fastly-terraformer -import ngwaf

# Show help
./fastly-terraformer -help
```

### Complete Workflow

1. **Generate import blocks**:
   ```bash
   export FASTLY_API_KEY="your-token"
   export FASTLY_TF_DISPLAY_SENSITIVE_FIELDS="true"
   ./fastly-terraformer
   ```

2. **Generate Terraform configuration**:
   ```bash
   terraform init
   terraform plan -generate-config-out=generated.tf
   ```

3. **Review and apply**:
   ```bash
   # Review the generated files
   cat import.tf generated.tf
   
   # Apply the import
   terraform apply
   ```

### Makefile Shortcuts

The repository includes convenient Make targets:

```bash
# Clean previous runs and import all resources
make rerun

# Clean previous runs and import only NGWAF resources  
make rengwaf

# Build and run
make run

# Clean generated files
make clean
```

## Output Files

- **`import.tf`** - Contains all the Terraform import blocks
- **`generated.tf`** - Contains the resource configurations (generated by `terraform plan -generate-config-out`)

## Example Output

### Import Blocks (`import.tf`)
```hcl
import {
  id = "abc123def456"
  to = fastly_service_vcl.my_service
}

import {
  id = "workspace-123/list-456"
  to = fastly_ngwaf_workspace_list.ws_abc123def456_custom_blocklist_list_456
}

import {
  id = "workspace-123/alert-789"
  to = fastly_ngwaf_alert_slack_integration.ws_abc123def456_security_alerts_alert_789
}
```

### Resource Naming

The tool uses intelligent naming conventions:

- **Services**: Uses service name, falls back to service ID
- **NGWAF Account Resources**: Uses descriptive names (list name, rule description, etc.)  
- **NGWAF Workspace Resources**: Prefixed with workspace ID to prevent conflicts
  - Format: `{sanitized_workspace_id}_{resource_name}_{sanitized_resource_id}`
  - Example: `ws_prod_tf_ngwaf_security_alerts_alert_789`

## Resource Discovery Process

### For "all" Mode:
1. **Fastly Services**: Discovers all VCL and Compute services
2. **Dynamic Snippets**: For each VCL service, finds all dynamic snippets
3. **NGWAF Resources**: Discovers all NGWAF resources (same as "ngwaf" mode)

### For "ngwaf" Mode:
1. **Workspaces**: Lists all available NGWAF workspaces
2. **Account-Level**: Lists account-scoped lists, rules, and signals
3. **Workspace-Scoped**: For each workspace, discovers:
   - Workspace-specific lists, rules, and signals
   - Alert integrations (all types)
   - Redactions, thresholds, and virtual patches

## Error Handling

The tool includes robust error handling:

- **API Errors**: Logged but don't stop processing other resources
- **Empty/Invalid IDs**: Resources with missing IDs are skipped
- **Access Issues**: Graceful degradation if workspace access fails
- **Service Discovery**: Continues processing if individual services fail

## Testing

Run the comprehensive test suite:

```bash
go test -v
```

Tests cover:
- Resource name sanitization
- Fallback behavior for empty names  
- Special character handling
- Import function signatures
- Workspace-prefixed resource name generation

## Troubleshooting

### Common Issues

1. **"FASTLY_API_KEY environment variable not set"**
   - Ensure you've exported your Fastly API token: `export FASTLY_API_KEY="your-token"`

2. **"No services/workspaces found"**  
   - Verify your API token has the necessary permissions
   - Check that you have resources in your Fastly account

3. **Empty import.tf file**
   - The tool may not have found any importable resources
   - Check the console output for error messages

4. **Import ID format errors**
   - Workspace resources use format: `workspace-id/resource-id`  
   - Account resources use format: `resource-id`
   - Service dynamic snippets use format: `service-id/snippet-id`

### Debug Tips

- Run with verbose output to see detailed discovery process
- Check the console summaries showing discovered resources
- Verify generated import.tf file has expected resource references
- Use `terraform plan` to validate import IDs before applying

## Contributing

1. Fork the repository
2. Create a feature branch  
3. Add tests for new functionality
4. Ensure all tests pass: `go test -v`
5. Submit a pull request

## License

This project is licensed under the terms specified in the repository.
