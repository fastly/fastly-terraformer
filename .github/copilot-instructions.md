# GitHub Copilot Instructions for fastly-terraformer

## Project Overview

fastly-terraformer is a specialized Go CLI tool that generates Terraform import blocks for Fastly Edge Cloud resources. It automatically discovers existing Fastly infrastructure and creates the necessary Terraform import statements to bring those resources under Terraform management.

### Key Features
- Comprehensive resource discovery for Fastly services, NGWAF resources, and more
- Two import modes: "all" (complete infrastructure) and "ngwaf" (NGWAF-only)
- Intelligent resource naming with sanitization for Terraform compatibility
- Workspace-scoped NGWAF support with conflict prevention
- Robust error handling and progress reporting

## Architecture

### Core Components

1. **Main Application** (`main.go`): ~3,772 lines containing:
   - CLI argument parsing and validation
   - Fastly API client initialization
   - Resource discovery orchestration
   - HCL import block generation

2. **Resource Import Functions**: Pattern-based functions for different resource types:
   - `importNGWAFWorkspaces()` - NGWAF workspace discovery
   - `importServices()` - Fastly service discovery
   - `importServiceDynamicSnippets()` - Service-specific resources
   - `importTLSSubscriptions()` - TLS/security resources
   - Various logging endpoint importers

3. **Utility Functions**:
   - `sanitizeForTerraformResourceName()` - Terraform-compatible naming
   - `generateWorkspacePrefixedResourceName()` - Workspace-scoped naming
   - `validateImportMode()` - Input validation

### Dependencies
- `github.com/fastly/go-fastly/v11` - Fastly API client
- `github.com/hashicorp/hcl/v2` - HCL generation
- `github.com/zclconf/go-cty` - Type system for HCL

## Development Guidelines

### Code Style and Patterns

#### Function Naming Convention
- Import functions: `import{ResourceType}()` (e.g., `importNGWAFWorkspaces`)
- Use descriptive, resource-specific function names
- Maintain consistent return patterns: `(count int, error)` or `(resource, count, error)`

#### Resource Naming Patterns
```go
// For regular resources
resourceName := sanitizeForTerraformResourceName(name, "fallback_prefix")

// For workspace-scoped resources (prevents conflicts)
resourceName := generateWorkspacePrefixedResourceName(
    workspaceID, resourceName, resourceID, "base_prefix"
)
```

#### Import Block Generation Pattern
```go
func importResourceType(client *fastly.Client, body *hclwrite.Body) (int, error) {
    resources, err := client.ListResourceType(&fastly.ListInput{})
    if err != nil {
        return 0, fmt.Errorf("error listing resources: %w", err)
    }

    count := 0
    for _, resource := range resources {
        if resource.ID == "" {
            continue // Skip resources with empty IDs
        }

        resourceName := sanitizeForTerraformResourceName(resource.Name, "resource")
        
        importBlock := body.AppendNewBlock("import", nil)
        importBlockBody := importBlock.Body()
        importBlockBody.SetAttributeValue("id", cty.StringVal(resource.ID))
        importBlockBody.SetAttributeValue("to", cty.StringVal(
            fmt.Sprintf("fastly_resource_type.%s", resourceName)
        ))
        
        count++
    }
    
    return count, nil
}
```

### Error Handling Principles

1. **Graceful Degradation**: Continue processing other resources if one fails
2. **Detailed Logging**: Log errors but don't stop the entire process
3. **Empty ID Validation**: Always check for empty/invalid resource IDs
4. **API Error Handling**: Wrap API errors with context

Example:
```go
resources, err := client.ListResources(&input)
if err != nil {
    fmt.Printf("Warning: Error listing resources: %v\n", err)
    return 0, nil // Don't fail the entire process
}

for _, resource := range resources {
    if resource.ID == "" {
        fmt.Printf("Skipping resource with empty ID: %+v\n", resource)
        continue
    }
    // Process resource...
}
```

### Testing Patterns

#### Function Signature Testing
```go
func TestImportFunction(t *testing.T) {
    // Verify function signature exists
    var fn func(*fastly.Client, *hclwrite.Body) (int, error)
    fn = importFunction
    if fn == nil {
        t.Error("importFunction should exist")
    }
}
```

#### Edge Case Testing
```go
func TestWithEmptyInput(t *testing.T) {
    count, err := importFunction(nil, nil)
    if count != 0 {
        t.Error("Expected 0 count with nil input")
    }
    if err != nil {
        t.Errorf("Expected no error with nil input, got %v", err)
    }
}
```

#### Name Sanitization Testing
```go
func TestSanitizeForTerraformResourceName(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        prefix   string
        expected string
    }{
        {"normal_name", "My Resource", "resource", "my_resource"},
        {"empty_name", "", "resource", "resource_unnamed"},
        {"special_chars", "Resource-with@special#chars!", "resource", "resource_with_special_chars"},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := sanitizeForTerraformResourceName(tt.input, tt.prefix)
            if result != tt.expected {
                t.Errorf("Expected %s, got %s", tt.expected, result)
            }
        })
    }
}
```

## API Integration Patterns

### Fastly Client Usage
```go
// Initialize client
client, err := fastly.NewClient(apiToken)
if err != nil {
    log.Fatalf("Error creating Fastly client: %v", err)
}

// List resources with proper input structs
input := &fastly.ListServicesInput{}
services, err := client.ListServices(input)
```

### NGWAF Resource Patterns
```go
// Account-level resources
accountLists, err := client.NGWAFListAccountLists(&lists.ListAccountListsRequest{})

// Workspace-scoped resources
workspaceLists, err := client.NGWAFListWorkspaceLists(&lists.ListWorkspaceListsRequest{
    WorkspaceID: workspace.ID,
})
```

## Resource Naming Conventions

### Terraform Resource Names
- Use lowercase with underscores
- Remove special characters and numbers from the beginning
- Handle empty names with appropriate fallbacks
- Ensure uniqueness for workspace-scoped resources

### Import ID Formats
- **Account resources**: `resource-id`
- **Workspace resources**: `workspace-id/resource-id`
- **Service resources**: `service-id/resource-id`

## Environment and Configuration

### Required Environment Variables
```bash
export FASTLY_API_KEY="your-fastly-api-token"
export FASTLY_TF_DISPLAY_SENSITIVE_FIELDS="true"  # Optional, for Terraform generation
```

### Command Line Usage
```bash
# Import all resources (default)
./fastly-terraformer
./fastly-terraformer -import all

# Import only NGWAF resources
./fastly-terraformer -import ngwaf

# Show help
./fastly-terraformer -help
```

## Build and Test Commands

### Development Workflow
```bash
# Install dependencies
go mod tidy

# Run tests
go test -v

# Build application
go build -o fastly-terraformer .

# Clean generated files
make clean

# Full workflow shortcuts
make rerun      # Clean and import all resources
make rengwaf    # Clean and import NGWAF only
```

## Output Files

### Generated Files
- **`import.tf`** - Contains Terraform import blocks
- **`generated.tf`** - Resource configurations (generated by `terraform plan -generate-config-out`)

### Example Import Block
```hcl
import {
  id = "abc123def456"
  to = fastly_service_vcl.my_service
}

import {
  id = "workspace-123/list-456"
  to = fastly_ngwaf_workspace_list.ws_abc123def456_custom_blocklist_list_456
}
```

## Supported Fastly Resources

### Core Services
- `fastly_service_vcl` / `fastly_service_compute`
- `fastly_service_domain`
- `fastly_service_backend`
- `fastly_service_acl`
- `fastly_service_dictionary`

### NGWAF Resources
- **Account-level**: workspaces, lists, rules, signals
- **Workspace-scoped**: lists, rules, signals, alert integrations
- **Additional**: redactions, thresholds, virtual patches

### Logging Endpoints
- S3, Syslog, Datadog, BigQuery, Splunk, Papertrail

### TLS and Security
- TLS subscriptions, activations, certificates
- TLS configurations and private keys

## Common Patterns for Adding New Resources

### 1. Add Import Function
```go
func importNewResourceType(client *fastly.Client, body *hclwrite.Body) (int, error) {
    // Follow established pattern
    resources, err := client.ListNewResourceType(&fastly.ListNewResourceTypeInput{})
    if err != nil {
        return 0, fmt.Errorf("error listing new resource type: %w", err)
    }
    
    count := 0
    for _, resource := range resources {
        if resource.ID == "" {
            continue
        }
        
        resourceName := sanitizeForTerraformResourceName(resource.Name, "new_resource")
        // Generate import block...
        count++
    }
    
    return count, nil
}
```

### 2. Add to Main Switch Statement
```go
switch *importMode {
case "all":
    // Add to "all" mode
    newResourceCount, err := importNewResourceType(client, rootBody)
    if err != nil {
        fmt.Printf("Error importing new resources: %v\n", err)
    } else {
        importCount += newResourceCount
        fmt.Printf("Imported %d new resources\n", newResourceCount)
    }
}
```

### 3. Add Corresponding Test
```go
func TestImportNewResourceType(t *testing.T) {
    var fn func(*fastly.Client, *hclwrite.Body) (int, error)
    fn = importNewResourceType
    if fn == nil {
        t.Error("importNewResourceType function should exist")
    }
}
```

## Troubleshooting Guidelines

### Common Issues
1. **API Key Issues**: Verify `FASTLY_API_KEY` is set and has proper permissions
2. **Empty Results**: Check API token permissions and resource availability
3. **Import ID Errors**: Ensure correct format for different resource types
4. **Build Issues**: Run `go mod tidy` to fix dependency problems

### Debug Tips
- Check console output for detailed error messages
- Verify generated `import.tf` file contents
- Use `terraform plan` to validate import IDs
- Test with minimal resource sets first

## Contributing Guidelines

### Pull Request Process
1. Fork repository and create feature branch
2. Add comprehensive tests for new functionality
3. Ensure all tests pass: `go test -v`
4. Follow established code patterns and naming conventions
5. Update documentation if adding new resource types
6. Submit pull request with clear description

### Code Review Focus Areas
- Error handling and graceful degradation
- Resource name sanitization and uniqueness
- Test coverage for new functions
- Consistent API integration patterns
- Documentation updates for new features

This project focuses on reliability, comprehensive resource coverage, and seamless integration with Terraform workflows. When contributing, prioritize robust error handling and maintain compatibility with existing Fastly infrastructure patterns.