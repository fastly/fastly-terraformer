package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	// IMPORTANT: Ensure your go.mod file correctly references github.com/fastly/go-fastly/v12
	// If errors persist, try running:
	// go clean -modcache
	// go get -u github.com/fastly/go-fastly/v12/fastly
	// go mod tidy
	"github.com/fastly/go-fastly/v12/fastly"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/lists"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/rules"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/scope"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/signals"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/alerts/datadog"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/alerts/jira"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/alerts/mailinglist"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/alerts/microsoftteams"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/alerts/opsgenie"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/alerts/pagerduty"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/alerts/slack"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/alerts/webhook"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/redactions"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/thresholds"
	"github.com/fastly/go-fastly/v12/fastly/ngwaf/v1/workspaces/virtualpatches"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/zclconf/go-cty/cty"
)

var (
	// Regular expressions for sanitizing names for Terraform.
	nonAlphanumericUnderscore = regexp.MustCompile(`[^a-zA-Z0-9_]`)
	leadingNumeric            = regexp.MustCompile(`^[0-9]`)
	leadingUnderscores        = regexp.MustCompile(`^_+`)
	trailingUnderscores       = regexp.MustCompile(`_+$`)
	multipleUnderscores       = regexp.MustCompile(`__+`)
)

// sanitizeForTerraformResourceName converts a string into a valid Terraform resource name.
// It converts to lowercase, replaces non-alphanumeric characters (except '_') with '_',
// handles leading numbers, and cleans up multiple/leading/trailing underscores.
func sanitizeForTerraformResourceName(name, defaultPrefix string) string {
	if name == "" {
		return defaultPrefix + "_unnamed"
	}

	s := nonAlphanumericUnderscore.ReplaceAllString(name, "_")
	s = strings.ToLower(s)
	s = multipleUnderscores.ReplaceAllString(s, "_")
	s = leadingUnderscores.ReplaceAllString(s, "")
	s = trailingUnderscores.ReplaceAllString(s, "")

	if s == "" {
		return defaultPrefix + "_sanitized_empty" // If name was purely non-alphanumeric like "///"
	}

	if leadingNumeric.MatchString(s) {
		s = "tf_" + s // Prepend "tf_" if it starts with a number
	}
	if s == "_" { // Avoid single underscore names if that was the result
		return defaultPrefix + "_underscore"
	}
	return s
}

// generateWorkspacePrefixedResourceName creates a workspace-prefixed Terraform resource name
// for workspace-scoped NGWAF resources to prevent naming conflicts.
// Format: {sanitized_workspace_id}_{resource_name}_{sanitized_resource_id}
func generateWorkspacePrefixedResourceName(workspaceID, resourceName, resourceID, basePrefix string) string {
	// Sanitize the workspace ID to use as prefix
	sanitizedWorkspaceID := sanitizeForTerraformResourceName(workspaceID, "ws")

	// Sanitize the resource ID to ensure uniqueness
	sanitizedResourceID := sanitizeForTerraformResourceName(resourceID, "id")

	// Generate the base resource name
	var baseResourceName string
	if resourceName == "" {
		// Use a generic name when resource name is empty
		baseResourceName = "resource"
	} else {
		baseResourceName = sanitizeForTerraformResourceName(resourceName, "resource")
	}

	// Combine workspace prefix, resource name, and resource ID to ensure uniqueness
	// Format: {sanitized_workspace_id}_{resource_name}_{sanitized_resource_id}
	return fmt.Sprintf("%s_%s_%s", sanitizedWorkspaceID, baseResourceName, sanitizedResourceID)
}

// validateImportMode validates and normalizes the import mode
func validateImportMode(mode string) string {
	if mode != "all" && mode != "ngwaf" {
		return "all" // default fallback
	}
	return mode
}

// filterServicesByVCLServiceID filters a service list to only the service with the given ID.
// If vclServiceID is empty, the original services slice is returned unmodified.
// An error is returned if the ID is not found or identifies a non-VCL service.
func filterServicesByVCLServiceID(services []*fastly.Service, vclServiceID string) ([]*fastly.Service, error) {
	if vclServiceID == "" {
		return services, nil
	}
	for _, svc := range services {
		if svc.ServiceID != nil && *svc.ServiceID == vclServiceID {
			if svc.Type != nil && *svc.Type != "vcl" {
				return nil, fmt.Errorf("service ID %s is not a VCL service (type: %s)", vclServiceID, *svc.Type)
			}
			return []*fastly.Service{svc}, nil
		}
	}
	return nil, fmt.Errorf("no VCL service found with ID %s", vclServiceID)
}

// importNGWAFWorkspaces handles importing NGWAF workspace resources
func importNGWAFWorkspaces(client *fastly.Client, rootBody *hclwrite.Body) (*workspaces.Workspaces, int, error) {
	fmt.Println("\nFetching NGWAF workspaces...")
	ngwafWorkspaces, err := workspaces.List(context.Background(), client, &workspaces.ListInput{})
	if err != nil {
		log.Printf("Error listing NGWAF workspaces: %v. Skipping NGWAF workspace imports.", err)
		return nil, 0, err
	}

	importCount := 0
	if len(ngwafWorkspaces.Data) == 0 {
		fmt.Println("No NGWAF workspaces found for this account.")
	} else {
		fmt.Printf("Found %d NGWAF workspace(s). Adding to import.tf...\n", len(ngwafWorkspaces.Data))

		for _, workspace := range ngwafWorkspaces.Data {
			if workspace.WorkspaceID == "" {
				log.Printf("Skipping NGWAF workspace with empty ID (Name: %s)\n", workspace.Name)
				continue
			}

			// Sanitize the workspace name for the Terraform resource
			tfWorkspaceResourceName := sanitizeForTerraformResourceName(workspace.Name, "ngwaf_workspace")
			if workspace.Name == "" || tfWorkspaceResourceName == "ngwaf_workspace_unnamed" || tfWorkspaceResourceName == "ngwaf_workspace_sanitized_empty" {
				// If original workspace name was empty or problematic, use sanitized ID for a more stable name
				sanitizedIDForName := sanitizeForTerraformResourceName(workspace.WorkspaceID, "ws")
				tfWorkspaceResourceName = fmt.Sprintf("ngwaf_workspace_%s", sanitizedIDForName)
			}

			// Create the import block for the NGWAF workspace
			workspaceImportBlock := rootBody.AppendNewBlock("import", nil)
			workspaceImportBody := workspaceImportBlock.Body()
			workspaceImportBody.SetAttributeValue("id", cty.StringVal(workspace.WorkspaceID))

			// Set the Terraform resource type and name
			// Note: Using fastly_ngwaf_workspace based on Fastly provider conventions
			// This should match the actual Terraform provider resource name for NGWAF workspaces
			workspaceImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_ngwaf_workspace"},
				hcl.TraverseAttr{Name: tfWorkspaceResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for NGWAF workspace: %s (ID: %s) as fastly_ngwaf_workspace.%s\n", workspace.Name, workspace.WorkspaceID, tfWorkspaceResourceName)
		}
	}

	return ngwafWorkspaces, importCount, nil
}

// importNGWAFAccountLists handles importing NGWAF account list resources
func importNGWAFAccountLists(client *fastly.Client, rootBody *hclwrite.Body) (*lists.Lists, int, error) {
	fmt.Println("\nFetching NGWAF account lists...")
	accountScope := &scope.Scope{
		Type:      scope.ScopeTypeAccount,
		AppliesTo: []string{"*"},
	}

	ngwafLists, err := lists.ListLists(context.Background(), client, &lists.ListInput{Scope: accountScope})
	if err != nil {
		log.Printf("Error listing NGWAF account lists: %v. Skipping NGWAF list imports.", err)
		return nil, 0, err
	}

	importCount := 0
	if len(ngwafLists.Data) == 0 {
		fmt.Println("No NGWAF account lists found for this account.")
	} else {
		fmt.Printf("Found %d NGWAF account list(s). Adding to import.tf...\n", len(ngwafLists.Data))

		for _, list := range ngwafLists.Data {
			if list.ListID == "" {
				log.Printf("Skipping NGWAF account list with empty ID (Name: %s)\n", list.Name)
				continue
			}

			// Sanitize the list name for the Terraform resource
			tfListResourceName := sanitizeForTerraformResourceName(list.Name, "ngwaf_account_list")
			if list.Name == "" || tfListResourceName == "ngwaf_account_list_unnamed" || tfListResourceName == "ngwaf_account_list_sanitized_empty" {
				// If original list name was empty or problematic, use sanitized ID for a more stable name
				sanitizedIDForName := sanitizeForTerraformResourceName(list.ListID, "list")
				tfListResourceName = fmt.Sprintf("ngwaf_account_list_%s", sanitizedIDForName)
			}

			// Create the import block for the NGWAF account list
			listImportBlock := rootBody.AppendNewBlock("import", nil)
			listImportBody := listImportBlock.Body()
			listImportBody.SetAttributeValue("id", cty.StringVal(list.ListID))

			// Set the Terraform resource type and name
			listImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_ngwaf_account_list"},
				hcl.TraverseAttr{Name: tfListResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for NGWAF account list: %s (ID: %s) as fastly_ngwaf_account_list.%s\n", list.Name, list.ListID, tfListResourceName)
		}
	}

	return ngwafLists, importCount, nil
}

// importNGWAFAccountRules handles importing NGWAF account rule resources
func importNGWAFAccountRules(client *fastly.Client, rootBody *hclwrite.Body) (*rules.Rules, int, error) {
	fmt.Println("\nFetching NGWAF account rules...")
	accountScope := &scope.Scope{
		Type:      scope.ScopeTypeAccount,
		AppliesTo: []string{"*"},
	}

	ngwafRules, err := rules.List(context.Background(), client, &rules.ListInput{Scope: accountScope})
	if err != nil {
		log.Printf("Error listing NGWAF account rules: %v. Skipping NGWAF rule imports.", err)
		return nil, 0, err
	}

	importCount := 0
	if len(ngwafRules.Data) == 0 {
		fmt.Println("No NGWAF account rules found for this account.")
	} else {
		fmt.Printf("Found %d NGWAF account rule(s). Adding to import.tf...\n", len(ngwafRules.Data))

		for _, rule := range ngwafRules.Data {
			if rule.RuleID == "" {
				log.Printf("Skipping NGWAF account rule with empty ID (Description: %s)\n", rule.Description)
				continue
			}

			// Sanitize the rule description for the Terraform resource name
			tfRuleResourceName := sanitizeForTerraformResourceName(rule.Description, "ngwaf_account_rule")
			if rule.Description == "" || tfRuleResourceName == "ngwaf_account_rule_unnamed" || tfRuleResourceName == "ngwaf_account_rule_sanitized_empty" {
				// If original rule description was empty or problematic, use sanitized ID for a more stable name
				sanitizedIDForName := sanitizeForTerraformResourceName(rule.RuleID, "rule")
				tfRuleResourceName = fmt.Sprintf("ngwaf_account_rule_%s", sanitizedIDForName)
			}

			// Create the import block for the NGWAF account rule
			ruleImportBlock := rootBody.AppendNewBlock("import", nil)
			ruleImportBody := ruleImportBlock.Body()
			ruleImportBody.SetAttributeValue("id", cty.StringVal(rule.RuleID))

			// Set the Terraform resource type and name
			ruleImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_ngwaf_account_rule"},
				hcl.TraverseAttr{Name: tfRuleResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for NGWAF account rule: %s (ID: %s) as fastly_ngwaf_account_rule.%s\n", rule.Description, rule.RuleID, tfRuleResourceName)
		}
	}

	return ngwafRules, importCount, nil
}

// importNGWAFAccountSignals handles importing NGWAF account signal resources
func importNGWAFAccountSignals(client *fastly.Client, rootBody *hclwrite.Body) (*signals.Signals, int, error) {
	fmt.Println("\nFetching NGWAF account signals...")
	accountScope := &scope.Scope{
		Type:      scope.ScopeTypeAccount,
		AppliesTo: []string{"*"},
	}

	ngwafSignals, err := signals.List(context.Background(), client, &signals.ListInput{Scope: accountScope})
	if err != nil {
		log.Printf("Error listing NGWAF account signals: %v. Skipping NGWAF signal imports.", err)
		return nil, 0, err
	}

	importCount := 0
	if len(ngwafSignals.Data) == 0 {
		fmt.Println("No NGWAF account signals found for this account.")
	} else {
		fmt.Printf("Found %d NGWAF account signal(s). Adding to import.tf...\n", len(ngwafSignals.Data))

		for _, signal := range ngwafSignals.Data {
			if signal.SignalID == "" {
				log.Printf("Skipping NGWAF account signal with empty ID (Name: %s)\n", signal.Name)
				continue
			}

			// Sanitize the signal name for the Terraform resource
			tfSignalResourceName := sanitizeForTerraformResourceName(signal.Name, "ngwaf_account_signal")
			if signal.Name == "" || tfSignalResourceName == "ngwaf_account_signal_unnamed" || tfSignalResourceName == "ngwaf_account_signal_sanitized_empty" {
				// If original signal name was empty or problematic, use sanitized ID for a more stable name
				sanitizedIDForName := sanitizeForTerraformResourceName(signal.SignalID, "signal")
				tfSignalResourceName = fmt.Sprintf("ngwaf_account_signal_%s", sanitizedIDForName)
			}

			// Create the import block for the NGWAF account signal
			signalImportBlock := rootBody.AppendNewBlock("import", nil)
			signalImportBody := signalImportBlock.Body()
			signalImportBody.SetAttributeValue("id", cty.StringVal(signal.SignalID))

			// Set the Terraform resource type and name
			signalImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_ngwaf_account_signal"},
				hcl.TraverseAttr{Name: tfSignalResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for NGWAF account signal: %s (ID: %s) as fastly_ngwaf_account_signal.%s\n", signal.Name, signal.SignalID, tfSignalResourceName)
		}
	}

	return ngwafSignals, importCount, nil
}

// importConfigStores handles importing Fastly Config Store resources
func importConfigStores(client *fastly.Client, rootBody *hclwrite.Body) (int, error) {
	fmt.Println("\nFetching Fastly Config Stores...")

	configStores, err := client.ListConfigStores(context.Background(), &fastly.ListConfigStoresInput{})
	if err != nil {
		log.Printf("Error listing Config Stores: %v. Skipping Config Store imports.", err)
		return 0, err
	}

	importCount := 0
	if len(configStores) == 0 {
		fmt.Println("No Config Stores found for this account.")
	} else {
		fmt.Printf("Found %d Config Store(s). Adding to import.tf...\n", len(configStores))

		for _, store := range configStores {
			if store.StoreID == "" {
				log.Printf("Skipping Config Store with empty ID (Name: %s)\n", store.Name)
				continue
			}

			// Sanitize the store name for the Terraform resource
			tfStoreResourceName := sanitizeForTerraformResourceName(store.Name, "configstore")
			if store.Name == "" || tfStoreResourceName == "configstore_unnamed" || tfStoreResourceName == "configstore_sanitized_empty" {
				// If original store name was empty or problematic, use sanitized ID for a more stable name
				sanitizedIDForName := sanitizeForTerraformResourceName(store.StoreID, "store")
				tfStoreResourceName = fmt.Sprintf("configstore_%s", sanitizedIDForName)
			}

			// Create the import block for the Config Store
			storeImportBlock := rootBody.AppendNewBlock("import", nil)
			storeImportBody := storeImportBlock.Body()
			storeImportBody.SetAttributeValue("id", cty.StringVal(store.StoreID))

			// Set the Terraform resource type and name
			storeImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_configstore"},
				hcl.TraverseAttr{Name: tfStoreResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for Config Store: %s (ID: %s) as fastly_configstore.%s\n", store.Name, store.StoreID, tfStoreResourceName)
		}
	}

	return importCount, nil
}

// importKVStores handles importing Fastly KV Store resources
func importKVStores(client *fastly.Client, rootBody *hclwrite.Body) (int, error) {
	fmt.Println("\nFetching Fastly KV Stores...")

	kvStoresResponse, err := client.ListKVStores(context.Background(), &fastly.ListKVStoresInput{})
	if err != nil {
		log.Printf("Error listing KV Stores: %v. Skipping KV Store imports.", err)
		return 0, err
	}

	importCount := 0
	if len(kvStoresResponse.Data) == 0 {
		fmt.Println("No KV Stores found for this account.")
	} else {
		fmt.Printf("Found %d KV Store(s). Adding to import.tf...\n", len(kvStoresResponse.Data))

		for _, store := range kvStoresResponse.Data {
			if store.StoreID == "" {
				log.Printf("Skipping KV Store with empty ID (Name: %s)\n", store.Name)
				continue
			}

			// Sanitize the store name for the Terraform resource
			tfStoreResourceName := sanitizeForTerraformResourceName(store.Name, "kvstore")
			if store.Name == "" || tfStoreResourceName == "kvstore_unnamed" || tfStoreResourceName == "kvstore_sanitized_empty" {
				// If original store name was empty or problematic, use sanitized ID for a more stable name
				sanitizedIDForName := sanitizeForTerraformResourceName(store.StoreID, "store")
				tfStoreResourceName = fmt.Sprintf("kvstore_%s", sanitizedIDForName)
			}

			// Create the import block for the KV Store
			storeImportBlock := rootBody.AppendNewBlock("import", nil)
			storeImportBody := storeImportBlock.Body()
			storeImportBody.SetAttributeValue("id", cty.StringVal(store.StoreID))

			// Set the Terraform resource type and name
			storeImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_kvstore"},
				hcl.TraverseAttr{Name: tfStoreResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for KV Store: %s (ID: %s) as fastly_kvstore.%s\n", store.Name, store.StoreID, tfStoreResourceName)
		}
	}

	return importCount, nil
}

// importSecretStores handles importing Fastly Secret Store resources
func importSecretStores(client *fastly.Client, rootBody *hclwrite.Body) (int, error) {
	fmt.Println("\nFetching Fastly Secret Stores...")

	secretStoresResponse, err := client.ListSecretStores(context.Background(), &fastly.ListSecretStoresInput{})
	if err != nil {
		log.Printf("Error listing Secret Stores: %v. Skipping Secret Store imports.", err)
		return 0, err
	}

	importCount := 0
	if len(secretStoresResponse.Data) == 0 {
		fmt.Println("No Secret Stores found for this account.")
	} else {
		fmt.Printf("Found %d Secret Store(s). Adding to import.tf...\n", len(secretStoresResponse.Data))

		for _, store := range secretStoresResponse.Data {
			if store.StoreID == "" {
				log.Printf("Skipping Secret Store with empty ID (Name: %s)\n", store.Name)
				continue
			}

			// Sanitize the store name for the Terraform resource
			tfStoreResourceName := sanitizeForTerraformResourceName(store.Name, "secretstore")
			if store.Name == "" || tfStoreResourceName == "secretstore_unnamed" || tfStoreResourceName == "secretstore_sanitized_empty" {
				// If original store name was empty or problematic, use sanitized ID for a more stable name
				sanitizedIDForName := sanitizeForTerraformResourceName(store.StoreID, "store")
				tfStoreResourceName = fmt.Sprintf("secretstore_%s", sanitizedIDForName)
			}

			// Create the import block for the Secret Store
			storeImportBlock := rootBody.AppendNewBlock("import", nil)
			storeImportBody := storeImportBlock.Body()
			storeImportBody.SetAttributeValue("id", cty.StringVal(store.StoreID))

			// Set the Terraform resource type and name
			storeImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_secretstore"},
				hcl.TraverseAttr{Name: tfStoreResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for Secret Store: %s (ID: %s) as fastly_secretstore.%s\n", store.Name, store.StoreID, tfStoreResourceName)
		}
	}

	return importCount, nil
}

// importServiceDomains handles importing Fastly service domain resources for all services
func importServiceDomains(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for domain imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service domains...")

	for _, service := range services {
		if service.ServiceID == nil || *service.ServiceID == "" {
			continue
		}

		serviceID := *service.ServiceID
		serviceName := ""
		if service.Name != nil {
			serviceName = *service.Name
		}

		fmt.Printf("  Fetching domains for service: %s (ID: %s)\n", serviceName, serviceID)

		// Get service details to find active version
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceID})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping domains.", serviceID, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion && serviceDetails.Versions != nil && len(serviceDetails.Versions) > 0 {
			for _, v := range serviceDetails.Versions {
				if v.Number != nil && v.Active != nil && *v.Active {
					activeVersionNumber = *v.Number
					foundActiveVersion = true
					break
				}
			}
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping domains.", serviceID)
			continue
		}

		domains, err := client.ListDomains(context.Background(), &fastly.ListDomainsInput{
			ServiceID:      serviceID,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("  Error listing domains for service ID %s, version %d: %v", serviceID, activeVersionNumber, err)
			continue
		}

		if len(domains) == 0 {
			fmt.Printf("    No domains found for service %s\n", serviceID)
			continue
		}

		fmt.Printf("    Found %d domain(s) for service %s\n", len(domains), serviceID)

		for _, domain := range domains {
			if domain.Name == nil || *domain.Name == "" {
				log.Printf("Skipping domain with empty name for service ID %s\n", serviceID)
				continue
			}

			// Import ID format for service domain is "service_id/domain_name"
			importID := fmt.Sprintf("%s/%s", serviceID, *domain.Name)

			// Generate resource name using service and domain information
			// Handle wildcard domains to avoid duplicate resource names when domains like
			// "*.livewaflove.com" and "livewaflove.com" would sanitize to the same value
			sanitizedServiceID := sanitizeForTerraformResourceName(serviceID, "svc")

			// Check if this is a wildcard domain and create appropriate identifier
			domainIdentifier := *domain.Name
			isWildcard := strings.HasPrefix(*domain.Name, "*.")
			if isWildcard {
				// For wildcard domains, prefix with "wildcard_" to ensure uniqueness
				// Remove the "*." and replace with "wildcard_"
				domainWithoutWildcard := strings.TrimPrefix(*domain.Name, "*.")
				domainIdentifier = "wildcard_" + domainWithoutWildcard
			}

			// Sanitize the domain identifier
			sanitizedDomainIdentifier := sanitizeForTerraformResourceName(domainIdentifier, "domain")

			// Create the final resource name
			tfDomainResourceName := fmt.Sprintf("service_%s_domain_%s", sanitizedServiceID, sanitizedDomainIdentifier)

			domainImportBlock := rootBody.AppendNewBlock("import", nil)
			domainImportBody := domainImportBlock.Body()
			domainImportBody.SetAttributeValue("id", cty.StringVal(importID))

			domainImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_service_domain"},
				hcl.TraverseAttr{Name: tfDomainResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("    Added import for service domain: %s (Import ID: %s) as fastly_service_domain.%s\n", *domain.Name, importID, tfDomainResourceName)
		}
	}

	return importCount, nil
}

// importServiceACLs handles importing Fastly service ACL resources for all services
func importServiceACLs(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for ACL imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service ACLs...")

	for _, service := range services {
		if service.ServiceID == nil || *service.ServiceID == "" {
			continue
		}

		serviceID := *service.ServiceID
		serviceName := ""
		if service.Name != nil {
			serviceName = *service.Name
		}

		// Only process VCL services as ACLs are VCL-specific
		serviceType := ""
		if service.Type != nil {
			serviceType = *service.Type
		}
		if serviceType != "vcl" {
			continue
		}

		fmt.Printf("  Fetching ACLs for VCL service: %s (ID: %s)\n", serviceName, serviceID)

		// Get service details to find active version
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceID})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping ACLs.", serviceID, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion && serviceDetails.Versions != nil && len(serviceDetails.Versions) > 0 {
			for _, v := range serviceDetails.Versions {
				if v.Number != nil && v.Active != nil && *v.Active {
					activeVersionNumber = *v.Number
					foundActiveVersion = true
					break
				}
			}
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping ACLs.", serviceID)
			continue
		}

		acls, err := client.ListACLs(context.Background(), &fastly.ListACLsInput{
			ServiceID:      serviceID,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("  Error listing ACLs for service ID %s, version %d: %v", serviceID, activeVersionNumber, err)
			continue
		}

		if len(acls) == 0 {
			fmt.Printf("    No ACLs found for service %s\n", serviceID)
			continue
		}

		fmt.Printf("    Found %d ACL(s) for service %s\n", len(acls), serviceID)

		for _, acl := range acls {
			if acl.ACLID == nil || *acl.ACLID == "" {
				log.Printf("Skipping ACL with empty ID for service ID %s\n", serviceID)
				continue
			}

			// Import ID format for service ACL is "service_id/acl_id"
			importID := fmt.Sprintf("%s/%s", serviceID, *acl.ACLID)

			// Generate resource name using service and ACL information
			sanitizedServiceID := sanitizeForTerraformResourceName(serviceID, "svc")
			aclName := ""
			if acl.Name != nil {
				aclName = *acl.Name
			}
			sanitizedACLName := sanitizeForTerraformResourceName(aclName, "acl")
			sanitizedACLID := sanitizeForTerraformResourceName(*acl.ACLID, "id")
			tfACLResourceName := fmt.Sprintf("service_%s_acl_%s_%s", sanitizedServiceID, sanitizedACLName, sanitizedACLID)

			aclImportBlock := rootBody.AppendNewBlock("import", nil)
			aclImportBody := aclImportBlock.Body()
			aclImportBody.SetAttributeValue("id", cty.StringVal(importID))

			aclImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_service_acl"},
				hcl.TraverseAttr{Name: tfACLResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("    Added import for service ACL: %s (Import ID: %s) as fastly_service_acl.%s\n", aclName, importID, tfACLResourceName)
		}
	}

	return importCount, nil
}

// importServiceDictionaries handles importing Fastly service dictionary resources for all services
func importServiceDictionaries(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for dictionary imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service dictionaries...")

	for _, service := range services {
		if service.ServiceID == nil || *service.ServiceID == "" {
			continue
		}

		serviceID := *service.ServiceID
		serviceName := ""
		if service.Name != nil {
			serviceName = *service.Name
		}

		// Only process VCL services as dictionaries are VCL-specific
		serviceType := ""
		if service.Type != nil {
			serviceType = *service.Type
		}
		if serviceType != "vcl" {
			continue
		}

		fmt.Printf("  Fetching dictionaries for VCL service: %s (ID: %s)\n", serviceName, serviceID)

		// Get service details to find active version
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceID})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping dictionaries.", serviceID, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion && serviceDetails.Versions != nil && len(serviceDetails.Versions) > 0 {
			for _, v := range serviceDetails.Versions {
				if v.Number != nil && v.Active != nil && *v.Active {
					activeVersionNumber = *v.Number
					foundActiveVersion = true
					break
				}
			}
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping dictionaries.", serviceID)
			continue
		}

		dictionaries, err := client.ListDictionaries(context.Background(), &fastly.ListDictionariesInput{
			ServiceID:      serviceID,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("  Error listing dictionaries for service ID %s, version %d: %v", serviceID, activeVersionNumber, err)
			continue
		}

		if len(dictionaries) == 0 {
			fmt.Printf("    No dictionaries found for service %s\n", serviceID)
			continue
		}

		fmt.Printf("    Found %d dictionary(ies) for service %s\n", len(dictionaries), serviceID)

		for _, dictionary := range dictionaries {
			if dictionary.DictionaryID == nil || *dictionary.DictionaryID == "" {
				log.Printf("Skipping dictionary with empty ID for service ID %s\n", serviceID)
				continue
			}

			// Import ID format for service dictionary is "service_id/dictionary_id"
			importID := fmt.Sprintf("%s/%s", serviceID, *dictionary.DictionaryID)

			// Generate resource name using service and dictionary information
			sanitizedServiceID := sanitizeForTerraformResourceName(serviceID, "svc")
			dictName := ""
			if dictionary.Name != nil {
				dictName = *dictionary.Name
			}
			sanitizedDictName := sanitizeForTerraformResourceName(dictName, "dict")
			sanitizedDictID := sanitizeForTerraformResourceName(*dictionary.DictionaryID, "id")
			tfDictResourceName := fmt.Sprintf("service_%s_dictionary_%s_%s", sanitizedServiceID, sanitizedDictName, sanitizedDictID)

			dictImportBlock := rootBody.AppendNewBlock("import", nil)
			dictImportBody := dictImportBlock.Body()
			dictImportBody.SetAttributeValue("id", cty.StringVal(importID))

			dictImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_service_dictionary"},
				hcl.TraverseAttr{Name: tfDictResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("    Added import for service dictionary: %s (Import ID: %s) as fastly_service_dictionary.%s\n", dictName, importID, tfDictResourceName)
		}
	}

	return importCount, nil
}

// importServiceBackends handles importing Fastly service backend resources for all services
func importServiceBackends(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for backend imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service backends...")

	for _, service := range services {
		if service.ServiceID == nil || *service.ServiceID == "" {
			continue
		}

		serviceID := *service.ServiceID
		serviceName := ""
		if service.Name != nil {
			serviceName = *service.Name
		}

		fmt.Printf("  Fetching backends for service: %s (ID: %s)\n", serviceName, serviceID)

		// Get service details to find active version
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceID})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping backends.", serviceID, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion && serviceDetails.Versions != nil && len(serviceDetails.Versions) > 0 {
			for _, v := range serviceDetails.Versions {
				if v.Number != nil && v.Active != nil && *v.Active {
					activeVersionNumber = *v.Number
					foundActiveVersion = true
					break
				}
			}
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping backends.", serviceID)
			continue
		}

		backends, err := client.ListBackends(context.Background(), &fastly.ListBackendsInput{
			ServiceID:      serviceID,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("  Error listing backends for service ID %s, version %d: %v", serviceID, activeVersionNumber, err)
			continue
		}

		if len(backends) == 0 {
			fmt.Printf("    No backends found for service %s\n", serviceID)
			continue
		}

		fmt.Printf("    Found %d backend(s) for service %s\n", len(backends), serviceID)

		for _, backend := range backends {
			if backend.Name == nil || *backend.Name == "" {
				log.Printf("Skipping backend with empty name for service ID %s\n", serviceID)
				continue
			}

			// Import ID format for service backend is "service_id/backend_name"
			importID := fmt.Sprintf("%s/%s", serviceID, *backend.Name)

			// Generate resource name using service and backend information
			sanitizedServiceID := sanitizeForTerraformResourceName(serviceID, "svc")
			sanitizedBackendName := sanitizeForTerraformResourceName(*backend.Name, "backend")
			tfBackendResourceName := fmt.Sprintf("service_%s_backend_%s", sanitizedServiceID, sanitizedBackendName)

			backendImportBlock := rootBody.AppendNewBlock("import", nil)
			backendImportBody := backendImportBlock.Body()
			backendImportBody.SetAttributeValue("id", cty.StringVal(importID))

			backendImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_service_backend"},
				hcl.TraverseAttr{Name: tfBackendResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("    Added import for service backend: %s (Import ID: %s) as fastly_service_backend.%s\n", *backend.Name, importID, tfBackendResourceName)
		}
	}

	return importCount, nil
}

// importTLSSubscriptions handles importing Fastly TLS subscription resources
func importTLSSubscriptions(client *fastly.Client, rootBody *hclwrite.Body) (int, error) {
	fmt.Println("\nFetching Fastly TLS subscriptions...")

	tlsSubscriptions, err := client.ListTLSSubscriptions(context.Background(), &fastly.ListTLSSubscriptionsInput{})
	if err != nil {
		log.Printf("Error listing TLS subscriptions: %v. Skipping TLS subscription imports.", err)
		return 0, err
	}

	importCount := 0
	if len(tlsSubscriptions) == 0 {
		fmt.Println("No TLS subscriptions found for this account.")
	} else {
		fmt.Printf("Found %d TLS subscription(s). Adding to import.tf...\n", len(tlsSubscriptions))

		for _, subscription := range tlsSubscriptions {
			if subscription.ID == "" {
				log.Printf("Skipping TLS subscription with empty ID\n")
				continue
			}

			// Sanitize the subscription ID for the Terraform resource name
			tfSubscriptionResourceName := sanitizeForTerraformResourceName(subscription.ID, "tls_subscription")

			// Create the import block for the TLS subscription
			subscriptionImportBlock := rootBody.AppendNewBlock("import", nil)
			subscriptionImportBody := subscriptionImportBlock.Body()
			subscriptionImportBody.SetAttributeValue("id", cty.StringVal(subscription.ID))

			// Set the Terraform resource type and name
			subscriptionImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_tls_subscription"},
				hcl.TraverseAttr{Name: tfSubscriptionResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for TLS subscription: %s as fastly_tls_subscription.%s\n", subscription.ID, tfSubscriptionResourceName)
		}
	}

	return importCount, nil
}

// importTLSActivations handles importing Fastly TLS activation resources
func importTLSActivations(client *fastly.Client, rootBody *hclwrite.Body) (int, error) {
	fmt.Println("\nFetching Fastly TLS activations...")

	tlsActivations, err := client.ListTLSActivations(context.Background(), &fastly.ListTLSActivationsInput{})
	if err != nil {
		log.Printf("Error listing TLS activations: %v. Skipping TLS activation imports.", err)
		return 0, err
	}

	importCount := 0
	if len(tlsActivations) == 0 {
		fmt.Println("No TLS activations found for this account.")
	} else {
		fmt.Printf("Found %d TLS activation(s). Adding to import.tf...\n", len(tlsActivations))

		for _, activation := range tlsActivations {
			if activation.ID == "" {
				log.Printf("Skipping TLS activation with empty ID\n")
				continue
			}

			// Sanitize the activation ID for the Terraform resource name
			tfActivationResourceName := sanitizeForTerraformResourceName(activation.ID, "tls_activation")

			// Create the import block for the TLS activation
			activationImportBlock := rootBody.AppendNewBlock("import", nil)
			activationImportBody := activationImportBlock.Body()
			activationImportBody.SetAttributeValue("id", cty.StringVal(activation.ID))

			// Set the Terraform resource type and name
			activationImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_tls_activation"},
				hcl.TraverseAttr{Name: tfActivationResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for TLS activation: %s as fastly_tls_activation.%s\n", activation.ID, tfActivationResourceName)
		}
	}

	return importCount, nil
}

// importTLSCertificates handles importing Fastly TLS certificate resources
func importTLSCertificates(client *fastly.Client, rootBody *hclwrite.Body) (int, error) {
	fmt.Println("\nFetching Fastly TLS certificates...")

	tlsCertificates, err := client.ListCustomTLSCertificates(context.Background(), &fastly.ListCustomTLSCertificatesInput{})
	if err != nil {
		log.Printf("Error listing TLS certificates: %v. Skipping TLS certificate imports.", err)
		return 0, err
	}

	importCount := 0
	if len(tlsCertificates) == 0 {
		fmt.Println("No TLS certificates found for this account.")
	} else {
		fmt.Printf("Found %d TLS certificate(s). Adding to import.tf...\n", len(tlsCertificates))

		for _, certificate := range tlsCertificates {
			if certificate.ID == "" {
				log.Printf("Skipping TLS certificate with empty ID\n")
				continue
			}

			// Sanitize the certificate ID for the Terraform resource name
			tfCertificateResourceName := sanitizeForTerraformResourceName(certificate.ID, "tls_certificate")

			// Create the import block for the TLS certificate
			certificateImportBlock := rootBody.AppendNewBlock("import", nil)
			certificateImportBody := certificateImportBlock.Body()
			certificateImportBody.SetAttributeValue("id", cty.StringVal(certificate.ID))

			// Set the Terraform resource type and name
			certificateImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_tls_certificate"},
				hcl.TraverseAttr{Name: tfCertificateResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for TLS certificate: %s as fastly_tls_certificate.%s\n", certificate.ID, tfCertificateResourceName)
		}
	}

	return importCount, nil
}

// importTLSConfigurations handles importing Fastly TLS configuration resources
func importTLSConfigurations(client *fastly.Client, rootBody *hclwrite.Body) (int, error) {
	fmt.Println("\nFetching Fastly TLS configurations...")

	tlsConfigurations, err := client.ListCustomTLSConfigurations(context.Background(), &fastly.ListCustomTLSConfigurationsInput{})
	if err != nil {
		log.Printf("Error listing TLS configurations: %v. Skipping TLS configuration imports.", err)
		return 0, err
	}

	importCount := 0
	if len(tlsConfigurations) == 0 {
		fmt.Println("No TLS configurations found for this account.")
	} else {
		fmt.Printf("Found %d TLS configuration(s). Adding to import.tf...\n", len(tlsConfigurations))

		for _, configuration := range tlsConfigurations {
			if configuration.ID == "" {
				log.Printf("Skipping TLS configuration with empty ID\n")
				continue
			}

			// Sanitize the configuration ID for the Terraform resource name
			tfConfigurationResourceName := sanitizeForTerraformResourceName(configuration.ID, "tls_configuration")

			// Create the import block for the TLS configuration
			configurationImportBlock := rootBody.AppendNewBlock("import", nil)
			configurationImportBody := configurationImportBlock.Body()
			configurationImportBody.SetAttributeValue("id", cty.StringVal(configuration.ID))

			// Set the Terraform resource type and name
			configurationImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_tls_configuration"},
				hcl.TraverseAttr{Name: tfConfigurationResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for TLS configuration: %s as fastly_tls_configuration.%s\n", configuration.ID, tfConfigurationResourceName)
		}
	}

	return importCount, nil
}

// importTLSPrivateKeys handles importing Fastly TLS private key resources
func importTLSPrivateKeys(client *fastly.Client, rootBody *hclwrite.Body) (int, error) {
	fmt.Println("\nFetching Fastly TLS private keys...")

	tlsPrivateKeys, err := client.ListPrivateKeys(context.Background(), &fastly.ListPrivateKeysInput{})
	if err != nil {
		log.Printf("Error listing TLS private keys: %v. Skipping TLS private key imports.", err)
		return 0, err
	}

	importCount := 0
	if len(tlsPrivateKeys) == 0 {
		fmt.Println("No TLS private keys found for this account.")
	} else {
		fmt.Printf("Found %d TLS private key(s). Adding to import.tf...\n", len(tlsPrivateKeys))

		for _, privateKey := range tlsPrivateKeys {
			if privateKey.ID == "" {
				log.Printf("Skipping TLS private key with empty ID\n")
				continue
			}

			// Sanitize the private key ID for the Terraform resource name
			tfPrivateKeyResourceName := sanitizeForTerraformResourceName(privateKey.ID, "tls_private_key")

			// Create the import block for the TLS private key
			privateKeyImportBlock := rootBody.AppendNewBlock("import", nil)
			privateKeyImportBody := privateKeyImportBlock.Body()
			privateKeyImportBody.SetAttributeValue("id", cty.StringVal(privateKey.ID))

			// Set the Terraform resource type and name
			privateKeyImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_tls_private_key"},
				hcl.TraverseAttr{Name: tfPrivateKeyResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for TLS private key: %s as fastly_tls_private_key.%s\n", privateKey.ID, tfPrivateKeyResourceName)
		}
	}

	return importCount, nil
}

// importServiceHealthChecks handles importing Fastly service health check resources for all services
func importServiceHealthChecks(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for health check imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service health checks...")

	for _, service := range services {
		if service.ServiceID == nil || *service.ServiceID == "" {
			continue
		}

		serviceID := *service.ServiceID
		serviceName := ""
		if service.Name != nil {
			serviceName = *service.Name
		}

		fmt.Printf("  Fetching health checks for service: %s (ID: %s)\n", serviceName, serviceID)

		// Get service details to find active version
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceID})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping health checks.", serviceID, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion && serviceDetails.Versions != nil && len(serviceDetails.Versions) > 0 {
			for _, v := range serviceDetails.Versions {
				if v.Number != nil && v.Active != nil && *v.Active {
					activeVersionNumber = *v.Number
					foundActiveVersion = true
					break
				}
			}
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping health checks.", serviceID)
			continue
		}

		healthChecks, err := client.ListHealthChecks(context.Background(), &fastly.ListHealthChecksInput{
			ServiceID:      serviceID,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("  Error listing health checks for service ID %s, version %d: %v", serviceID, activeVersionNumber, err)
			continue
		}

		if len(healthChecks) == 0 {
			fmt.Printf("    No health checks found for service %s\n", serviceID)
			continue
		}

		fmt.Printf("    Found %d health check(s) for service %s\n", len(healthChecks), serviceID)

		for _, healthCheck := range healthChecks {
			if healthCheck.Name == nil || *healthCheck.Name == "" {
				log.Printf("Skipping health check with empty name for service ID %s\n", serviceID)
				continue
			}

			// Import ID format for service health check is "service_id/health_check_name"
			importID := fmt.Sprintf("%s/%s", serviceID, *healthCheck.Name)

			// Generate resource name using service and health check information
			sanitizedServiceID := sanitizeForTerraformResourceName(serviceID, "svc")
			sanitizedHealthCheckName := sanitizeForTerraformResourceName(*healthCheck.Name, "healthcheck")
			tfHealthCheckResourceName := fmt.Sprintf("service_%s_health_check_%s", sanitizedServiceID, sanitizedHealthCheckName)

			healthCheckImportBlock := rootBody.AppendNewBlock("import", nil)
			healthCheckImportBody := healthCheckImportBlock.Body()
			healthCheckImportBody.SetAttributeValue("id", cty.StringVal(importID))

			healthCheckImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_service_health_check"},
				hcl.TraverseAttr{Name: tfHealthCheckResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("    Added import for service health check: %s (Import ID: %s) as fastly_service_health_check.%s\n", *healthCheck.Name, importID, tfHealthCheckResourceName)
		}
	}

	return importCount, nil
}

// importServiceDirectors handles importing Fastly service director resources for all services
func importServiceDirectors(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for director imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service directors...")

	for _, service := range services {
		if service.ServiceID == nil || *service.ServiceID == "" {
			continue
		}

		serviceID := *service.ServiceID
		serviceName := ""
		if service.Name != nil {
			serviceName = *service.Name
		}

		// Only process VCL services as directors are VCL-specific
		serviceType := ""
		if service.Type != nil {
			serviceType = *service.Type
		}
		if serviceType != "vcl" {
			continue
		}

		fmt.Printf("  Fetching directors for VCL service: %s (ID: %s)\n", serviceName, serviceID)

		// Get service details to find active version
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceID})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping directors.", serviceID, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion && serviceDetails.Versions != nil && len(serviceDetails.Versions) > 0 {
			for _, v := range serviceDetails.Versions {
				if v.Number != nil && v.Active != nil && *v.Active {
					activeVersionNumber = *v.Number
					foundActiveVersion = true
					break
				}
			}
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping directors.", serviceID)
			continue
		}

		directors, err := client.ListDirectors(context.Background(), &fastly.ListDirectorsInput{
			ServiceID:      serviceID,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("  Error listing directors for service ID %s, version %d: %v", serviceID, activeVersionNumber, err)
			continue
		}

		if len(directors) == 0 {
			fmt.Printf("    No directors found for service %s\n", serviceID)
			continue
		}

		fmt.Printf("    Found %d director(s) for service %s\n", len(directors), serviceID)

		for _, director := range directors {
			if director.Name == nil || *director.Name == "" {
				log.Printf("Skipping director with empty name for service ID %s\n", serviceID)
				continue
			}

			// Import ID format for service director is "service_id/director_name"
			importID := fmt.Sprintf("%s/%s", serviceID, *director.Name)

			// Generate resource name using service and director information
			sanitizedServiceID := sanitizeForTerraformResourceName(serviceID, "svc")
			sanitizedDirectorName := sanitizeForTerraformResourceName(*director.Name, "director")
			tfDirectorResourceName := fmt.Sprintf("service_%s_director_%s", sanitizedServiceID, sanitizedDirectorName)

			directorImportBlock := rootBody.AppendNewBlock("import", nil)
			directorImportBody := directorImportBlock.Body()
			directorImportBody.SetAttributeValue("id", cty.StringVal(importID))

			directorImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_service_director"},
				hcl.TraverseAttr{Name: tfDirectorResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("    Added import for service director: %s (Import ID: %s) as fastly_service_director.%s\n", *director.Name, importID, tfDirectorResourceName)
		}
	}

	return importCount, nil
}

// importServiceRequestSettings handles importing Fastly service request setting resources
func importServiceRequestSettings(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for request setting imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service request settings...")

	for _, service := range services {
		var serviceIDValue string
		if service.ServiceID != nil {
			serviceIDValue = *service.ServiceID
		}

		var serviceName string
		if service.Name != nil {
			serviceName = *service.Name
		}

		if serviceIDValue == "" {
			log.Printf("Skipping service with empty ID (Name: %s) for request setting imports\n", serviceName)
			continue
		}

		// Get the active version for this service
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping request settings.", serviceIDValue, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping request settings.", serviceIDValue)
			continue
		}

		fmt.Printf("  Fetching request settings for service: %s (ID: %s, version: %d)\n", serviceName, serviceIDValue, activeVersionNumber)

		requestSettings, err := client.ListRequestSettings(context.Background(), &fastly.ListRequestSettingsInput{
			ServiceID:      serviceIDValue,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("    Error listing request settings for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
			continue
		}

		if len(requestSettings) == 0 {
			fmt.Printf("    No request settings found for service %s\n", serviceName)
		} else {
			fmt.Printf("    Found %d request setting(s) for service %s\n", len(requestSettings), serviceName)

			for _, requestSetting := range requestSettings {
				if requestSetting.Name == nil || *requestSetting.Name == "" {
					log.Printf("      Skipping request setting with empty name for service ID %s", serviceIDValue)
					continue
				}

				requestSettingName := *requestSetting.Name
				importID := fmt.Sprintf("%s/%s", serviceIDValue, requestSettingName)

				// Generate resource name
				tfRequestSettingResourceName := sanitizeForTerraformResourceName(requestSettingName, "request_setting")

				// Ensure uniqueness by adding service ID
				sanitizedServiceID := sanitizeForTerraformResourceName(serviceIDValue, "svc")
				tfRequestSettingResourceName = fmt.Sprintf("%s_%s", tfRequestSettingResourceName, sanitizedServiceID)

				requestSettingImportBlock := rootBody.AppendNewBlock("import", nil)
				requestSettingImportBody := requestSettingImportBlock.Body()
				requestSettingImportBody.SetAttributeValue("id", cty.StringVal(importID))

				requestSettingImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: "fastly_service_request_setting"},
					hcl.TraverseAttr{Name: tfRequestSettingResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				fmt.Printf("      Added import for request setting: %s (Import ID: %s) as fastly_service_request_setting.%s\n", requestSettingName, importID, tfRequestSettingResourceName)
			}
		}
	}

	return importCount, nil
}

// importServiceResponseObjects handles importing Fastly service response object resources
func importServiceResponseObjects(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for response object imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service response objects...")

	for _, service := range services {
		var serviceIDValue string
		if service.ServiceID != nil {
			serviceIDValue = *service.ServiceID
		}

		var serviceName string
		if service.Name != nil {
			serviceName = *service.Name
		}

		if serviceIDValue == "" {
			log.Printf("Skipping service with empty ID (Name: %s) for response object imports\n", serviceName)
			continue
		}

		// Get the active version for this service
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping response objects.", serviceIDValue, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping response objects.", serviceIDValue)
			continue
		}

		fmt.Printf("  Fetching response objects for service: %s (ID: %s, version: %d)\n", serviceName, serviceIDValue, activeVersionNumber)

		responseObjects, err := client.ListResponseObjects(context.Background(), &fastly.ListResponseObjectsInput{
			ServiceID:      serviceIDValue,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("    Error listing response objects for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
			continue
		}

		if len(responseObjects) == 0 {
			fmt.Printf("    No response objects found for service %s\n", serviceName)
		} else {
			fmt.Printf("    Found %d response object(s) for service %s\n", len(responseObjects), serviceName)

			for _, responseObject := range responseObjects {
				if responseObject.Name == nil || *responseObject.Name == "" {
					log.Printf("      Skipping response object with empty name for service ID %s", serviceIDValue)
					continue
				}

				responseObjectName := *responseObject.Name
				importID := fmt.Sprintf("%s/%s", serviceIDValue, responseObjectName)

				// Generate resource name
				tfResponseObjectResourceName := sanitizeForTerraformResourceName(responseObjectName, "response_object")

				// Ensure uniqueness by adding service ID
				sanitizedServiceID := sanitizeForTerraformResourceName(serviceIDValue, "svc")
				tfResponseObjectResourceName = fmt.Sprintf("%s_%s", tfResponseObjectResourceName, sanitizedServiceID)

				responseObjectImportBlock := rootBody.AppendNewBlock("import", nil)
				responseObjectImportBody := responseObjectImportBlock.Body()
				responseObjectImportBody.SetAttributeValue("id", cty.StringVal(importID))

				responseObjectImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: "fastly_service_response_object"},
					hcl.TraverseAttr{Name: tfResponseObjectResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				fmt.Printf("      Added import for response object: %s (Import ID: %s) as fastly_service_response_object.%s\n", responseObjectName, importID, tfResponseObjectResourceName)
			}
		}
	}

	return importCount, nil
}

// importServiceStaticSnippets handles importing Fastly service static VCL snippet resources
func importServiceStaticSnippets(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for static snippet imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service static VCL snippets...")

	for _, service := range services {
		var serviceIDValue string
		if service.ServiceID != nil {
			serviceIDValue = *service.ServiceID
		}

		var serviceName string
		if service.Name != nil {
			serviceName = *service.Name
		}

		var serviceType string
		if service.Type != nil {
			serviceType = *service.Type
		}

		if serviceIDValue == "" {
			log.Printf("Skipping service with empty ID (Name: %s) for static snippet imports\n", serviceName)
			continue
		}

		// Only process VCL services for static snippets
		if serviceType != "vcl" {
			fmt.Printf("  Skipping service %s (ID: %s) - static snippets only available for VCL services\n", serviceName, serviceIDValue)
			continue
		}

		// Get the active version for this service
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping static snippets.", serviceIDValue, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping static snippets.", serviceIDValue)
			continue
		}

		fmt.Printf("  Fetching static snippets for VCL service: %s (ID: %s, version: %d)\n", serviceName, serviceIDValue, activeVersionNumber)

		snippets, err := client.ListSnippets(context.Background(), &fastly.ListSnippetsInput{
			ServiceID:      serviceIDValue,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("    Error listing snippets for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
			continue
		}

		staticSnippetCount := 0
		for _, snippet := range snippets {
			// Filter for static snippets (Dynamic == 0 or nil)
			isStatic := true
			if snippet.Dynamic != nil && *snippet.Dynamic == 1 {
				isStatic = false
			}

			if isStatic {
				staticSnippetCount++

				if snippet.Name == nil || *snippet.Name == "" {
					log.Printf("      Skipping static snippet with empty name for service ID %s", serviceIDValue)
					continue
				}

				snippetName := *snippet.Name
				importID := fmt.Sprintf("%s/%s", serviceIDValue, snippetName)

				// Generate resource name
				tfSnippetResourceName := sanitizeForTerraformResourceName(snippetName, "snippet")

				// Ensure uniqueness by adding service ID
				sanitizedServiceID := sanitizeForTerraformResourceName(serviceIDValue, "svc")
				tfSnippetResourceName = fmt.Sprintf("%s_%s", tfSnippetResourceName, sanitizedServiceID)

				snippetImportBlock := rootBody.AppendNewBlock("import", nil)
				snippetImportBody := snippetImportBlock.Body()
				snippetImportBody.SetAttributeValue("id", cty.StringVal(importID))

				snippetImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: "fastly_service_snippet"},
					hcl.TraverseAttr{Name: tfSnippetResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				fmt.Printf("      Added import for static snippet: %s (Import ID: %s) as fastly_service_snippet.%s\n", snippetName, importID, tfSnippetResourceName)
			}
		}

		if staticSnippetCount == 0 {
			fmt.Printf("    No static snippets found for service %s\n", serviceName)
		} else {
			fmt.Printf("    Found %d static snippet(s) for service %s\n", staticSnippetCount, serviceName)
		}
	}

	return importCount, nil
}

// importServiceVCLs handles importing Fastly service VCL file resources
func importServiceVCLs(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for VCL imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service VCL files...")

	for _, service := range services {
		var serviceIDValue string
		if service.ServiceID != nil {
			serviceIDValue = *service.ServiceID
		}

		var serviceName string
		if service.Name != nil {
			serviceName = *service.Name
		}

		var serviceType string
		if service.Type != nil {
			serviceType = *service.Type
		}

		if serviceIDValue == "" {
			log.Printf("Skipping service with empty ID (Name: %s) for VCL imports\n", serviceName)
			continue
		}

		// Only process VCL services for VCL files
		if serviceType != "vcl" {
			fmt.Printf("  Skipping service %s (ID: %s) - VCL files only available for VCL services\n", serviceName, serviceIDValue)
			continue
		}

		// Get the active version for this service
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping VCL files.", serviceIDValue, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping VCL files.", serviceIDValue)
			continue
		}

		fmt.Printf("  Fetching VCL files for VCL service: %s (ID: %s, version: %d)\n", serviceName, serviceIDValue, activeVersionNumber)

		vcls, err := client.ListVCLs(context.Background(), &fastly.ListVCLsInput{
			ServiceID:      serviceIDValue,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("    Error listing VCL files for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
			continue
		}

		if len(vcls) == 0 {
			fmt.Printf("    No VCL files found for service %s\n", serviceName)
		} else {
			fmt.Printf("    Found %d VCL file(s) for service %s\n", len(vcls), serviceName)

			for _, vcl := range vcls {
				if vcl.Name == nil || *vcl.Name == "" {
					log.Printf("      Skipping VCL file with empty name for service ID %s", serviceIDValue)
					continue
				}

				vclName := *vcl.Name
				importID := fmt.Sprintf("%s/%s", serviceIDValue, vclName)

				// Generate resource name
				tfVCLResourceName := sanitizeForTerraformResourceName(vclName, "vcl")

				// Ensure uniqueness by adding service ID
				sanitizedServiceID := sanitizeForTerraformResourceName(serviceIDValue, "svc")
				tfVCLResourceName = fmt.Sprintf("%s_%s", tfVCLResourceName, sanitizedServiceID)

				vclImportBlock := rootBody.AppendNewBlock("import", nil)
				vclImportBody := vclImportBlock.Body()
				vclImportBody.SetAttributeValue("id", cty.StringVal(importID))

				vclImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: "fastly_service_vcl"},
					hcl.TraverseAttr{Name: tfVCLResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				fmt.Printf("      Added import for VCL file: %s (Import ID: %s) as fastly_service_vcl.%s\n", vclName, importID, tfVCLResourceName)
			}
		}
	}

	return importCount, nil
}

// importUsers handles importing Fastly user resources
func importUsers(client *fastly.Client, rootBody *hclwrite.Body) (int, error) {
	fmt.Println("\nFetching Fastly users...")

	users, err := client.ListCustomerUsers(context.Background(), &fastly.ListCustomerUsersInput{})
	if err != nil {
		log.Printf("Error listing users: %v. Skipping user imports.", err)
		return 0, err
	}

	importCount := 0
	if len(users) == 0 {
		fmt.Println("No users found for this account.")
	} else {
		fmt.Printf("Found %d user(s). Adding to import.tf...\n", len(users))

		for _, user := range users {
			if user.UserID == nil || *user.UserID == "" {
				log.Printf("Skipping user with empty ID\n")
				continue
			}

			userID := *user.UserID
			var userName string
			if user.Name != nil {
				userName = *user.Name
			}

			// Generate resource name using user name if available, otherwise use ID
			var tfUserResourceName string
			if userName != "" {
				tfUserResourceName = sanitizeForTerraformResourceName(userName, "user")
			} else {
				tfUserResourceName = sanitizeForTerraformResourceName(userID, "user")
			}

			// Ensure uniqueness by adding user ID suffix
			sanitizedUserID := sanitizeForTerraformResourceName(userID, "id")
			tfUserResourceName = fmt.Sprintf("%s_%s", tfUserResourceName, sanitizedUserID)

			userImportBlock := rootBody.AppendNewBlock("import", nil)
			userImportBody := userImportBlock.Body()
			userImportBody.SetAttributeValue("id", cty.StringVal(userID))

			userImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_user"},
				hcl.TraverseAttr{Name: tfUserResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("  Added import for user: %s (ID: %s) as fastly_user.%s\n", userName, userID, tfUserResourceName)
		}
	}

	return importCount, nil
}

// importServiceAuthorizations handles importing Fastly service authorization resources
func importServiceAuthorizations(client *fastly.Client, rootBody *hclwrite.Body) (int, error) {
	fmt.Println("\nFetching Fastly service authorizations...")

	serviceAuthorizations, err := client.ListServiceAuthorizations(context.Background(), &fastly.ListServiceAuthorizationsInput{})
	if err != nil {
		log.Printf("Error listing service authorizations: %v. Skipping service authorization imports.", err)
		return 0, err
	}

	importCount := 0
	if serviceAuthorizations == nil || len(serviceAuthorizations.Items) == 0 {
		fmt.Println("No service authorizations found for this account.")
	} else {
		fmt.Printf("Found %d service authorization(s). Adding to import.tf...\n", len(serviceAuthorizations.Items))

		for _, serviceAuth := range serviceAuthorizations.Items {
			if serviceAuth.ID == "" {
				log.Printf("Skipping service authorization with empty ID\n")
				continue
			}

			serviceAuthID := serviceAuth.ID

			// Generate resource name using service auth ID
			tfServiceAuthResourceName := sanitizeForTerraformResourceName(serviceAuthID, "service_authorization")

			serviceAuthImportBlock := rootBody.AppendNewBlock("import", nil)
			serviceAuthImportBody := serviceAuthImportBlock.Body()
			serviceAuthImportBody.SetAttributeValue("id", cty.StringVal(serviceAuthID))

			serviceAuthImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_service_authorization"},
				hcl.TraverseAttr{Name: tfServiceAuthResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			// Show service and user info if available
			var serviceInfo, userInfo string
			if serviceAuth.Service != nil && serviceAuth.Service.ID != "" {
				serviceInfo = fmt.Sprintf("Service: %s", serviceAuth.Service.ID)
			}
			if serviceAuth.User != nil && serviceAuth.User.ID != "" {
				userInfo = fmt.Sprintf("User: %s", serviceAuth.User.ID)
			}

			fmt.Printf("  Added import for service authorization: %s (%s, %s) as fastly_service_authorization.%s\n", serviceAuthID, serviceInfo, userInfo, tfServiceAuthResourceName)
		}
	}

	return importCount, nil
}

// importServiceS3Logging handles importing Fastly service S3 logging resources
func importServiceS3Logging(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for S3 logging imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service S3 logging endpoints...")

	for _, service := range services {
		var serviceIDValue string
		if service.ServiceID != nil {
			serviceIDValue = *service.ServiceID
		}

		var serviceName string
		if service.Name != nil {
			serviceName = *service.Name
		}

		if serviceIDValue == "" {
			log.Printf("Skipping service with empty ID (Name: %s) for S3 logging imports\n", serviceName)
			continue
		}

		// Get the active version for this service
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping S3 logging.", serviceIDValue, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping S3 logging.", serviceIDValue)
			continue
		}

		fmt.Printf("  Fetching S3 logging endpoints for service: %s (ID: %s, version: %d)\n", serviceName, serviceIDValue, activeVersionNumber)

		s3Logs, err := client.ListS3s(context.Background(), &fastly.ListS3sInput{
			ServiceID:      serviceIDValue,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("    Error listing S3 logging endpoints for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
			continue
		}

		if len(s3Logs) == 0 {
			fmt.Printf("    No S3 logging endpoints found for service %s\n", serviceName)
		} else {
			fmt.Printf("    Found %d S3 logging endpoint(s) for service %s\n", len(s3Logs), serviceName)

			for _, s3Log := range s3Logs {
				if s3Log.Name == nil || *s3Log.Name == "" {
					log.Printf("      Skipping S3 logging endpoint with empty name for service ID %s", serviceIDValue)
					continue
				}

				s3LogName := *s3Log.Name
				importID := fmt.Sprintf("%s/%s", serviceIDValue, s3LogName)

				// Generate resource name
				tfS3LogResourceName := sanitizeForTerraformResourceName(s3LogName, "s3_logging")

				// Ensure uniqueness by adding service ID
				sanitizedServiceID := sanitizeForTerraformResourceName(serviceIDValue, "svc")
				tfS3LogResourceName = fmt.Sprintf("%s_%s", tfS3LogResourceName, sanitizedServiceID)

				s3LogImportBlock := rootBody.AppendNewBlock("import", nil)
				s3LogImportBody := s3LogImportBlock.Body()
				s3LogImportBody.SetAttributeValue("id", cty.StringVal(importID))

				s3LogImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: "fastly_service_logging_s3"},
					hcl.TraverseAttr{Name: tfS3LogResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				fmt.Printf("      Added import for S3 logging: %s (Import ID: %s) as fastly_service_logging_s3.%s\n", s3LogName, importID, tfS3LogResourceName)
			}
		}
	}

	return importCount, nil
}

// importServiceSyslogLogging handles importing Fastly service Syslog logging resources
func importServiceSyslogLogging(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for Syslog logging imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service Syslog logging endpoints...")

	for _, service := range services {
		var serviceIDValue string
		if service.ServiceID != nil {
			serviceIDValue = *service.ServiceID
		}

		var serviceName string
		if service.Name != nil {
			serviceName = *service.Name
		}

		if serviceIDValue == "" {
			log.Printf("Skipping service with empty ID (Name: %s) for Syslog logging imports\n", serviceName)
			continue
		}

		// Get the active version for this service
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping Syslog logging.", serviceIDValue, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping Syslog logging.", serviceIDValue)
			continue
		}

		fmt.Printf("  Fetching Syslog logging endpoints for service: %s (ID: %s, version: %d)\n", serviceName, serviceIDValue, activeVersionNumber)

		syslogLogs, err := client.ListSyslogs(context.Background(), &fastly.ListSyslogsInput{
			ServiceID:      serviceIDValue,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("    Error listing Syslog logging endpoints for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
			continue
		}

		if len(syslogLogs) == 0 {
			fmt.Printf("    No Syslog logging endpoints found for service %s\n", serviceName)
		} else {
			fmt.Printf("    Found %d Syslog logging endpoint(s) for service %s\n", len(syslogLogs), serviceName)

			for _, syslogLog := range syslogLogs {
				if syslogLog.Name == nil || *syslogLog.Name == "" {
					log.Printf("      Skipping Syslog logging endpoint with empty name for service ID %s", serviceIDValue)
					continue
				}

				syslogLogName := *syslogLog.Name
				importID := fmt.Sprintf("%s/%s", serviceIDValue, syslogLogName)

				// Generate resource name
				tfSyslogLogResourceName := sanitizeForTerraformResourceName(syslogLogName, "syslog_logging")

				// Ensure uniqueness by adding service ID
				sanitizedServiceID := sanitizeForTerraformResourceName(serviceIDValue, "svc")
				tfSyslogLogResourceName = fmt.Sprintf("%s_%s", tfSyslogLogResourceName, sanitizedServiceID)

				syslogLogImportBlock := rootBody.AppendNewBlock("import", nil)
				syslogLogImportBody := syslogLogImportBlock.Body()
				syslogLogImportBody.SetAttributeValue("id", cty.StringVal(importID))

				syslogLogImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: "fastly_service_logging_syslog"},
					hcl.TraverseAttr{Name: tfSyslogLogResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				fmt.Printf("      Added import for Syslog logging: %s (Import ID: %s) as fastly_service_logging_syslog.%s\n", syslogLogName, importID, tfSyslogLogResourceName)
			}
		}
	}

	return importCount, nil
}

// importServiceDatadogLogging handles importing Fastly service Datadog logging resources
func importServiceDatadogLogging(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for Datadog logging imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service Datadog logging endpoints...")

	for _, service := range services {
		var serviceIDValue string
		if service.ServiceID != nil {
			serviceIDValue = *service.ServiceID
		}

		var serviceName string
		if service.Name != nil {
			serviceName = *service.Name
		}

		if serviceIDValue == "" {
			log.Printf("Skipping service with empty ID (Name: %s) for Datadog logging imports\n", serviceName)
			continue
		}

		// Get the active version for this service
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping Datadog logging.", serviceIDValue, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping Datadog logging.", serviceIDValue)
			continue
		}

		fmt.Printf("  Fetching Datadog logging endpoints for service: %s (ID: %s, version: %d)\n", serviceName, serviceIDValue, activeVersionNumber)

		datadogLogs, err := client.ListDatadog(context.Background(), &fastly.ListDatadogInput{
			ServiceID:      serviceIDValue,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("    Error listing Datadog logging endpoints for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
			continue
		}

		if len(datadogLogs) == 0 {
			fmt.Printf("    No Datadog logging endpoints found for service %s\n", serviceName)
		} else {
			fmt.Printf("    Found %d Datadog logging endpoint(s) for service %s\n", len(datadogLogs), serviceName)

			for _, datadogLog := range datadogLogs {
				if datadogLog.Name == nil || *datadogLog.Name == "" {
					log.Printf("      Skipping Datadog logging endpoint with empty name for service ID %s", serviceIDValue)
					continue
				}

				datadogLogName := *datadogLog.Name
				importID := fmt.Sprintf("%s/%s", serviceIDValue, datadogLogName)

				// Generate resource name
				tfDatadogLogResourceName := sanitizeForTerraformResourceName(datadogLogName, "datadog_logging")

				// Ensure uniqueness by adding service ID
				sanitizedServiceID := sanitizeForTerraformResourceName(serviceIDValue, "svc")
				tfDatadogLogResourceName = fmt.Sprintf("%s_%s", tfDatadogLogResourceName, sanitizedServiceID)

				datadogLogImportBlock := rootBody.AppendNewBlock("import", nil)
				datadogLogImportBody := datadogLogImportBlock.Body()
				datadogLogImportBody.SetAttributeValue("id", cty.StringVal(importID))

				datadogLogImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: "fastly_service_logging_datadog"},
					hcl.TraverseAttr{Name: tfDatadogLogResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				fmt.Printf("      Added import for Datadog logging: %s (Import ID: %s) as fastly_service_logging_datadog.%s\n", datadogLogName, importID, tfDatadogLogResourceName)
			}
		}
	}

	return importCount, nil
}

// importServiceBigQueryLogging handles importing Fastly service BigQuery logging resources
func importServiceBigQueryLogging(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for BigQuery logging imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service BigQuery logging endpoints...")

	for _, service := range services {
		var serviceIDValue string
		if service.ServiceID != nil {
			serviceIDValue = *service.ServiceID
		}

		var serviceName string
		if service.Name != nil {
			serviceName = *service.Name
		}

		if serviceIDValue == "" {
			log.Printf("Skipping service with empty ID (Name: %s) for BigQuery logging imports\n", serviceName)
			continue
		}

		// Get the active version for this service
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping BigQuery logging.", serviceIDValue, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping BigQuery logging.", serviceIDValue)
			continue
		}

		fmt.Printf("  Fetching BigQuery logging endpoints for service: %s (ID: %s, version: %d)\n", serviceName, serviceIDValue, activeVersionNumber)

		bigQueryLogs, err := client.ListBigQueries(context.Background(), &fastly.ListBigQueriesInput{
			ServiceID:      serviceIDValue,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("    Error listing BigQuery logging endpoints for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
			continue
		}

		if len(bigQueryLogs) == 0 {
			fmt.Printf("    No BigQuery logging endpoints found for service %s\n", serviceName)
		} else {
			fmt.Printf("    Found %d BigQuery logging endpoint(s) for service %s\n", len(bigQueryLogs), serviceName)

			for _, bigQueryLog := range bigQueryLogs {
				if bigQueryLog.Name == nil || *bigQueryLog.Name == "" {
					log.Printf("      Skipping BigQuery logging endpoint with empty name for service ID %s", serviceIDValue)
					continue
				}

				bigQueryLogName := *bigQueryLog.Name
				importID := fmt.Sprintf("%s/%s", serviceIDValue, bigQueryLogName)

				// Generate resource name
				tfBigQueryLogResourceName := sanitizeForTerraformResourceName(bigQueryLogName, "bigquery_logging")

				// Ensure uniqueness by adding service ID
				sanitizedServiceID := sanitizeForTerraformResourceName(serviceIDValue, "svc")
				tfBigQueryLogResourceName = fmt.Sprintf("%s_%s", tfBigQueryLogResourceName, sanitizedServiceID)

				bigQueryLogImportBlock := rootBody.AppendNewBlock("import", nil)
				bigQueryLogImportBody := bigQueryLogImportBlock.Body()
				bigQueryLogImportBody.SetAttributeValue("id", cty.StringVal(importID))

				bigQueryLogImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: "fastly_service_logging_bigquery"},
					hcl.TraverseAttr{Name: tfBigQueryLogResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				fmt.Printf("      Added import for BigQuery logging: %s (Import ID: %s) as fastly_service_logging_bigquery.%s\n", bigQueryLogName, importID, tfBigQueryLogResourceName)
			}
		}
	}

	return importCount, nil
}

// importServiceSplunkLogging handles importing Fastly service Splunk logging resources
func importServiceSplunkLogging(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for Splunk logging imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service Splunk logging endpoints...")

	for _, service := range services {
		var serviceIDValue string
		if service.ServiceID != nil {
			serviceIDValue = *service.ServiceID
		}

		var serviceName string
		if service.Name != nil {
			serviceName = *service.Name
		}

		if serviceIDValue == "" {
			log.Printf("Skipping service with empty ID (Name: %s) for Splunk logging imports\n", serviceName)
			continue
		}

		// Get the active version for this service
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping Splunk logging.", serviceIDValue, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping Splunk logging.", serviceIDValue)
			continue
		}

		fmt.Printf("  Fetching Splunk logging endpoints for service: %s (ID: %s, version: %d)\n", serviceName, serviceIDValue, activeVersionNumber)

		splunkLogs, err := client.ListSplunks(context.Background(), &fastly.ListSplunksInput{
			ServiceID:      serviceIDValue,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("    Error listing Splunk logging endpoints for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
			continue
		}

		if len(splunkLogs) == 0 {
			fmt.Printf("    No Splunk logging endpoints found for service %s\n", serviceName)
		} else {
			fmt.Printf("    Found %d Splunk logging endpoint(s) for service %s\n", len(splunkLogs), serviceName)

			for _, splunkLog := range splunkLogs {
				if splunkLog.Name == nil || *splunkLog.Name == "" {
					log.Printf("      Skipping Splunk logging endpoint with empty name for service ID %s", serviceIDValue)
					continue
				}

				splunkLogName := *splunkLog.Name
				importID := fmt.Sprintf("%s/%s", serviceIDValue, splunkLogName)

				// Generate resource name
				tfSplunkLogResourceName := sanitizeForTerraformResourceName(splunkLogName, "splunk_logging")

				// Ensure uniqueness by adding service ID
				sanitizedServiceID := sanitizeForTerraformResourceName(serviceIDValue, "svc")
				tfSplunkLogResourceName = fmt.Sprintf("%s_%s", tfSplunkLogResourceName, sanitizedServiceID)

				splunkLogImportBlock := rootBody.AppendNewBlock("import", nil)
				splunkLogImportBody := splunkLogImportBlock.Body()
				splunkLogImportBody.SetAttributeValue("id", cty.StringVal(importID))

				splunkLogImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: "fastly_service_logging_splunk"},
					hcl.TraverseAttr{Name: tfSplunkLogResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				fmt.Printf("      Added import for Splunk logging: %s (Import ID: %s) as fastly_service_logging_splunk.%s\n", splunkLogName, importID, tfSplunkLogResourceName)
			}
		}
	}

	return importCount, nil
}

// importServicePapertrailLogging handles importing Fastly service Papertrail logging resources
func importServicePapertrailLogging(client *fastly.Client, rootBody *hclwrite.Body, services []*fastly.Service) (int, error) {
	importCount := 0

	if len(services) == 0 {
		fmt.Println("No services available for Papertrail logging imports.")
		return 0, nil
	}

	fmt.Println("\nFetching Fastly service Papertrail logging endpoints...")

	for _, service := range services {
		var serviceIDValue string
		if service.ServiceID != nil {
			serviceIDValue = *service.ServiceID
		}

		var serviceName string
		if service.Name != nil {
			serviceName = *service.Name
		}

		if serviceIDValue == "" {
			log.Printf("Skipping service with empty ID (Name: %s) for Papertrail logging imports\n", serviceName)
			continue
		}

		// Get the active version for this service
		serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
		if err != nil {
			log.Printf("Error fetching service details for service ID %s: %v. Skipping Papertrail logging.", serviceIDValue, err)
			continue
		}

		var activeVersionNumber int
		foundActiveVersion := false

		if serviceDetails.ActiveVersion != nil {
			activeVersionNumber = *serviceDetails.ActiveVersion
			foundActiveVersion = true
		}

		if !foundActiveVersion {
			log.Printf("  No active version found for service ID %s. Skipping Papertrail logging.", serviceIDValue)
			continue
		}

		fmt.Printf("  Fetching Papertrail logging endpoints for service: %s (ID: %s, version: %d)\n", serviceName, serviceIDValue, activeVersionNumber)

		papertrailLogs, err := client.ListPapertrails(context.Background(), &fastly.ListPapertrailsInput{
			ServiceID:      serviceIDValue,
			ServiceVersion: activeVersionNumber,
		})
		if err != nil {
			log.Printf("    Error listing Papertrail logging endpoints for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
			continue
		}

		if len(papertrailLogs) == 0 {
			fmt.Printf("    No Papertrail logging endpoints found for service %s\n", serviceName)
		} else {
			fmt.Printf("    Found %d Papertrail logging endpoint(s) for service %s\n", len(papertrailLogs), serviceName)

			for _, papertrailLog := range papertrailLogs {
				if papertrailLog.Name == nil || *papertrailLog.Name == "" {
					log.Printf("      Skipping Papertrail logging endpoint with empty name for service ID %s", serviceIDValue)
					continue
				}

				papertrailLogName := *papertrailLog.Name
				importID := fmt.Sprintf("%s/%s", serviceIDValue, papertrailLogName)

				// Generate resource name
				tfPapertrailLogResourceName := sanitizeForTerraformResourceName(papertrailLogName, "papertrail_logging")

				// Ensure uniqueness by adding service ID
				sanitizedServiceID := sanitizeForTerraformResourceName(serviceIDValue, "svc")
				tfPapertrailLogResourceName = fmt.Sprintf("%s_%s", tfPapertrailLogResourceName, sanitizedServiceID)

				papertrailLogImportBlock := rootBody.AppendNewBlock("import", nil)
				papertrailLogImportBody := papertrailLogImportBlock.Body()
				papertrailLogImportBody.SetAttributeValue("id", cty.StringVal(importID))

				papertrailLogImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: "fastly_service_logging_papertrail"},
					hcl.TraverseAttr{Name: tfPapertrailLogResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				fmt.Printf("      Added import for Papertrail logging: %s (Import ID: %s) as fastly_service_logging_papertrail.%s\n", papertrailLogName, importID, tfPapertrailLogResourceName)
			}
		}
	}

	return importCount, nil
}

// importNGWAFWorkspaceLists handles importing NGWAF workspace-scoped list resources
func importNGWAFWorkspaceLists(client *fastly.Client, rootBody *hclwrite.Body, ngwafWorkspaces *workspaces.Workspaces) (int, error) {
	importCount := 0

	if ngwafWorkspaces == nil || len(ngwafWorkspaces.Data) == 0 {
		fmt.Println("No workspaces available for workspace-scoped list imports.")
		return 0, nil
	}

	fmt.Println("\nFetching NGWAF workspace-scoped lists...")

	for _, workspace := range ngwafWorkspaces.Data {
		if workspace.WorkspaceID == "" {
			continue
		}

		fmt.Printf("  Fetching lists for workspace: %s (ID: %s)\n", workspace.Name, workspace.WorkspaceID)

		workspaceScope := &scope.Scope{
			Type:      scope.ScopeTypeWorkspace,
			AppliesTo: []string{workspace.WorkspaceID},
		}

		ngwafLists, err := lists.ListLists(context.Background(), client, &lists.ListInput{Scope: workspaceScope})
		if err != nil {
			log.Printf("Error listing NGWAF lists for workspace %s: %v. Skipping.", workspace.WorkspaceID, err)
			continue
		}

		if len(ngwafLists.Data) == 0 {
			fmt.Printf("    No lists found for workspace %s\n", workspace.WorkspaceID)
			continue
		}

		fmt.Printf("    Found %d list(s) for workspace %s\n", len(ngwafLists.Data), workspace.WorkspaceID)

		for _, list := range ngwafLists.Data {
			if list.ListID == "" {
				log.Printf("Skipping NGWAF workspace list with empty ID (Name: %s) in workspace %s\n", list.Name, workspace.WorkspaceID)
				continue
			}

			importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, list.ListID)

			// Generate workspace-prefixed resource name to prevent conflicts
			tfListResourceName := generateWorkspacePrefixedResourceName(
				workspace.WorkspaceID,
				list.Name,
				list.ListID,
				"ngwaf_workspace_list",
			)

			listImportBlock := rootBody.AppendNewBlock("import", nil)
			listImportBody := listImportBlock.Body()
			listImportBody.SetAttributeValue("id", cty.StringVal(importID))

			listImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_ngwaf_workspace_list"},
				hcl.TraverseAttr{Name: tfListResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("    Added import for NGWAF workspace list: %s (ID: %s) as fastly_ngwaf_workspace_list.%s\n", list.Name, importID, tfListResourceName)
		}
	}

	return importCount, nil
}

// importNGWAFWorkspaceRules handles importing NGWAF workspace-scoped rule resources
func importNGWAFWorkspaceRules(client *fastly.Client, rootBody *hclwrite.Body, ngwafWorkspaces *workspaces.Workspaces) (int, error) {
	importCount := 0

	if ngwafWorkspaces == nil || len(ngwafWorkspaces.Data) == 0 {
		fmt.Println("No workspaces available for workspace-scoped rule imports.")
		return 0, nil
	}

	fmt.Println("\nFetching NGWAF workspace-scoped rules...")

	for _, workspace := range ngwafWorkspaces.Data {
		if workspace.WorkspaceID == "" {
			continue
		}

		fmt.Printf("  Fetching rules for workspace: %s (ID: %s)\n", workspace.Name, workspace.WorkspaceID)

		workspaceScope := &scope.Scope{
			Type:      scope.ScopeTypeWorkspace,
			AppliesTo: []string{workspace.WorkspaceID},
		}

		ngwafRules, err := rules.List(context.Background(), client, &rules.ListInput{Scope: workspaceScope})
		if err != nil {
			log.Printf("Error listing NGWAF rules for workspace %s: %v. Skipping.", workspace.WorkspaceID, err)
			continue
		}

		if len(ngwafRules.Data) == 0 {
			fmt.Printf("    No rules found for workspace %s\n", workspace.WorkspaceID)
			continue
		}

		fmt.Printf("    Found %d rule(s) for workspace %s\n", len(ngwafRules.Data), workspace.WorkspaceID)

		for _, rule := range ngwafRules.Data {
			if rule.RuleID == "" {
				log.Printf("Skipping NGWAF workspace rule with empty ID (Description: %s) in workspace %s\n", rule.Description, workspace.WorkspaceID)
				continue
			}

			importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, rule.RuleID)

			// Generate workspace-prefixed resource name to prevent conflicts
			tfRuleResourceName := generateWorkspacePrefixedResourceName(
				workspace.WorkspaceID,
				rule.Description,
				rule.RuleID,
				"ngwaf_workspace_rule",
			)

			ruleImportBlock := rootBody.AppendNewBlock("import", nil)
			ruleImportBody := ruleImportBlock.Body()
			ruleImportBody.SetAttributeValue("id", cty.StringVal(importID))

			ruleImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_ngwaf_workspace_rule"},
				hcl.TraverseAttr{Name: tfRuleResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("    Added import for NGWAF workspace rule: %s (ID: %s) as fastly_ngwaf_workspace_rule.%s\n", rule.Description, importID, tfRuleResourceName)
		}
	}

	return importCount, nil
}

// importNGWAFWorkspaceSignals handles importing NGWAF workspace-scoped signal resources
func importNGWAFWorkspaceSignals(client *fastly.Client, rootBody *hclwrite.Body, ngwafWorkspaces *workspaces.Workspaces) (int, error) {
	importCount := 0

	if ngwafWorkspaces == nil || len(ngwafWorkspaces.Data) == 0 {
		fmt.Println("No workspaces available for workspace-scoped signal imports.")
		return 0, nil
	}

	fmt.Println("\nFetching NGWAF workspace-scoped signals...")

	for _, workspace := range ngwafWorkspaces.Data {
		if workspace.WorkspaceID == "" {
			continue
		}

		fmt.Printf("  Fetching signals for workspace: %s (ID: %s)\n", workspace.Name, workspace.WorkspaceID)

		workspaceScope := &scope.Scope{
			Type:      scope.ScopeTypeWorkspace,
			AppliesTo: []string{workspace.WorkspaceID},
		}

		ngwafSignals, err := signals.List(context.Background(), client, &signals.ListInput{Scope: workspaceScope})
		if err != nil {
			log.Printf("Error listing NGWAF signals for workspace %s: %v. Skipping.", workspace.WorkspaceID, err)
			continue
		}

		if len(ngwafSignals.Data) == 0 {
			fmt.Printf("    No signals found for workspace %s\n", workspace.WorkspaceID)
			continue
		}

		fmt.Printf("    Found %d signal(s) for workspace %s\n", len(ngwafSignals.Data), workspace.WorkspaceID)

		for _, signal := range ngwafSignals.Data {
			if signal.SignalID == "" {
				log.Printf("Skipping NGWAF workspace signal with empty ID (Name: %s) in workspace %s\n", signal.Name, workspace.WorkspaceID)
				continue
			}

			importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, signal.SignalID)

			// Generate workspace-prefixed resource name to prevent conflicts
			tfSignalResourceName := generateWorkspacePrefixedResourceName(
				workspace.WorkspaceID,
				signal.Name,
				signal.SignalID,
				"ngwaf_workspace_signal",
			)

			signalImportBlock := rootBody.AppendNewBlock("import", nil)
			signalImportBody := signalImportBlock.Body()
			signalImportBody.SetAttributeValue("id", cty.StringVal(importID))

			signalImportBody.SetAttributeTraversal("to", hcl.Traversal{
				hcl.TraverseRoot{Name: "fastly_ngwaf_workspace_signal"},
				hcl.TraverseAttr{Name: tfSignalResourceName},
			})
			rootBody.AppendNewline()
			importCount++

			fmt.Printf("    Added import for NGWAF workspace signal: %s (ID: %s) as fastly_ngwaf_workspace_signal.%s\n", signal.Name, importID, tfSignalResourceName)
		}
	}

	return importCount, nil
}

// importNGWAFWorkspaceScopedResources handles importing all workspace-scoped NGWAF resources (alerts, redactions, thresholds, virtual patches)
func importNGWAFWorkspaceScopedResources(client *fastly.Client, rootBody *hclwrite.Body, ngwafWorkspaces *workspaces.Workspaces) (int, error) {
	importCount := 0

	// For each workspace, fetch all alert integrations and other workspace-scoped resources
	if ngwafWorkspaces != nil && len(ngwafWorkspaces.Data) > 0 {
		fmt.Println("\nFetching NGWAF workspace alert integrations...")

		for _, workspace := range ngwafWorkspaces.Data {
			if workspace.WorkspaceID == "" {
				continue
			}

			fmt.Printf("  Processing alerts for workspace: %s (ID: %s)\n", workspace.Name, workspace.WorkspaceID)

			// Datadog alerts
			datadogAlerts, err := datadog.List(context.Background(), client, &datadog.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace datadog alerts for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(datadogAlerts.Data) > 0 {
				fmt.Printf("    Found %d datadog alert(s)\n", len(datadogAlerts.Data))
				for _, alert := range datadogAlerts.Data {
					if alert.ID == "" {
						continue
					}

					// Use workspace ID + alert ID as composite import ID
					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, alert.ID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfAlertResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						alert.Description,
						alert.ID,
						"ngwaf_alert_datadog",
					)

					alertImportBlock := rootBody.AppendNewBlock("import", nil)
					alertImportBody := alertImportBlock.Body()
					alertImportBody.SetAttributeValue("id", cty.StringVal(importID))

					alertImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_alert_datadog_integration"},
						hcl.TraverseAttr{Name: tfAlertResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF datadog alert: %s (ID: %s) as fastly_ngwaf_alert_datadog_integration.%s\n", alert.Description, importID, tfAlertResourceName)
				}
			}

			// Jira alerts
			jiraAlerts, err := jira.List(context.Background(), client, &jira.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace jira alerts for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(jiraAlerts.Data) > 0 {
				fmt.Printf("    Found %d jira alert(s)\n", len(jiraAlerts.Data))
				for _, alert := range jiraAlerts.Data {
					if alert.ID == "" {
						continue
					}

					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, alert.ID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfAlertResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						alert.Description,
						alert.ID,
						"ngwaf_alert_jira",
					)

					alertImportBlock := rootBody.AppendNewBlock("import", nil)
					alertImportBody := alertImportBlock.Body()
					alertImportBody.SetAttributeValue("id", cty.StringVal(importID))

					alertImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_alert_jira_integration"},
						hcl.TraverseAttr{Name: tfAlertResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF jira alert: %s (ID: %s) as fastly_ngwaf_alert_jira_integration.%s\n", alert.Description, importID, tfAlertResourceName)
				}
			}

			// Mailing list alerts
			mailinglistAlerts, err := mailinglist.List(context.Background(), client, &mailinglist.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace mailing list alerts for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(mailinglistAlerts.Data) > 0 {
				fmt.Printf("    Found %d mailing list alert(s)\n", len(mailinglistAlerts.Data))
				for _, alert := range mailinglistAlerts.Data {
					if alert.ID == "" {
						continue
					}

					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, alert.ID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfAlertResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						alert.Description,
						alert.ID,
						"ngwaf_alert_mailing_list",
					)

					alertImportBlock := rootBody.AppendNewBlock("import", nil)
					alertImportBody := alertImportBlock.Body()
					alertImportBody.SetAttributeValue("id", cty.StringVal(importID))

					alertImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_alert_mailing_list_integration"},
						hcl.TraverseAttr{Name: tfAlertResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF mailing list alert: %s (ID: %s) as fastly_ngwaf_alert_mailing_list_integration.%s\n", alert.Description, importID, tfAlertResourceName)
				}
			}

			// Microsoft Teams alerts
			microsoftteamsAlerts, err := microsoftteams.List(context.Background(), client, &microsoftteams.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace microsoft teams alerts for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(microsoftteamsAlerts.Data) > 0 {
				fmt.Printf("    Found %d microsoft teams alert(s)\n", len(microsoftteamsAlerts.Data))
				for _, alert := range microsoftteamsAlerts.Data {
					if alert.ID == "" {
						continue
					}

					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, alert.ID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfAlertResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						alert.Description,
						alert.ID,
						"ngwaf_alert_microsoft_teams",
					)

					alertImportBlock := rootBody.AppendNewBlock("import", nil)
					alertImportBody := alertImportBlock.Body()
					alertImportBody.SetAttributeValue("id", cty.StringVal(importID))

					alertImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_alert_microsoft_teams_integration"},
						hcl.TraverseAttr{Name: tfAlertResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF microsoft teams alert: %s (ID: %s) as fastly_ngwaf_alert_microsoft_teams_integration.%s\n", alert.Description, importID, tfAlertResourceName)
				}
			}

			// Opsgenie alerts
			opsgenieAlerts, err := opsgenie.List(context.Background(), client, &opsgenie.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace opsgenie alerts for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(opsgenieAlerts.Data) > 0 {
				fmt.Printf("    Found %d opsgenie alert(s)\n", len(opsgenieAlerts.Data))
				for _, alert := range opsgenieAlerts.Data {
					if alert.ID == "" {
						continue
					}

					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, alert.ID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfAlertResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						alert.Description,
						alert.ID,
						"ngwaf_alert_opsgenie",
					)

					alertImportBlock := rootBody.AppendNewBlock("import", nil)
					alertImportBody := alertImportBlock.Body()
					alertImportBody.SetAttributeValue("id", cty.StringVal(importID))

					alertImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_alert_opsgenie_integration"},
						hcl.TraverseAttr{Name: tfAlertResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF opsgenie alert: %s (ID: %s) as fastly_ngwaf_alert_opsgenie_integration.%s\n", alert.Description, importID, tfAlertResourceName)
				}
			}

			// PagerDuty alerts
			pagerdutyAlerts, err := pagerduty.List(context.Background(), client, &pagerduty.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace pagerduty alerts for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(pagerdutyAlerts.Data) > 0 {
				fmt.Printf("    Found %d pagerduty alert(s)\n", len(pagerdutyAlerts.Data))
				for _, alert := range pagerdutyAlerts.Data {
					if alert.ID == "" {
						continue
					}

					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, alert.ID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfAlertResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						alert.Description,
						alert.ID,
						"ngwaf_alert_pagerduty",
					)

					alertImportBlock := rootBody.AppendNewBlock("import", nil)
					alertImportBody := alertImportBlock.Body()
					alertImportBody.SetAttributeValue("id", cty.StringVal(importID))

					alertImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_alert_pagerduty_integration"},
						hcl.TraverseAttr{Name: tfAlertResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF pagerduty alert: %s (ID: %s) as fastly_ngwaf_alert_pagerduty_integration.%s\n", alert.Description, importID, tfAlertResourceName)
				}
			}

			// Slack alerts
			slackAlerts, err := slack.List(context.Background(), client, &slack.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace slack alerts for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(slackAlerts.Data) > 0 {
				fmt.Printf("    Found %d slack alert(s)\n", len(slackAlerts.Data))
				for _, alert := range slackAlerts.Data {
					if alert.ID == "" {
						continue
					}

					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, alert.ID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfAlertResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						alert.Description,
						alert.ID,
						"ngwaf_alert_slack",
					)

					alertImportBlock := rootBody.AppendNewBlock("import", nil)
					alertImportBody := alertImportBlock.Body()
					alertImportBody.SetAttributeValue("id", cty.StringVal(importID))

					alertImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_alert_slack_integration"},
						hcl.TraverseAttr{Name: tfAlertResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF slack alert: %s (ID: %s) as fastly_ngwaf_alert_slack_integration.%s\n", alert.Description, importID, tfAlertResourceName)
				}
			}

			// Webhook alerts
			webhookAlerts, err := webhook.List(context.Background(), client, &webhook.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace webhook alerts for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(webhookAlerts.Data) > 0 {
				fmt.Printf("    Found %d webhook alert(s)\n", len(webhookAlerts.Data))
				for _, alert := range webhookAlerts.Data {
					if alert.ID == "" {
						continue
					}

					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, alert.ID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfAlertResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						alert.Description,
						alert.ID,
						"ngwaf_alert_webhook",
					)

					alertImportBlock := rootBody.AppendNewBlock("import", nil)
					alertImportBody := alertImportBlock.Body()
					alertImportBody.SetAttributeValue("id", cty.StringVal(importID))

					alertImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_alert_webhook_integration"},
						hcl.TraverseAttr{Name: tfAlertResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF webhook alert: %s (ID: %s) as fastly_ngwaf_alert_webhook_integration.%s\n", alert.Description, importID, tfAlertResourceName)
				}
			}

			// Redactions
			workspaceRedactions, err := redactions.List(context.Background(), client, &redactions.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace redactions for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(workspaceRedactions.Data) > 0 {
				fmt.Printf("    Found %d redaction(s)\n", len(workspaceRedactions.Data))
				for _, redaction := range workspaceRedactions.Data {
					if redaction.RedactionID == "" {
						continue
					}

					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, redaction.RedactionID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfRedactionResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						redaction.Field,
						redaction.RedactionID,
						"ngwaf_redaction",
					)

					redactionImportBlock := rootBody.AppendNewBlock("import", nil)
					redactionImportBody := redactionImportBlock.Body()
					redactionImportBody.SetAttributeValue("id", cty.StringVal(importID))

					redactionImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_redaction"},
						hcl.TraverseAttr{Name: tfRedactionResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF redaction: %s (ID: %s) as fastly_ngwaf_redaction.%s\n", redaction.Field, importID, tfRedactionResourceName)
				}
			}

			// Thresholds
			workspaceThresholds, err := thresholds.List(context.Background(), client, &thresholds.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace thresholds for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(workspaceThresholds.Data) > 0 {
				fmt.Printf("    Found %d threshold(s)\n", len(workspaceThresholds.Data))
				for _, threshold := range workspaceThresholds.Data {
					if threshold.ThresholdID == "" {
						continue
					}

					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, threshold.ThresholdID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfThresholdResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						threshold.Name,
						threshold.ThresholdID,
						"ngwaf_thresholds",
					)

					thresholdImportBlock := rootBody.AppendNewBlock("import", nil)
					thresholdImportBody := thresholdImportBlock.Body()
					thresholdImportBody.SetAttributeValue("id", cty.StringVal(importID))

					thresholdImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_thresholds"},
						hcl.TraverseAttr{Name: tfThresholdResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF threshold: %s (ID: %s) as fastly_ngwaf_thresholds.%s\n", threshold.Name, importID, tfThresholdResourceName)
				}
			}

			// Virtual Patches
			workspaceVirtualPatches, err := virtualpatches.List(context.Background(), client, &virtualpatches.ListInput{WorkspaceID: &workspace.WorkspaceID})
			if err != nil {
				log.Printf("Error listing NGWAF workspace virtual patches for workspace %s: %v", workspace.WorkspaceID, err)
			} else if len(workspaceVirtualPatches.Data) > 0 {
				fmt.Printf("    Found %d virtual patch(es)\n", len(workspaceVirtualPatches.Data))
				for _, virtualPatch := range workspaceVirtualPatches.Data {
					if virtualPatch.ID == "" {
						continue
					}

					importID := fmt.Sprintf("%s/%s", workspace.WorkspaceID, virtualPatch.ID)

					// Generate workspace-prefixed resource name to prevent conflicts
					tfVirtualPatchResourceName := generateWorkspacePrefixedResourceName(
						workspace.WorkspaceID,
						virtualPatch.Description,
						virtualPatch.ID,
						"ngwaf_virtual_patches",
					)

					virtualPatchImportBlock := rootBody.AppendNewBlock("import", nil)
					virtualPatchImportBody := virtualPatchImportBlock.Body()
					virtualPatchImportBody.SetAttributeValue("id", cty.StringVal(importID))

					virtualPatchImportBody.SetAttributeTraversal("to", hcl.Traversal{
						hcl.TraverseRoot{Name: "fastly_ngwaf_virtual_patches"},
						hcl.TraverseAttr{Name: tfVirtualPatchResourceName},
					})
					rootBody.AppendNewline()
					importCount++

					fmt.Printf("      Added import for NGWAF virtual patch: %s (ID: %s) as fastly_ngwaf_virtual_patches.%s\n", virtualPatch.Description, importID, tfVirtualPatchResourceName)
				}
			}
		}
	}

	return importCount, nil
}

func main() {
	// --- 0. Parse CLI Arguments ---
	var importMode = flag.String("import", "all", "Specify which resources to import: all (default) or ngwaf")
	var showHelp = flag.Bool("help", false, "Show help information")
	var vclServiceID = flag.String("vcl-service-id", "", "Specify a single VCL service ID to import (optional, only applicable with -import all)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nfastly-terraformer generates Terraform import blocks for Fastly resources.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nImport Modes:\n")
		fmt.Fprintf(os.Stderr, "  all    Import all resources (Fastly services, dynamic snippets, NGWAF workspaces, lists, rules, signals, etc.) - default\n")
		fmt.Fprintf(os.Stderr, "  ngwaf  Import only NGWAF-specific resources (workspaces, lists, rules, signals, and all NGWAF sub-resources)\n")
		fmt.Fprintf(os.Stderr, "\nEnvironment Variables:\n")
		fmt.Fprintf(os.Stderr, "  FASTLY_API_KEY  Your Fastly API token (required)\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s                                      # Import all resources\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -import all                          # Import all resources (explicit)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -import ngwaf                        # Import only NGWAF resources\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -vcl-service-id SERVICE_ID           # Import only the specified VCL service (requires -import all)\n", os.Args[0])
	}
	flag.Parse()

	if *showHelp {
		flag.Usage()
		return
	}

	// Validate import mode
	originalMode := *importMode
	*importMode = validateImportMode(*importMode)
	if originalMode != *importMode {
		fmt.Fprintf(os.Stderr, "Error: Invalid import mode '%s'. Valid options are 'all' or 'ngwaf'.\n", originalMode)
		fmt.Fprintf(os.Stderr, "Using default mode 'all'.\n\n")
	}

	if *vclServiceID != "" && *importMode != "all" {
		fmt.Fprintf(os.Stderr, "Warning: -vcl-service-id flag is only applicable with -import all mode and will be ignored.\n")
	}

	fmt.Printf("Import mode: %s\n", *importMode)

	// --- 1. Initialize Fastly Client ---
	apiToken := os.Getenv("FASTLY_API_KEY")
	if apiToken == "" {
		log.Fatal("FASTLY_API_KEY environment variable not set. Please set it before running the program.")
	}

	client, err := fastly.NewClient(apiToken)
	if err != nil {
		log.Fatalf("Error creating Fastly client: %v", err)
	}

	// --- 2. Generate Terraform Import File ---
	hclFile := hclwrite.NewEmptyFile()
	rootBody := hclFile.Body()
	importCount := 0

	// Declare variables for resources that will be shown in the summary
	var services []*fastly.Service

	// --- 3. Process Resources Based on Import Mode ---
	switch *importMode {
	case "all":
		// --- 3a. List All Services ---
		listServicesInput := &fastly.ListServicesInput{}

		fmt.Println("Fetching Fastly services...")
		var err error
		services, err = client.ListServices(context.Background(), listServicesInput)
		if err != nil {
			log.Fatalf("Error listing Fastly services: %v", err)
		}

		// If a specific VCL service ID was requested, filter to only that service
		if *vclServiceID != "" {
			services, err = filterServicesByVCLServiceID(services, *vclServiceID)
			if err != nil {
				log.Fatalf("Error filtering services by VCL service ID: %v", err)
			}
			fmt.Printf("Filtered to VCL service ID: %s\n", *vclServiceID)
		}

		if len(services) == 0 {
			fmt.Println("No Fastly services found for this account.")
		} else {
			fmt.Printf("Found %d Fastly service(s). Adding to import.tf...\n", len(services))

			// Process Fastly services (VCL, Compute) and their dynamic snippets
			for _, service := range services { // service is of type *fastly.Service
				var serviceIDValue string
				// The fastly.Service struct (from ListServices) has a 'ServiceID *string `mapstructure:"id"`' field.
				if service.ServiceID != nil {
					serviceIDValue = *service.ServiceID
				}

				var serviceName string
				if service.Name != nil {
					serviceName = *service.Name
				}

				var serviceType string
				if service.Type != nil {
					serviceType = *service.Type
				}

				if serviceIDValue == "" {
					log.Printf("Skipping service with empty ID (Name: %s)\n", serviceName)
					continue
				}

				// Sanitize the service name for the Terraform resource
				tfServiceResourceName := sanitizeForTerraformResourceName(serviceName, "service")
				if serviceName == "" || tfServiceResourceName == "service_unnamed" || tfServiceResourceName == "service_sanitized_empty" {
					// If original service name was empty or problematic, use sanitized ID for a more stable name
					sanitizedIDForName := sanitizeForTerraformResourceName(serviceIDValue, "svc")
					tfServiceResourceName = fmt.Sprintf("service_%s", sanitizedIDForName)
				}

				// Create the import block for the service itself
				serviceImportBlock := rootBody.AppendNewBlock("import", nil)
				serviceImportBody := serviceImportBlock.Body()
				serviceImportBody.SetAttributeValue("id", cty.StringVal(serviceIDValue))

				var tfResourceType string
				switch serviceType {
				case "vcl":
					tfResourceType = "fastly_service_vcl"
				case "wasm":
					tfResourceType = "fastly_service_compute"
				default:
					log.Printf("Warning: Unknown service type '%s' for service ID %s. Defaulting to 'fastly_service_vcl' for import block. Please verify.", serviceType, serviceIDValue)
					os.Exit(-1)
				}

				serviceImportBody.SetAttributeTraversal("to", hcl.Traversal{
					hcl.TraverseRoot{Name: tfResourceType},
					hcl.TraverseAttr{Name: tfServiceResourceName},
				})
				rootBody.AppendNewline()
				importCount++

				if serviceType == "vcl" {
					fmt.Printf("Processing VCL service: %s (ID: %s) for dynamic snippets...\n", serviceName, serviceIDValue)

					serviceDetails, err := client.GetService(context.Background(), &fastly.GetServiceInput{ServiceID: serviceIDValue})
					if err != nil {
						log.Printf("Error fetching service details for service ID %s: %v. Skipping dynamic snippets.", serviceIDValue, err)
						continue
					}

					var activeVersionNumber int
					foundActiveVersion := false

					var activeVersionData *int
					if serviceDetails.ActiveVersion != nil {
						activeVersionData = serviceDetails.ActiveVersion
						if activeVersionData != nil {
							activeVersionNumber = *activeVersionData
							foundActiveVersion = true
							fmt.Printf("  Found active version %d via serviceDetails.ActiveVersion.Number field.\n", activeVersionNumber)
						}
					}

					if !foundActiveVersion && serviceDetails.Versions != nil && len(serviceDetails.Versions) > 0 {
						fmt.Printf("  ActiveVersion field not directly populated or its Number is nil. Iterating %d versions to find active one.\n", len(serviceDetails.Versions))
						latestVersionNumber := 0
						for _, v := range serviceDetails.Versions {
							var vNum int
							if v.Number != nil {
								vNum = *v.Number
							} else {
								continue
							}

							if vNum > latestVersionNumber {
								latestVersionNumber = vNum
							}
							if v.Active != nil && *v.Active {
								activeVersionNumber = vNum
								foundActiveVersion = true
								fmt.Printf("    Found active version %d by iteration.\n", activeVersionNumber)
								break
							}
						}
						if !foundActiveVersion {
							log.Printf("  No active version found by iterating for service ID %s. Skipping dynamic snippets.", serviceIDValue)
							continue
						}
					} else if !foundActiveVersion {
						log.Printf("  No version information (neither ActiveVersion with Number nor Versions slice) found for service ID %s. Skipping dynamic snippets.", serviceIDValue)
						continue
					}

					if !foundActiveVersion {
						log.Printf("  Could not determine an active version for service ID %s after all checks. Skipping dynamic snippets.", serviceIDValue)
						continue
					}

					allSnippets, err := client.ListSnippets(context.Background(), &fastly.ListSnippetsInput{
						ServiceID:      serviceIDValue,
						ServiceVersion: activeVersionNumber,
					})
					if err != nil {
						log.Printf("  Error listing all snippets for service ID %s, version %d: %v", serviceIDValue, activeVersionNumber, err)
						continue
					}

					dynamicSnippetsFoundCount := 0
					for _, listedSnippet := range allSnippets { // listedSnippet is *fastly.Snippet

						isDynamic := false
						if listedSnippet.Dynamic != nil {
							if *listedSnippet.Dynamic == 1 { // 1 indicates a dynamic snippet
								isDynamic = true
							}
						}

						if isDynamic {
							dynamicSnippetsFoundCount++
							var currentSnippetID string
							if listedSnippet.SnippetID != nil { // fastly.Snippet uses 'SnippetID *string `mapstructure:"id"`'
								currentSnippetID = *listedSnippet.SnippetID
							}

							var currentSnippetName string
							if listedSnippet.Name != nil {
								currentSnippetName = *listedSnippet.Name
							}

							if currentSnippetID == "" {
								log.Printf("    Skipping dynamic snippet with empty ID (Name: %s) for service ID %s", currentSnippetName, serviceIDValue)
								continue
							}

							// Sanitize the original snippet name for the base part of the resource name
							tfBaseSnippetResourceName := sanitizeForTerraformResourceName(currentSnippetName, "snippet")
							if currentSnippetName == "" || tfBaseSnippetResourceName == "snippet_unnamed" || tfBaseSnippetResourceName == "snippet_sanitized_empty" {
								// If original snippet name is problematic, use its sanitized ID as part of base name
								sanitizedSnippetIDForBaseName := sanitizeForTerraformResourceName(currentSnippetID, "snipid")
								tfBaseSnippetResourceName = fmt.Sprintf("snippet_%s", sanitizedSnippetIDForBaseName)
							}

							// The import ID for fastly_service_dynamic_snippet_content is "service_id/snippet_id"
							importIDValue := fmt.Sprintf("%s/%s", serviceIDValue, currentSnippetID)

							// Sanitize the full importIDValue (e.g., "service123/snippetABC" -> "service123_snippetabc")
							// This part will be appended to make the Terraform resource name unique.
							sanitizedImportIDPart := sanitizeForTerraformResourceName(importIDValue, "ref")

							// Combine to form the final Terraform resource name.
							// e.g., "my_snippet_name_service123_snippetabc"
							finalTfResourceName := fmt.Sprintf("%s_%s", tfBaseSnippetResourceName, sanitizedImportIDPart)

							importBlock := rootBody.AppendNewBlock("import", nil)
							importBody := importBlock.Body()
							importBody.SetAttributeValue("id", cty.StringVal(importIDValue)) // This is the actual ID Fastly uses

							// Construct the 'to' attribute:
							// e.g., fastly_service_dynamic_snippet_content.my_snippet_name_sanitized_service_id_sanitized_snippet_id
							importBody.SetAttributeTraversal("to", hcl.Traversal{
								hcl.TraverseRoot{Name: "fastly_service_dynamic_snippet_content"},
								hcl.TraverseAttr{Name: finalTfResourceName},
							})
							rootBody.AppendNewline()
							importCount++
							fmt.Printf("    Added import for dynamic snippet: %s (Import ID: %s) as fastly_service_dynamic_snippet_content.%s\n", currentSnippetName, importIDValue, finalTfResourceName)
						}
					}
					if dynamicSnippetsFoundCount > 0 {
						fmt.Printf("  Processed %d snippets and found %d dynamic snippets for service %s (version %d).\n", len(allSnippets), dynamicSnippetsFoundCount, serviceName, activeVersionNumber)
					} else {
						fmt.Printf("  Processed %d snippets. No snippets with Dynamic flag set found for service %s (version %d).\n", len(allSnippets), serviceName, activeVersionNumber)
					}
				}
			}
		}

		// --- 3b. Process Service-Scoped Resources ---
		// Import service domains for all services
		serviceDomainImportCount, err := importServiceDomains(client, rootBody, services)
		if err == nil {
			importCount += serviceDomainImportCount
		}

		// Import service ACLs for VCL services
		serviceACLImportCount, err := importServiceACLs(client, rootBody, services)
		if err == nil {
			importCount += serviceACLImportCount
		}

		// Import service dictionaries for VCL services
		serviceDictImportCount, err := importServiceDictionaries(client, rootBody, services)
		if err == nil {
			importCount += serviceDictImportCount
		}

		// Import service backends for all services
		serviceBackendImportCount, err := importServiceBackends(client, rootBody, services)
		if err == nil {
			importCount += serviceBackendImportCount
		}

		// Import service health checks for all services
		serviceHealthCheckImportCount, err := importServiceHealthChecks(client, rootBody, services)
		if err == nil {
			importCount += serviceHealthCheckImportCount
		}

		// Import service directors for VCL services
		serviceDirectorImportCount, err := importServiceDirectors(client, rootBody, services)
		if err == nil {
			importCount += serviceDirectorImportCount
		}

		// Import service request settings for all services
		serviceRequestSettingImportCount, err := importServiceRequestSettings(client, rootBody, services)
		if err == nil {
			importCount += serviceRequestSettingImportCount
		}

		// Import service response objects for all services
		serviceResponseObjectImportCount, err := importServiceResponseObjects(client, rootBody, services)
		if err == nil {
			importCount += serviceResponseObjectImportCount
		}

		// Import service static VCL snippets for VCL services
		serviceStaticSnippetImportCount, err := importServiceStaticSnippets(client, rootBody, services)
		if err == nil {
			importCount += serviceStaticSnippetImportCount
		}

		// Import service VCL files for VCL services
		serviceVCLImportCount, err := importServiceVCLs(client, rootBody, services)
		if err == nil {
			importCount += serviceVCLImportCount
		}

		// --- 3c. Process Service Logging Resources ---
		// Import S3 logging endpoints for all services
		serviceS3LogImportCount, err := importServiceS3Logging(client, rootBody, services)
		if err == nil {
			importCount += serviceS3LogImportCount
		}

		// Import Syslog logging endpoints for all services
		serviceSyslogImportCount, err := importServiceSyslogLogging(client, rootBody, services)
		if err == nil {
			importCount += serviceSyslogImportCount
		}

		// Import Datadog logging endpoints for all services
		serviceDatadogImportCount, err := importServiceDatadogLogging(client, rootBody, services)
		if err == nil {
			importCount += serviceDatadogImportCount
		}

		// Import BigQuery logging endpoints for all services
		serviceBigQueryImportCount, err := importServiceBigQueryLogging(client, rootBody, services)
		if err == nil {
			importCount += serviceBigQueryImportCount
		}

		// Import Splunk logging endpoints for all services
		serviceSplunkImportCount, err := importServiceSplunkLogging(client, rootBody, services)
		if err == nil {
			importCount += serviceSplunkImportCount
		}

		// Import Papertrail logging endpoints for all services
		servicePapertrailImportCount, err := importServicePapertrailLogging(client, rootBody, services)
		if err == nil {
			importCount += servicePapertrailImportCount
		}

		// --- 4. Process Store Resources ---
		configStoreImportCount, err := importConfigStores(client, rootBody)
		if err == nil {
			importCount += configStoreImportCount
		}

		kvStoreImportCount, err := importKVStores(client, rootBody)
		if err == nil {
			importCount += kvStoreImportCount
		}

		secretStoreImportCount, err := importSecretStores(client, rootBody)
		if err == nil {
			importCount += secretStoreImportCount
		}

		// --- 5. Process TLS Resources ---
		tlsSubscriptionImportCount, err := importTLSSubscriptions(client, rootBody)
		if err == nil {
			importCount += tlsSubscriptionImportCount
		}

		tlsActivationImportCount, err := importTLSActivations(client, rootBody)
		if err == nil {
			importCount += tlsActivationImportCount
		}

		tlsCertificateImportCount, err := importTLSCertificates(client, rootBody)
		if err == nil {
			importCount += tlsCertificateImportCount
		}

		tlsConfigurationImportCount, err := importTLSConfigurations(client, rootBody)
		if err == nil {
			importCount += tlsConfigurationImportCount
		}

		tlsPrivateKeyImportCount, err := importTLSPrivateKeys(client, rootBody)
		if err == nil {
			importCount += tlsPrivateKeyImportCount
		}

		// --- 6. Process User and Authorization Resources ---
		userImportCount, err := importUsers(client, rootBody)
		if err == nil {
			importCount += userImportCount
		}

		serviceAuthorizationImportCount, err := importServiceAuthorizations(client, rootBody)
		if err == nil {
			importCount += serviceAuthorizationImportCount
		}

		// --- 7. Process NGWAF Resources ---
		// Skip NGWAF imports when scoped to a single VCL service via -vcl-service-id,
		// since NGWAF settings are account/workspace-level resources, not service-specific.
		var ngwafWorkspaces *workspaces.Workspaces
		var ngwafLists *lists.Lists
		var ngwafRules *rules.Rules
		var ngwafSignals *signals.Signals
		if *vclServiceID == "" {
			var workspaceImportCount int
			ngwafWorkspaces, workspaceImportCount, err = importNGWAFWorkspaces(client, rootBody)
			if err == nil {
				importCount += workspaceImportCount
			}

			var listsImportCount int
			ngwafLists, listsImportCount, err = importNGWAFAccountLists(client, rootBody)
			if err == nil {
				importCount += listsImportCount
			}

			var rulesImportCount int
			ngwafRules, rulesImportCount, err = importNGWAFAccountRules(client, rootBody)
			if err == nil {
				importCount += rulesImportCount
			}

			var signalsImportCount int
			ngwafSignals, signalsImportCount, err = importNGWAFAccountSignals(client, rootBody)
			if err == nil {
				importCount += signalsImportCount
			}

			// Import workspace-scoped lists, rules, and signals
			workspaceListsImportCount, err := importNGWAFWorkspaceLists(client, rootBody, ngwafWorkspaces)
			if err == nil {
				importCount += workspaceListsImportCount
			}

			workspaceRulesImportCount, err := importNGWAFWorkspaceRules(client, rootBody, ngwafWorkspaces)
			if err == nil {
				importCount += workspaceRulesImportCount
			}

			workspaceSignalsImportCount, err := importNGWAFWorkspaceSignals(client, rootBody, ngwafWorkspaces)
			if err == nil {
				importCount += workspaceSignalsImportCount
			}

			workspaceScopedImportCount, err := importNGWAFWorkspaceScopedResources(client, rootBody, ngwafWorkspaces)
			if err == nil {
				importCount += workspaceScopedImportCount
			}
		} else {
			fmt.Println("\nSkipping NGWAF imports because -vcl-service-id is set.")
		}

		outputPath := "./import.tf"
		err = os.WriteFile(outputPath, hclFile.Bytes(), 0644)
		if err != nil {
			log.Fatalf("Error writing import.tf file: %v", err)
		}

		fmt.Printf("\nSuccessfully generated %s with %d import block(s).\n", outputPath, importCount)

		// --- Summary Sections (for reference) ---
		if *importMode == "all" && len(services) > 0 {
			fmt.Println("\n--- Service Details Summary (for reference) ---")
			fmt.Println("------------------------------------")
			for i, service := range services {
				fmt.Printf("Service %d:\n", i+1)
				var id, name, typeStr string
				if service.ServiceID != nil {
					id = *service.ServiceID
				}
				if service.Name != nil {
					name = *service.Name
				}
				if service.Type != nil {
					typeStr = *service.Type
				}
				fmt.Printf("  ID:   %s\n", id)
				fmt.Printf("  Name: %s\n", name)
				fmt.Printf("  Type: %s\n", typeStr)
				fmt.Println("------------------------------------")
			}
		}

		// Add NGWAF workspace summary
		if ngwafWorkspaces != nil && len(ngwafWorkspaces.Data) > 0 {
			fmt.Println("\n--- NGWAF Workspace Details Summary (for reference) ---")
			fmt.Println("------------------------------------")
			for i, workspace := range ngwafWorkspaces.Data {
				fmt.Printf("NGWAF Workspace %d:\n", i+1)
				fmt.Printf("  ID:          %s\n", workspace.WorkspaceID)
				fmt.Printf("  Name:        %s\n", workspace.Name)
				fmt.Printf("  Description: %s\n", workspace.Description)
				fmt.Printf("  Mode:        %s\n", workspace.Mode)
				fmt.Println("------------------------------------")
			}
		}

		// Add NGWAF account lists summary
		if ngwafLists != nil && len(ngwafLists.Data) > 0 {
			fmt.Println("\n--- NGWAF Account Lists Summary (for reference) ---")
			fmt.Println("------------------------------------")
			for i, list := range ngwafLists.Data {
				fmt.Printf("NGWAF Account List %d:\n", i+1)
				fmt.Printf("  ID:          %s\n", list.ListID)
				fmt.Printf("  Name:        %s\n", list.Name)
				fmt.Printf("  Description: %s\n", list.Description)
				fmt.Printf("  Type:        %s\n", list.Type)
				fmt.Printf("  ReferenceID: %s\n", list.ReferenceID)
				fmt.Println("------------------------------------")
			}
		}

		// Add NGWAF account rules summary
		if ngwafRules != nil && len(ngwafRules.Data) > 0 {
			fmt.Println("\n--- NGWAF Account Rules Summary (for reference) ---")
			fmt.Println("------------------------------------")
			for i, rule := range ngwafRules.Data {
				fmt.Printf("NGWAF Account Rule %d:\n", i+1)
				fmt.Printf("  ID:              %s\n", rule.RuleID)
				fmt.Printf("  Description:     %s\n", rule.Description)
				fmt.Printf("  Type:            %s\n", rule.Type)
				fmt.Printf("  Enabled:         %t\n", rule.Enabled)
				fmt.Printf("  GroupOperator:   %s\n", rule.GroupOperator)
				fmt.Printf("  RequestLogging:  %s\n", rule.RequestLogging)
				fmt.Println("------------------------------------")
			}
		}

		// Add NGWAF account signals summary
		if ngwafSignals != nil && len(ngwafSignals.Data) > 0 {
			fmt.Println("\n--- NGWAF Account Signals Summary (for reference) ---")
			fmt.Println("------------------------------------")
			for i, signal := range ngwafSignals.Data {
				fmt.Printf("NGWAF Account Signal %d:\n", i+1)
				fmt.Printf("  ID:          %s\n", signal.SignalID)
				fmt.Printf("  Name:        %s\n", signal.Name)
				fmt.Printf("  Description: %s\n", signal.Description)
				fmt.Printf("  ReferenceID: %s\n", signal.ReferenceID)
				fmt.Println("------------------------------------")
			}
		}
	case "ngwaf":
		// Handle NGWAF import modes
		ngwafWorkspaces, workspaceImportCount, err := importNGWAFWorkspaces(client, rootBody)
		if err == nil {
			importCount += workspaceImportCount
		}

		ngwafLists, listsImportCount, err := importNGWAFAccountLists(client, rootBody)
		if err == nil {
			importCount += listsImportCount
		}

		ngwafRules, rulesImportCount, err := importNGWAFAccountRules(client, rootBody)
		if err == nil {
			importCount += rulesImportCount
		}

		ngwafSignals, signalsImportCount, err := importNGWAFAccountSignals(client, rootBody)
		if err == nil {
			importCount += signalsImportCount
		}

		// Import workspace-scoped lists, rules, and signals
		workspaceListsImportCount, err := importNGWAFWorkspaceLists(client, rootBody, ngwafWorkspaces)
		if err == nil {
			importCount += workspaceListsImportCount
		}

		workspaceRulesImportCount, err := importNGWAFWorkspaceRules(client, rootBody, ngwafWorkspaces)
		if err == nil {
			importCount += workspaceRulesImportCount
		}

		workspaceSignalsImportCount, err := importNGWAFWorkspaceSignals(client, rootBody, ngwafWorkspaces)
		if err == nil {
			importCount += workspaceSignalsImportCount
		}

		workspaceScopedImportCount, err := importNGWAFWorkspaceScopedResources(client, rootBody, ngwafWorkspaces)
		if err == nil {
			importCount += workspaceScopedImportCount
		}

		outputPath := "./import.tf"
		err = os.WriteFile(outputPath, hclFile.Bytes(), 0644)
		if err != nil {
			log.Fatalf("Error writing import.tf file: %v", err)
		}

		fmt.Printf("\nSuccessfully generated %s with %d import block(s).\n", outputPath, importCount)

		// --- Summary Sections (for reference) ---
		// Add NGWAF workspace summary
		if ngwafWorkspaces != nil && len(ngwafWorkspaces.Data) > 0 {
			fmt.Println("\n--- NGWAF Workspace Details Summary (for reference) ---")
			fmt.Println("------------------------------------")
			for i, workspace := range ngwafWorkspaces.Data {
				fmt.Printf("NGWAF Workspace %d:\n", i+1)
				fmt.Printf("  ID:          %s\n", workspace.WorkspaceID)
				fmt.Printf("  Name:        %s\n", workspace.Name)
				fmt.Printf("  Description: %s\n", workspace.Description)
				fmt.Printf("  Mode:        %s\n", workspace.Mode)
				fmt.Println("------------------------------------")
			}
		}

		// Add NGWAF account lists summary
		if ngwafLists != nil && len(ngwafLists.Data) > 0 {
			fmt.Println("\n--- NGWAF Account Lists Summary (for reference) ---")
			fmt.Println("------------------------------------")
			for i, list := range ngwafLists.Data {
				fmt.Printf("NGWAF Account List %d:\n", i+1)
				fmt.Printf("  ID:          %s\n", list.ListID)
				fmt.Printf("  Name:        %s\n", list.Name)
				fmt.Printf("  Description: %s\n", list.Description)
				fmt.Printf("  Type:        %s\n", list.Type)
				fmt.Printf("  ReferenceID: %s\n", list.ReferenceID)
				fmt.Println("------------------------------------")
			}
		}

		// Add NGWAF account rules summary
		if ngwafRules != nil && len(ngwafRules.Data) > 0 {
			fmt.Println("\n--- NGWAF Account Rules Summary (for reference) ---")
			fmt.Println("------------------------------------")
			for i, rule := range ngwafRules.Data {
				fmt.Printf("NGWAF Account Rule %d:\n", i+1)
				fmt.Printf("  ID:              %s\n", rule.RuleID)
				fmt.Printf("  Description:     %s\n", rule.Description)
				fmt.Printf("  Type:            %s\n", rule.Type)
				fmt.Printf("  Enabled:         %t\n", rule.Enabled)
				fmt.Printf("  GroupOperator:   %s\n", rule.GroupOperator)
				fmt.Printf("  RequestLogging:  %s\n", rule.RequestLogging)
				fmt.Println("------------------------------------")
			}
		}

		// Add NGWAF account signals summary
		if ngwafSignals != nil && len(ngwafSignals.Data) > 0 {
			fmt.Println("\n--- NGWAF Account Signals Summary (for reference) ---")
			fmt.Println("------------------------------------")
			for i, signal := range ngwafSignals.Data {
				fmt.Printf("NGWAF Account Signal %d:\n", i+1)
				fmt.Printf("  ID:          %s\n", signal.SignalID)
				fmt.Printf("  Name:        %s\n", signal.Name)
				fmt.Printf("  Description: %s\n", signal.Description)
				fmt.Printf("  ReferenceID: %s\n", signal.ReferenceID)
				fmt.Println("------------------------------------")
			}
		}
	default:
		// Handle default import mode
		fmt.Printf("Import mode '%s' is not recognized. Supported modes are 'all' and 'ngwaf'.\n", *importMode)
	}
}
