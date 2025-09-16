package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	// IMPORTANT: Ensure your go.mod file correctly references github.com/fastly/go-fastly/v10
	// If errors persist, try running:
	// go clean -modcache
	// go get -u github.com/fastly/go-fastly/v11/fastly
	// go mod tidy
	"github.com/fastly/go-fastly/v11/fastly"
	"github.com/fastly/go-fastly/v11/fastly/ngwaf/v1/common"
	"github.com/fastly/go-fastly/v11/fastly/ngwaf/v1/lists"
	"github.com/fastly/go-fastly/v11/fastly/ngwaf/v1/rules"
	"github.com/fastly/go-fastly/v11/fastly/ngwaf/v1/signals"
	"github.com/fastly/go-fastly/v11/fastly/ngwaf/v1/workspaces"

	"github.com/hashicorp/hcl/v2"
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

func main() {
	// --- 1. Initialize Fastly Client ---
	apiToken := os.Getenv("FASTLY_API_TOKEN")
	if apiToken == "" {
		log.Fatal("FASTLY_API_TOKEN environment variable not set. Please set it before running the program.")
	}

	client, err := fastly.NewClient(apiToken)
	if err != nil {
		log.Fatalf("Error creating Fastly client: %v", err)
	}

	// --- 2. List All Services ---
	listServicesInput := &fastly.ListServicesInput{}

	fmt.Println("Fetching Fastly services...")
	services, err := client.ListServices(context.Background(), listServicesInput)
	if err != nil {
		log.Fatalf("Error listing Fastly services: %v", err)
	}

	if len(services) == 0 {
		fmt.Println("No Fastly services found for this account. No import.tf will be generated.")
		return
	}

	fmt.Printf("\nFound %d Fastly service(s). Generating import.tf...\n", len(services))

	// --- 3. Generate Terraform Import File ---
	hclFile := hclwrite.NewEmptyFile()
	rootBody := hclFile.Body()
	importCount := 0

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

	// --- 4. Process NGWAF Workspaces ---
	fmt.Println("\nFetching NGWAF workspaces...")
	ngwafWorkspaces, err := workspaces.List(context.Background(), client, &workspaces.ListInput{})
	if err != nil {
		log.Printf("Error listing NGWAF workspaces: %v. Skipping NGWAF workspace imports.", err)
	} else {
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
	}

	// --- 5. Process NGWAF Account Lists ---
	fmt.Println("\nFetching NGWAF account lists...")
	accountScope := &common.Scope{
		Type:      common.ScopeTypeAccount,
		AppliesTo: []string{"*"},
	}
	
	ngwafLists, err := lists.ListLists(context.Background(), client, &lists.ListInput{Scope: accountScope})
	if err != nil {
		log.Printf("Error listing NGWAF account lists: %v. Skipping NGWAF list imports.", err)
	} else {
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
	}

	// --- 6. Process NGWAF Account Rules ---
	fmt.Println("\nFetching NGWAF account rules...")
	
	ngwafRules, err := rules.List(context.Background(), client, &rules.ListInput{Scope: accountScope})
	if err != nil {
		log.Printf("Error listing NGWAF account rules: %v. Skipping NGWAF rule imports.", err)
	} else {
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
	}

	// --- 7. Process NGWAF Account Signals ---
	fmt.Println("\nFetching NGWAF account signals...")
	
	ngwafSignals, err := signals.List(context.Background(), client, &signals.ListInput{Scope: accountScope})
	if err != nil {
		log.Printf("Error listing NGWAF account signals: %v. Skipping NGWAF signal imports.", err)
	} else {
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
	}

	outputPath := "./import.tf"
	err = os.WriteFile(outputPath, hclFile.Bytes(), 0644)
	if err != nil {
		log.Fatalf("Error writing import.tf file: %v", err)
	}

	fmt.Printf("\nSuccessfully generated %s with %d import block(s).\n", outputPath, importCount)

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
}
