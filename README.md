# fastly-terraformer

This repo builds the Terraform configuration and imports the remote state for Fastly Edge resources.

Things that somewhat work so far.
- [x] VCL Services
- [x] Compute Services
- [x] Dynamic Snippets
- [x] NGWAF Workspaces
- [x] NGWAF Account Lists
- [x] NGWAF Account Rules
- [x] NGWAF Account Signals

# Quickstart

```
export FASTLY_TF_DISPLAY_SENSITIVE_FIELDS="true"
make rerun
```


*Note* This will set the following environment variable which is needed to generate otherwise sensitive Terraform fields for the Fastly provider. `FASTLY_TF_DISPLAY_SENSITIVE_FIELDS="true"`
