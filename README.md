# fastly-terraformer

This repo builds the Terraform configuration and imports the remote state for Fastly Edge resources.

Things that somewhat work so far.
- [x] VCL Services
- [x] Compute Services
- [x] Dynamic Snippets

Things that DO **NOT** work with this tool so far.
- [ ] Just about anything else not explicitly mentioned above.
- [ ] NGWAF Settings. See [sigsci-ngwaf-terraformer](https://github.com/fastly/sigsci-ngwaf-terraformer/tree/main) for that work.
- [ ] VCL Dictionaries

# Quickstart

```
export FASTLY_TF_DISPLAY_SENSITIVE_FIELDS="true"
make rerun
```


*Note* This will set the following environment variable which is needed to generate otherwise sensitive Terraform fields for the Fastly provider. `FASTLY_TF_DISPLAY_SENSITIVE_FIELDS="true"`