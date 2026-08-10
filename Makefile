# - rm -r .terraform*
# - rm *.tfstate*
# - rm *.tfstate.backup

# To display sensitive fields in the generated terraform files, run the following command before executing 'make run'
# export FASTLY_TF_DISPLAY_SENSITIVE_FIELDS="true"

clean:
	- rm generated.tf
	- rm import.tf

build:
	- terraform init

run:
	go build -o fastly-terraformer
	./fastly-terraformer
	- terraform plan -generate-config-out=generated.tf

ngwaf:
	go build -o fastly-terraformer
	./fastly-terraformer -import ngwaf
	- terraform plan -generate-config-out=generated.tf

rengwaf:
	make clean
	make ngwaf

rerun:
	make clean
	make run
