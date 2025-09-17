# - rm -r .terraform*
# - rm *.tfstate*
# - rm *.tfstate.backup

clean:
	- rm generated.tf
	- rm import.tf

build:
	- terraform init

run:
	go run .
	- terraform plan -generate-config-out=generated.tf

rengwaf:
	make clean
	go build -o fastly-terraformer
	./fastly-terraformer -import ngwaf
	- terraform plan -generate-config-out=generated.tf

rerun:
	make clean
	make run
