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

rerun:
	make clean
	make run
