CA_URL := https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem

.PHONY: ca-bundle build deploy test
ca-bundle:            ## Download the RDS CA bundle so the Lambda can verify TLS
	mkdir -p src/rds-ca && curl -fsSL $(CA_URL) -o src/rds-ca/global-bundle.pem

build: ca-bundle
	sam build

deploy: build
	sam deploy --guided

test:
	pytest -q
