gatehouse: $(wildcard *.go) web/dist
	go build -o gatehouse .

web/dist: $(wildcard web/src/*) web/package.json
	cd web && npm ci && npm run build

test: web/dist
	go vet ./... && go test ./...

.PHONY: test
