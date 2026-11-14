.PHONY: all generate build test sim install clean

all: build

generate:
	cd internal/sensor && go generate ./...

build: generate
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/warden ./cmd/warden

test:
	go vet ./... && go test ./...

# End-to-end: start warden with the test config, run benign attack
# simulations, check every expected rule fired.
sim: build
	sudo rm -rf /tmp/warden-test && mkdir -p /tmp/warden-test
	sudo ./bin/warden run -config tests/test-config.yaml > /tmp/warden-test/stdout.log 2>&1 & echo $$! > /tmp/warden-test/pid
	sleep 3
	./tests/simulate.sh > /tmp/warden-test/sim.log 2>&1 || true
	sleep 2
	sudo pkill -n -x warden || true
	sudo python3 tests/check.py /tmp/warden-test/sim.log /tmp/warden-test/alerts.jsonl

install: build
	./deploy/install.sh

clean:
	rm -rf bin
