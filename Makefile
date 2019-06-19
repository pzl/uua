TARGETS=$(notdir $(wildcard cmd/*))

all: build

build: $(TARGETS:%=bin/%)

bin/% : cmd/% cmd/%/*
	go build -o $@ ./$<

static:
	CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags '-w' -o bin/uua ./cmd/uua/
	CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags '-w' -o bin/mkpass ./cmd/mkpass/

pass:
	./bin/mkpass

key:
	openssl req -x509 -nodes -newkey rsa:2048 -keyout server.key -out server.crt -days 3650

.PHONY: all build static clean key pass

clean:
	$(RM) -rf bin/*
