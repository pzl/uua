TARGETS=$(notdir $(wildcard cmd/*))

all: build

build: $(TARGETS:%=bin/%)

bin/% : cmd/% cmd/%/*
	go build -o $@ ./$<

#  todo: release targets  GOOS=X GOARCH=amd64 (usually) CGO_ENABLED=0

pass:
	./bin/mkpass

key:
	openssl req -x509 -nodes -newkey rsa:2048 -keyout server.key -out server.crt -days 3650

.PHONY: all build clean key pass

clean:
	$(RM) -rf bin/*
