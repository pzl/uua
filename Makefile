TARGETS=$(notdir $(wildcard cmd/*))

all: build

build: $(TARGETS:%=bin/%)

bin/% : cmd/% cmd/%/*
	go build -o $@ ./$<

#  todo: release targets  GOOS=X GOARCH=amd64 (usually) CGO_ENABLED=0

.PHONY: all build clean

clean:
	$(RM) -rf bin/*
