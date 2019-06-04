RELEASE=$(GOPATH)/release
MAIN_BASEN_SRC=gene
VERSION=1.5.0
COMMITID=$(shell git rev-parse HEAD)
# Strips symbols and dwarf to make binary smaller
OPTS=-ldflags "-s -w"
ifdef DEBUG
	OPTS=
endif

all:
	$(MAKE) clean
	$(MAKE) init
	$(MAKE) buildversion
	$(MAKE) compile

init:
	mkdir -p $(RELEASE)
	mkdir -p $(RELEASE)/linux
	mkdir -p $(RELEASE)/windows
	mkdir -p $(RELEASE)/darwin

compile:linux windows darwin

buildversion:
	printf "package main\n\nconst(\n    version=\"$(VERSION)\"\n    commitID=\"$(COMMITID)\"\n)\n" > version.go

linux:
	GOARCH=386 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-386 ./
	GOARCH=amd64 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-amd64 ./
	cd $(RELEASE)/linux; md5sum * > md5.txt
	cd $(RELEASE)/linux; tar -cvzf ../linux-$(VERSION).tar.gz *

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-386.exe ./
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-amd64.exe ./
	cd $(RELEASE)/windows; md5sum * > md5.txt
	cd $(RELEASE)/windows; tar -cvzf ../windows-$(VERSION).tar.gz *

darwin:
	GOARCH=386 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-386 ./
	GOARCH=amd64 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-amd64 ./
	cd $(RELEASE)/darwin; md5sum * > md5.txt
	cd $(RELEASE)/darwin; tar -cvzf ../darwin-$(VERSION).tar.gz *

clean:
	rm -rf $(RELEASE)/*
