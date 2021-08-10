RELEASE=$(shell go env GOPATH)/release
MAIN_BASEN_SRC=gene
VERSION=$(shell git tag | sort -V | tail -1 | sed 's/^v//')
COMMITID=$(shell git rev-parse HEAD)

# Strips symbols and dwarf to make binary smaller
OPTS=-ldflags "-s -w"
ifdef DEBUG
	OPTS=
endif

all: buildversion
	$(MAKE) clean
	$(MAKE) init
	$(MAKE) compile

install: buildversion
	go install $(OPTS) ./

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
	cd $(RELEASE)/linux; tar -cvzf ../$(MAIN_BASEN_SRC)-linux-v$(VERSION).tar.gz *

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-386.exe ./
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-amd64.exe ./
	cd $(RELEASE)/windows; md5sum * > md5.txt
	#cd $(RELEASE)/windows; tar -cvzf ../$(MAIN_BASEN_SRC)-windows-$(VERSION).tar.gz *
	cd $(RELEASE)/windows; 7z a -tzip ../$(MAIN_BASEN_SRC)-windows-v$(VERSION).zip *

darwin:
	#GOARCH=386 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-386 ./
	GOARCH=amd64 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-amd64 ./
	cd $(RELEASE)/darwin; md5sum * > md5.txt
	cd $(RELEASE)/darwin; tar -cvzf ../$(MAIN_BASEN_SRC)-darwin-v$(VERSION).tar.gz *

clean:
	rm -rf $(RELEASE)/*
