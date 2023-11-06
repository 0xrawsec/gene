RELEASE=target
MAIN_BASEN_SRC=gene
VERSION=$(shell git describe --tags --abbrev=0)
COMMITID=$(shell git rev-parse HEAD)

LD_SET_VARS=-X main.commitID=$(COMMITID) -X main.version=$(VERSION)
# Strips symbols and dwarf to make binary smaller
OPTS=-trimpath -ldflags "-s -w $(LD_SET_VARS)"
ifdef DEBUG
	OPTS=-ldflags "$(LD_SET_VARS)"
endif

all:
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
	go build $(OPTS) -o $(RELEASE)

linux:
	GOARCH=386 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-386 ./
	GOARCH=amd64 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-amd64 ./
	cd $(RELEASE)/linux; md5sum * > md5.txt
	cd $(RELEASE)/linux; tar -cvzf ../$(MAIN_BASEN_SRC)-linux-$(VERSION).tar.gz *

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-386.exe ./
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-amd64.exe ./
	cd $(RELEASE)/windows; md5sum * > md5.txt
	cd $(RELEASE)/windows; 7z a -tzip ../$(MAIN_BASEN_SRC)-windows-$(VERSION).zip *

darwin:
	GOARCH=amd64 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-amd64 ./
	cd $(RELEASE)/darwin; md5sum * > md5.txt
	cd $(RELEASE)/darwin; tar -cvzf ../$(MAIN_BASEN_SRC)-darwin-$(VERSION).tar.gz *

ci-build: buildversion
	go build $(OPTS) -o $(shell mktemp) ./

clean:
	rm -rf $(RELEASE)/*