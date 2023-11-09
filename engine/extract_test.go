package engine

import (
	"encoding/json"
	"fmt"
	"testing"
)

var (
	black = "blacklist"

	// key: extract, value: test string
	extractMap = map[string]string{
		fmt.Sprintf("extract('MD5=(?P<md5>[A-F0-9]{32})', Hashes) in %s", black):         "SHA1=AAE17944782B25F41F7B3A756532B4923F4AE817,MD5=6C60B5ACA7442EFB794082CDACFC001C,SHA256=FC1D9124856A70FF232EF3057D66BEE803295847624CE23B4D0217F23AF52C75,IMPHASH=FAAD2D5BF5C0CA9639E07A49E8C5D8AE",
		fmt.Sprintf("extract('SHA1=(?P<sha1>[A-F0-9]{40})', Hashes) in %s", black):       "SHA1=AAE17944782B25F41F7B3A756532B4923F4AE817,MD5=6C60B5ACA7442EFB794082CDACFC001C,SHA256=FC1D9124856A70FF232EF3057D66BEE803295847624CE23B4D0217F23AF52C75,IMPHASH=FAAD2D5BF5C0CA9639E07A49E8C5D8AE",
		fmt.Sprintf("extract('SHA256=(?P<sha256>[A-F0-9]{64})', Hashes) in %s", black):   "SHA1=AAE17944782B25F41F7B3A756532B4923F4AE817,MD5=6C60B5ACA7442EFB794082CDACFC001C,SHA256=FC1D9124856A70FF232EF3057D66BEE803295847624CE23B4D0217F23AF52C75,IMPHASH=FAAD2D5BF5C0CA9639E07A49E8C5D8AE",
		fmt.Sprintf("extract('IMPHASH=(?P<imphash>[A-F0-9]{32})', Hashes) in %s", black): "SHA1=AAE17944782B25F41F7B3A756532B4923F4AE817,MD5=6C60B5ACA7442EFB794082CDACFC001C,SHA256=FC1D9124856A70FF232EF3057D66BEE803295847624CE23B4D0217F23AF52C75,IMPHASH=FAAD2D5BF5C0CA9639E07A49E8C5D8AE",
	}
)

func TestExtract(t *testing.T) {
	for ext, test := range extractMap {
		ae, err := parseContainerMatch("$inTest", ext, &TypeWinevt)
		if err != nil {
			t.Logf("Failed to parse extract: %s", err)
			t.Fail()
		} else {
			t.Logf("Parsed extract: %s", ae)
			err = ae.compile()
			if err != nil {
				t.Logf("Failed to compile: %s", err)
				t.Fail()
				continue
			}
			if v, ok := ae.ExtractFromString(test); ok {
				t.Logf("Extracted value: %s", v)
			} else {
				t.Logf("Failed to extract value")
				t.Fail()
			}
		}

	}
}

func TestExtractContainerName(t *testing.T) {
	template := "extract('MD5=(?P<md5>[A-F0-9]{32})', Hashes) in %s"
	names := []string{
		"container-a",
		"container_b",
		"container.c",
	}

	for _, n := range names {
		atom := fmt.Sprintf(template, n)
		if cm, err := parseContainerMatch("$inTest", atom, &TypeWinevt); err != nil {
			t.Error(err)
		} else {
			if cm.Container != n {
				t.Errorf("Failed to parse container name, expecting \"%s\", got \"%s\"", n, cm.Container)
			}
		}

	}

}

func TestExtractFromEvent(t *testing.T) {
	eJSON := `{"Event":{"EventData":{"Company":"Microsoft Corporation","Description":"Microsoft OLE for Windows","FileVersion":"6.1.7600.16385 (win7_rtm.090713-1255)","Hashes":"SHA1=AAE17944782B25F41F7B3A756532B4923F4AE817,MD5=6C60B5ACA7442EFB794082CDACFC001C,SHA256=FC1D9124856A70FF232EF3057D66BEE803295847624CE23B4D0217F23AF52C75,IMPHASH=FAAD2D5BF5C0CA9639E07A49E8C5D8AE","Image":"C:\\Windows\\System32\\mcbuilder.exe","ImageLoaded":"C:\\Windows\\System32\\ole32.dll","ProcessGuid":"{49F1AF32-39CC-5A94-0000-0010706A1200}","ProcessId":"572","Product":"Microsoft® Windows® Operating System","Signature":"Microsoft Windows","SignatureStatus":"Valid","Signed":"true","UtcTime":"2018-02-26 16:46:06.836"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA02.caldera.loc","Correlation":{},"EventID":"7","EventRecordID":"822149","Execution":{"ProcessID":"1464","ThreadID":"1680"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"7","TimeCreated":{"SystemTime":"2018-02-26T16:46:06.851842000Z"},"Version":"3"}}}`
	evt := GenericEvent{}
	err := json.Unmarshal([]byte(eJSON), &evt)
	if err != nil {
		panic(err)
	}
	for ext := range extractMap {
		ae, err := parseContainerMatch("$inTest", ext, &TypeWinevt)
		if err != nil {
			t.Logf("Failed to parse extract: %s", err)
			t.Fail()
		} else {
			t.Logf("Parsed extract: %s", ae)
			err = ae.compile()
			if err != nil {
				t.Logf("Failed to compile: %s", err)
				t.Fail()
				continue
			}
			if v, ok := ae.Extract(&evt); ok {
				t.Logf("Extracted value: %s", v)
			} else {
				t.Logf("Failed to extract value")
				t.Fail()
			}
		}
	}
}

func TestExtractMatch(t *testing.T) {
	eJSON := `{"Event":{"EventData":{"Company":"Microsoft Corporation","Description":"Microsoft OLE for Windows","FileVersion":"6.1.7600.16385 (win7_rtm.090713-1255)","Hashes":"SHA1=AAE17944782B25F41F7B3A756532B4923F4AE817,MD5=6C60B5ACA7442EFB794082CDACFC001C,SHA256=FC1D9124856A70FF232EF3057D66BEE803295847624CE23B4D0217F23AF52C75,IMPHASH=FAAD2D5BF5C0CA9639E07A49E8C5D8AE","Image":"C:\\Windows\\System32\\mcbuilder.exe","ImageLoaded":"C:\\Windows\\System32\\ole32.dll","ProcessGuid":"{49F1AF32-39CC-5A94-0000-0010706A1200}","ProcessId":"572","Product":"Microsoft® Windows® Operating System","Signature":"Microsoft Windows","SignatureStatus":"Valid","Signed":"true","UtcTime":"2018-02-26 16:46:06.836"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA02.caldera.loc","Correlation":{},"EventID":"7","EventRecordID":"822149","Execution":{"ProcessID":"1464","ThreadID":"1680"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"7","TimeCreated":{"SystemTime":"2018-02-26T16:46:06.851842000Z"},"Version":"3"}}}`
	containers := NewContainers()
	//containers.AddNewContainer(black)
	containers.AddStringToContainer(black, "6C60B5ACA7442EFB794082CDACFC001C")
	containers.AddStringToContainer(black, "AAE17944782B25F41F7B3A756532B4923F4AE817")
	containers.AddStringToContainer(black, "FC1D9124856A70FF232EF3057D66BEE803295847624CE23B4D0217F23AF52C75")
	containers.AddStringToContainer(black, "FAAD2D5BF5C0CA9639E07A49E8C5D8AE")
	t.Log(containers)

	evt := GenericEvent{}
	err := json.Unmarshal([]byte(eJSON), &evt)
	if err != nil {
		panic(err)
	}
	for ext := range extractMap {
		ae, err := parseContainerMatch("$inTest", ext, &TypeWinevt)
		if err != nil {
			t.Logf("Failed to parse extract: %s", err)
			t.Fail()
		} else {
			t.Logf("Parsed extract: %s", ae)
			err = ae.compile()
			if err != nil {
				t.Logf("Failed to compile: %s", err)
				t.Fail()
				continue
			}
			ae.setContainerDB(containers)
			if !ae.match(&evt) {
				t.Logf("Not matching: %s", ae)
				t.Fail()
			}
		}
	}

}
