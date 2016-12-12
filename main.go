package main

import (
	"flag"
	"fmt"
	"net/http"
	"regexp"

	"log"

	"encoding/json"

	"strings"

	xmlpath "gopkg.in/xmlpath.v2"
)

type report struct {
	ID                                                                     string
	URL                                                                    string
	HTML                                                                   string
	Category, Started, Completed, Duration                                 string
	Error                                                                  string
	FileName, FileSize, FileType, MD5, SHA1, SHA256, SHA512, CRC32, SSDEEP string
	YARA                                                                   []string
	Signatures                                                             []string
	Hosts                                                                  []string
	Domains                                                                []domain
	Files, RegistryKeys, Mutexes                                           []string
	VirusTotal                                                             []virustotal
	DroppedFiles                                                           []dropped
}

type domain struct {
	Domain, IP string
}

type virustotal struct {
	Score      string
	Detections struct{ AntiVirus, Detection string }
}

type dropped struct {
	FileName, FileSize, FileType, MD5, SHA1, SHA256, CRC32, SSDEEP string
	YARA                                                           string
}

func main() {
	reportID := flag.String("id", "", "malwr.com report id")
	flag.Parse()

	url := fmt.Sprintf("https://malwr.com/analysis/%s/", *reportID)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	request.Header.Set("user-agent", "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Mobile Safari/537.36")
	request.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	request.Header.Set("accept-language", "en-US,en;q=0.8,he;q=0.6")
	request.Header.Set("dnt", "1")
	request.Header.Set("host", "malwr.com")
	request.Header.Set("upgrade-insecure-requests", "1")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	var result report
	result.ID = *reportID
	result.URL = url
	// if bytesHTML, err := ioutil.ReadAll(response.Body); err == nil {
	// 	result.HTML = string(bytesHTML)
	// }

	xmlRoot, err := xmlpath.ParseHTML(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	var xpath *xmlpath.Path

	// Analysis
	for i := 1; i <= 9; i++ {
		xpath = xmlpath.MustCompile(fmt.Sprintf(`/html/body/div[@class='container-fluid']/div[@class='tabbable tabs-left']/div[@class='tab-content']/div[@id='overview']/section[@id='information']/div[@class='box']/div[@class='box-content']/table[@class='table table-striped']/tbody/tr/td[%d]`, i))
		if value, ok := xpath.String(xmlRoot); ok {
			switch i {
			case 1:
				result.Category = value
			case 2:
				result.Started = value
			case 3:
				result.Completed = value
			case 4:
				result.Duration = value
			}
		}
	}

	// Error
	xpath = xmlpath.MustCompile(`/html/body/div[@class='container-fluid']/div[@class='tabbable tabs-left']/div[@class='tab-content']/div[@id='overview']/section[@id='information']/ul/li[@class='text-error']`)
	if errorText, ok := xpath.String(xmlRoot); ok {
		result.Error = errorText
	}

	// File Details
	for i := 1; i <= 9; i++ {
		xpath = xmlpath.MustCompile(fmt.Sprintf(`/html/body/div[@class='container-fluid']/div[@class='tabbable tabs-left']/div[@class='tab-content']/div[@id='overview']/section[@id='file']/div[@class='box']/div[@class='box-content']/table[@class='table table-striped']/tbody/tr[%d]/td`, i))
		if value, ok := xpath.String(xmlRoot); ok {
			switch i {
			case 1:
				result.FileName = value
			case 2:
				result.FileSize = value
			case 3:
				result.FileType = value
			case 4:
				result.MD5 = value
			case 5:
				result.SHA1 = value
			case 6:
				result.SHA256 = value
			case 7:
				result.SHA512 = value
			case 8:
				result.CRC32 = value
			case 9:
				result.SSDEEP = value
			}
		}
	}

	// Files, Registry Keys, Mutexes
	for _, listType := range []string{"summary_keys", "summary_files", "summary_mutexes"} {
		xpath = xmlpath.MustCompile(fmt.Sprintf(`/html/body/div[@class='container-fluid']/div[@class='tabbable tabs-left']/div[@class='tab-content']/div[@id='overview']/section[@id='summary']/div[@class='tabbable tabs']/div[@class='tab-content']/div[@id='%s']/div[@class='well mono']`, listType))
		if listExtracted, ok := xpath.String(xmlRoot); ok {
			asArray := strings.Split(listExtracted, "\n")

			for _, asString := range asArray {
				asString = strings.Trim(asString, " \t")
				if len(asString) == 0 {
					continue
				}

				switch listType {
				case "summary_files":
					result.Files = append(result.Files, asString)
				case "summary_keys":
					result.RegistryKeys = append(result.RegistryKeys, asString)
				case "summary_mutexes":
					result.Mutexes = append(result.Mutexes, asString)
				}
			}
		}
	}

	// YARA
	xpath = xmlpath.MustCompile(`/html/body/div[@class='container-fluid']/div[@class='tabbable tabs-left']/div[@class='tab-content']/div[@id='overview']/section[@id='file']/div[@class='box']/div[@class='box-content']/table[@class='table table-striped']/tbody/tr[10]/td`)
	if yarasExtracted, ok := xpath.String(xmlRoot); ok {
		asArray := strings.Split(yarasExtracted, "\n")

		for _, asString := range asArray {
			asString = strings.Trim(asString, " \t")
			if len(asString) == 0 || asString == "None matched" {
				continue
			}

			result.YARA = append(result.YARA, asString)
		}
	}

	// Signatures
	xpath = xmlpath.MustCompile(`//section[@id='signatures']`)
	if signaturesExtracted, ok := xpath.String(xmlRoot); ok {
		asArray := strings.Split(signaturesExtracted, "\n")
		dozenSpacesAtStart := regexp.MustCompile(`^ {12}[^ ]`)

		for _, asString := range asArray {
			if dozenSpacesAtStart.MatchString(asString) {
				result.Signatures = append(result.Signatures, strings.Trim(asString, " "))
			}
		}
	}

	b, _ := json.MarshalIndent(result, "", "\t")
	fmt.Println(string(b))

}
