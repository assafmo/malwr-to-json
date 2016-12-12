package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"

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
	includeHTML := flag.String("html", "false", "include html? (default=false)")
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

	var xmlRoot *xmlpath.Node
	if *includeHTML == "true" {
		if bytesHTML, err := ioutil.ReadAll(response.Body); err == nil {
			result.HTML = string(bytesHTML)
			xmlRoot, err = xmlpath.ParseHTML(strings.NewReader(result.HTML))
			if err != nil {
				log.Fatal(err)
			}
		}
	} else {
		xmlRoot, err = xmlpath.ParseHTML(response.Body)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Analysis
	for i := 1; i <= 9; i++ {
		xpath := xmlpath.MustCompile(fmt.Sprintf(`//section[@id='information']/div[@class='box']/div[@class='box-content']/table[@class='table table-striped']/tbody/tr/td[%d]`, i))
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
	xpath := xmlpath.MustCompile(`//section[@id='information']/ul/li[@class='text-error']`)
	if errorText, ok := xpath.String(xmlRoot); ok {
		result.Error = errorText
	}

	// File Details
	for i := 1; i <= 9; i++ {
		xpath := xmlpath.MustCompile(fmt.Sprintf(`//section[@id='file']/div[@class='box']/div[@class='box-content']/table[@class='table table-striped']/tbody/tr[%d]/td`, i))
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

	// YARA
	xpath = xmlpath.MustCompile(`//section[@id='file']/div[@class='box']/div[@class='box-content']/table[@class='table table-striped']/tbody/tr[10]/td`)
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
	for i := 1; ; i++ {
		xpath := xmlpath.MustCompile(fmt.Sprintf(`//section[@id='signatures']/a[%d]`, i))
		if signature, ok := xpath.String(xmlRoot); ok && len(signature) > 0 {
			result.Signatures = append(result.Signatures, strings.Trim(signature, " \n\t"))
		} else {
			break
		}
	}

	// Hosts
	for i := 2; ; i++ {
		xpath := xmlpath.MustCompile(fmt.Sprintf(`//section[@id='hosts']/table[@class='table table-striped table-bordered']/tbody/tr[%d]/td`, i))
		if ip, ok := xpath.String(xmlRoot); ok && len(ip) > 0 {
			result.Hosts = append(result.Hosts, ip)
		} else {
			break
		}
	}

	// Domains
	for i := 2; ; i++ {
		domainXpath := xmlpath.MustCompile(fmt.Sprintf(`//section[@id='domains']/table[@class='table table-striped table-bordered']/tbody/tr[%d]/td[1]`, i))
		domainString, ok := domainXpath.String(xmlRoot)
		if !ok || len(domainString) == 0 {
			break
		}

		ipXpath := xmlpath.MustCompile(fmt.Sprintf(`//section[@id='domains']/table[@class='table table-striped table-bordered']/tbody/tr[%d]/td[2]`, i))
		ipString, ok := ipXpath.String(xmlRoot)
		if !ok || len(ipString) == 0 {
			break
		}

		result.Domains = append(result.Domains, domain{IP: ipString, Domain: domainString})
	}

	// Files, Registry Keys, Mutexes
	for _, listType := range []string{"summary_keys", "summary_files", "summary_mutexes"} {
		xpath = xmlpath.MustCompile(fmt.Sprintf(`//section[@id='summary']/div[@class='tabbable tabs']/div[@class='tab-content']/div[@id='%s']/div[@class='well mono']`, listType))
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

	asJSON, err := json.MarshalIndent(result, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(asJSON))
}
