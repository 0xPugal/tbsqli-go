package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
	"net/url"
)

const (
	errorColor     = "\033[1;31m"
	successColor   = "\033[1;32m"
	resetColor     = "\033[0m"
	minResponseTime = 20.0
)

var (
	verbose    bool
	outputFile string
	payloadsFile string 
)

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func performRequest(urlStr, data, cookie string, ch chan<- string, maxResponseTime float64, output *os.File) {
	urlWithData := fmt.Sprintf("%s%s", urlStr, url.QueryEscape(data))
	startTime := time.Now()

	resp, err := http.Get(urlWithData)
	if err != nil {
		ch <- fmt.Sprintf("%sURL %s - Error: %s%s", errorColor, urlWithData, err, resetColor)
		return
	}
	defer resp.Body.Close()

	responseTime := time.Since(startTime).Seconds()

	if found, result := isVulnerable(resp, responseTime, urlWithData, verbose, maxResponseTime); found {
		ch <- result
		if output != nil {
			fmt.Fprintf(output, "%s\n", result)
		}
	}
}

func isVulnerable(resp *http.Response, responseTime float64, urlWithData string, verbose bool, maxResponseTime float64) (bool, string) {
	if resp.StatusCode == http.StatusOK && isWithinResponseTimeRange(responseTime, maxResponseTime) {
		return true, fmt.Sprintf("%sURL %s - %.2f seconds - Vulnerable%s", errorColor, urlWithData, responseTime, resetColor)
	} else if verbose {
		return false, fmt.Sprintf("%sURL %s - %.2f seconds%s", successColor, urlWithData, responseTime, resetColor)
	}
	return false, ""
}

func isWithinResponseTimeRange(responseTime, maxResponseTime float64) bool {
	return responseTime >= minResponseTime && responseTime < maxResponseTime
}

func main() {
	inputFile := flag.String("i", "", "Text file with the URLs to which the GET request will be made.")
	flag.StringVar(&payloadsFile, "p", "", "Text file with the payloads that will be appended to the URLs.")
	cookie := flag.String("C", "", "Cookie to include in the GET request.")
	responseTimeFlag := flag.Float64("r", 22.0, "Maximum response time considered vulnerable.")
	flag.BoolVar(&verbose, "v", false, "Show detailed information during execution.")
	flag.StringVar(&outputFile, "o", "", "File to save the output.")
	flag.Parse()

	if *inputFile == "" || payloadsFile == "" {
		flag.Usage()
		log.Fatal("You must provide files for input URLs and payloads.")
	}

	urls, err := readLines(*inputFile)
	if err != nil {
		log.Fatalf("Error reading the input URLs file: %s", err)
	}

	payloads, err := readLines(payloadsFile) 
	if err != nil {
		log.Fatalf("Error reading the payloads file: %s", err)
	}

	var wg sync.WaitGroup
	ch := make(chan string, len(urls)*len(payloads)) 

	// Concurrency control
	sem := make(chan struct{}, 10) 

	var output *os.File
	if outputFile != "" {
		output, err = os.Create(outputFile)
		if err != nil {
			log.Fatalf("Error creating the output file: %s", err)
		}
		defer output.Close()
	}

	for _, url := range urls {
		for _, payload := range payloads {
			sem <- struct{}{} // Acquire semaphore
			wg.Add(1)
			go func(url, payload string) {
				defer wg.Done()
				performRequest(url, payload, *cookie, ch, *responseTimeFlag, output)
				<-sem // Release semaphore
			}(url, payload)
		}
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	fmt.Println("Time Based SQLI Scanner")
	for result := range ch {
		log.Println(result)
	}
}
