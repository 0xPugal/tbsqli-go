# tbsqli-go
Time based SQL injection Scanner written in Golang inspired by [ghsec's SQLi_Sleeps2](https://github.com/ghsec/SQLi_Sleeps2).

## Installation
```bash
git clone https://github.com/0xPugal/tbsqli-go
cd tbsqli-go
go build sqli.go
```

## Help
```bash
Usage of /tmp/go-build3565722498/b001/exe/sqli:
  -C string
    	Cookie to include in the GET request.
  -i string
    	Text file with the URLs to which the GET request will be made.
  -o string
    	File to save the output.
  -p string
    	Text file with the payloads that will be appended to the URLs.
  -r float
    	Maximum response time considered vulnerable. (default 22)
  -v	Show detailed information during execution.
```

## Usage
```bash
./sqli -i input.txt -p payloads.txt -v -o output.txt
```

## Contributing
If you find issues or want to contribute, feel free to submit a pull request or raise an issue in the repository.

## License
This project is licensed under the Nothing. Do whatever you want responsibly.
