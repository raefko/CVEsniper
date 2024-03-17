# CVEsniper

CVEsniper is a Go-based tool designed to audit Go modules for known vulnerabilities. It fetches vulnerability data from Snyk's vulnerability database and compares it with the versions of the modules used in your project.

## Installation

To install CVEsniper, you need to have Go installed on your machine. You can download it from [here](https://golang.org/dl/). Once Go is installed, you can install CVEsniper using the following command:

```bash
go get github.com/raefko/CVEsniper
```

## Usage
```bash
cvesniper <path_to_gomod_file>
```

You can enable verbose mode by using the --verbose flag:

```bash
cvesniper --verbose <path_to_gomod_file>
```

## Contributing
Contributions to CVEsniper are welcome! Please feel free to open an issue or submit a pull request if you have any improvements or bug fixes.

## License
TODO