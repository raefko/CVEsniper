# CVEsniper

> [!WARNING]  
> CVEsniper is currently under active development: false positives and breaking changes can happen. 
> We highly appreciate any feedback and contributions!

CVEsniper is a Go-based tool designed to audit Go modules for known vulnerabilities. It fetches vulnerability data from Snyk's vulnerability database and compares it with the versions of the modules used in your project.

## Installation

To install CVEsniper, you need to have Go installed on your machine. You can download it from [here](https://golang.org/dl/). Once Go is installed, you can install CVEsniper using the following command:

```bash
go install github.com/raefko/CVEsniper/cmd/CVEsniper@latest
```

## Usage
```bash
CVEsniper <path_to_gomod_file>
```

You can enable verbose mode by using the --verbose flag:

```bash
CVEsniper --verbose <path_to_gomod_file>
```

## Contributing
Contributions to CVEsniper are welcome! Please feel free to open an issue or submit a pull request if you have any improvements or bug fixes.

## License

This project is licensed under the Apache License 2.0. See the `LICENSE` file for details.