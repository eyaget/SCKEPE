# Setup

Install a stable version of `go`, e.g., 1.24.11

# Configuration

## Create directory
- Download the code from this repository
- Go to the directory: `cd SCKEPE`
  
## Initialize module
- `go mod init SCKEPE`

## Add dependencies
- `go get github.com/consensys/gnark@v0.14.0`
- `go get github.com/consensys/gnark-crypto@v0.19.2`
- `go get github.com/liyue201/gnark-circomlib@latest`
- `go get github.com/iden3/go-iden3-crypto@latest`
- `go mod tidy`

The above steps create `go.mod` and `go.sum` configuration files in the project directory. 

# Run

- `go run .

The code is executed 100 times to simulate the complete proof process of SCKEPE and to measure the execution time of each proof generation and verification module.
