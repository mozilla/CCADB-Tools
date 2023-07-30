Certificate (JSON from PEM)
-----------------

### Use Cases

Certificate takes a PEM-encoded certificate and outputs JSON containing the parsed certificate and its raw X509 version encoded with base64.

### Deployment

#### Locally
When running `certificate` locally:

  ```sh
  $ go build -o certificate .
  $ PORT=8080 ./certificate
  ```

#### Using Docker
Alternatively, one may use the provided `Dockerfile` and `Makefile`:

  ```sh
  $ make clean build run
  ```

### Usage

Certificate offers one endpoint - `/certificate`

For example:

  ```sh
  # Submit a PEM file and get back JSON output.
  curl -X POST -F certificate=@example.pem http://localhost:8080/certificate
  ```
