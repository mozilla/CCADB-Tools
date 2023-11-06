EV Certificate Readiness Tool
-----------------

## Use Cases

Test tool for Certificate Authorities (CAs) who request to have a root certificate enabled for Extended Validation (EV) treatment.

## Deployment

### Locally
When running `evReadiness` locally:

```sh
$ docker build -t evready .
$ docker run -p 8080:8080 evready
```
Navigate to http://127.0.0.1:8080/evready in your web browser.

### Production
When running `evReadiness` in production:

```sh
$ make clean build run
```