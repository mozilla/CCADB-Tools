Certificate Viewing Tool
-----------------

## Deployment

### Locally
When running `certViewer` locally:

```sh
$ docker build -t certviewer .
$ docker run -p 8080:8080 certviewer
```
Navigate to http://127.0.0.1:8080/certviewer in your web browser.

### Production
When running `certViewer` in production:

```sh
$ make clean build run
```