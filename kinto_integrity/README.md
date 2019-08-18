# Kinto Integrity
This tool computes the set differences between Kinto, Firefox Nightly's `cert_storage`, and (optionally) `revocations.txt`.

## Deployment
A `Dockerfile`, `Makefile`, and convenience `run.sh` are provided.

`make clean build run` ... deploys this application within an Ubuntu Docker container listening on port 8080 
## HTTP Endpoints

For all requests, the following datasets are always used:

##### Kinto
`https://settings.prod.mozaws.net/v1/buckets/security-state/collections/onecrl/records`

##### cert_storage
A fresh, per request, Firefox Nightly profile is create and its cert_storage is populated.

##### revocations.txt
`revocations.txt` differs based on which endpoint is called.

### Default
```bash
curl -X GET http://example.org
```
The default `/` endpoint computes a diff using a baked-in copy of `revocations.txt` that is a copy of [bug #1553256](https://bug1553256.bmoattachments.org/attachment.cgi?id=9066502).

### Specifying a revocations.txt
##### GET /with_revocations?url={}
This endpoint allows you to specify a URL from which the tool may download any valid `revocations.txt`.
```bash
curl -X GET http://example.org/with_revocations?url=https%3A%2F%2Fbug1553256.bmoattachments.org%2Fattachment.cgi%3Fid%3D9066502
```
> NOTE: It is imperative that the value of `url` be URL encoded.

##### POST /with_revocations
This endpoint allows you upload any arbitrary `revocations.txt` in the body of a `POST` request.
```bash
curl -X POST -H "Content-Type: text/plain" --data-binary @revocations.txt http://example.org/with_revocations
```
> NOTE: --data-binary is mandatory when using cURL. This is due to the fact that the --data flag strips the POST data of all newlines which, within revocations.txt, are actually meaningful.

> NOTE: The header `"Content-Type: text/plain"` is mandatory. Failure to set this header will result in a 404.

### Excluding revocations.txt
The following endpoint excludes `revocations.txt` from the computation altogether.
```bash
curl -X GET http://example.org/without_revocations
```

### Force Updating Firefox Nightly
While this application polls `download.mozilla.org` each hour, as well as polling it on every request, you may have the desire to force an update to Firefox Nightly.
```bash
curl -X PATCH http://example.org/update_firefox_nightly
```
Updating Firefox Nightly also triggers a refresh of `cert_storage`
This method *_must_* be PATCH - all other HTTP methods will return a 404.

### Force Updating cert_storage
`cert_storage` is freshed each time Firefox Nightly is updated. However, if you believe that `cert_storage` warrants an immediate refresh, then you may do so.
```bash
curl -X PATCH http://example.org/update_cert_storage
```

This method *_must_* be PATCH - all other HTTP methods will return a 404.

### Return Structures

A certificate is defined at as the following struct.

```json
Certificate = {
  issuer_name: String,
  serial: String,
}
```

As this tool computes the difference between the different datasets, the results are represented in a "in this but not in that" format. This computation is done as a typical set difference.

For endpoints that compare against revocations.txt, the following JSON structure is returned.
```json
{
  "in_kinto_not_in_cert_storage": [Certificate...],
  "in_cert_storage_not_in_kinto": [Certificate...],
  "in_cert_storage_not_in_revocations": [Certificate...],
  "in_revocations_not_in_cert_storage": [Certificate...],
  "in_revocations_not_in_kinto": [Certificate...]},
  "in_kinto_not_in_revocations": [Certificate...]}
```

For endpoints that do not include revocations.txt within their computation, the following JSON structure is returned.
```json
{
  "in_kinto_not_in_cert_storage": [Certificate...],
  "in_cert_storage_not_in_kinto": [Certificate...]
}
```

In an ideal, "no problems", scenario all of the above arrays will be empty, as there is no difference between the various datasources.

### Firefox Nightly

`https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US`

This tool vendors a local copy of Firefox Nightly to service every request with diffs of `cert_storage`. In order to facilitate this, a thread awakes every hour to poll `download.mozilla.org` for a new a build of Firefox Nightly. If a new build has been published then this tool will replace the previous night's build with the current one.

Additionally, `download.mozilla.org` is polled at the beginning of every diffing request. Most typically, an up-to-date copy will already be present, however it is entirely possible that a request is made inbetween ticks of the updater thread. If this occurs, then the given request will take slightly longer as it needs to download and unpack the update.

### cert_storage Population Heuristic
`cert_storage` is populated as a step within the general initialization of a fresh Firefox profile. The strategy of this tool is to simply execute Firefox in the context of a given profile, which begins the initialization of that profile. However, since Firefox is not expecting to be ran programmatically, Firefox does not explicitly inform us whether `cert_storage` initialization is complete. Therefor, the following heuristic is applied:

1. Wait for `data.mdb` to be created, or a timeout is reached.
2. Beginning polling for the filesize of `data.mdb`. Keep polling until the size of the file begins increasing, or a timeout is reached.
3. Beginning polling for the filesize of `data.mdb`, keeping note of how long `data.mdb` stays at a particular size. Once `data.mdb` has stayed a certain size for 10 polling periods, it is assumed to be entirely populated.

The above heuristic us just that - a heuristic. While the heuristic has been observed to work consistently, if there is any point of failure within this tool then, this is it.