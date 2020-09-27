# OneCRL-Viewer
This tool manages a git repo that is intended to serve as a version controlled history of OneCRL.
It attempts to find a complete certificate within [crt.sh](crt.sh) for each entry in OneCRL and provide a 
navigable, and human readable, view into OneCRL in general.

For example output, please see this [test repository](https://github.com/christopher-henderson/TestRepo).

## Usage
```bash
mkdir /tmp/test
git init /tmp/test
go run main.go /tmp/test
```

The above will commit changes to whatever branch `/tmp/test` is currently on, however it will not `git push origin` on your behalf - that remains a manual step.