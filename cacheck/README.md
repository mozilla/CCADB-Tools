cacheck
-----------------
Web UI for viewing crt.sh's cached certificate linting results


## Deployment

Make sure Python is in your PATH
```sh
echo $PATH
export PATH=$PATH:~/Library/Python/3.9/bin
```
Depends on a few other things:
```sh
pip3 install psycopg2-binary
pip3 install flask
```
Build
```sh
python3 main.py
```

Navigate to http://127.0.0.1:8080 
