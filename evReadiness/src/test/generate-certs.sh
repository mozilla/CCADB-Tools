#!/bin/bash

#echo "../ev-checker -c github.com.pem -o 2.16.840.1.114412.2.1 -d 'DigiCert'" > run-tests.sh

echo	"V	401212121212Z	401212121212Z	2	unknown	/C=US/ST=California/L=Mountain View/O=Mozilla Corporation/OU=EV Testing/businessCategory=V1.0, Clause 5.(d)/1.3.6.1.4.1.311.60.2.1.1=Mountain View/1.3.6.1.4.1.311.60.2.1.2=CA/1.3.6.1.4.1.311.60.2.1.3=US/CN=EV Test Intermediate" > index.txt
echo	"V	401212121212Z	401212121212Z	1	unknown	/C=US/ST=California/L=Mountain View/O=Mozilla Corporation, OU=EV Testing/CN=EV Test Root" >> index.txt

echo "#!/bin/bash" > run-tests.sh
chmod u+x run-tests.sh

#XXX need some way to stop these when the test is done...
echo "openssl ocsp -index index.txt  -rsigner int.pem -rkey int.key -port 8080 -CA int.pem &" >> run-tests.sh
echo "openssl ocsp -index index.txt -CA CA.pem -rsigner CA.pem -rkey CA.key -port 8081 &" >> run-tests.sh

openssl req -new -x509 -days 1825 -nodes -out CA.pem -config ev-ca.cnf
openssl req -new -days 365 -nodes -out int.req -config ev-int.cnf
openssl x509 -req -in int.req -CA CA.pem -CAkey CA.key -extensions v3_int -out int.pem -set_serial 1 -extfile ev-int.cnf
#openssl req -new -out non-ev-cert.req -days 365 -nodes
#openssl x509 -req -in non-ev-cert.req -CA int.pem -CAkey int.key -extensions usr_cert -out non-ev-cert.pem -set_serial 1
#cat CA.pem int.pem non-ev-cert.pem > non-ev-chain.pem
openssl req -new -out ev-cert.req -days 365 -nodes -config ev.cnf
openssl x509 -req -in ev-cert.req -CA int.pem -CAkey int.key -out ev-cert.pem -extfile ev.cnf -set_serial 2 -extensions v3_req
cat ev-cert.pem int.pem CA.pem > ev-chain.pem
echo "../ev-checker -c ev-chain.pem -o 1.3.6.1.4.1.13769.666.666.666.1.500.9.1 -d 'Test EV Policy' -h ev-test.mozilla.example.com" >> run-tests.sh
openssl req -new -out ev-cert-no-int.req -days 365 -key ee.key -config ev.cnf
openssl x509 -req -in ev-cert-no-int.req -CA CA.pem -CAkey CA.key -out ev-cert-no-int.pem -extfile ev.cnf -set_serial 3 -extensions v3_req
cat ev-cert-no-int.pem CA.pem > ev-chain-no-int.pem
echo "../ev-checker -c ev-chain-no-int.pem -o 1.3.6.1.4.1.13769.666.666.666.1.500.9.1 -d 'Test EV Policy' -h ev-test.mozilla.example.com" >> run-tests.sh
