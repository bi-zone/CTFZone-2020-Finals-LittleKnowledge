# Cryptographic Task for CTFZone Finals 2019 (held in 2020)

This repository contains the code of the cryptographic task "LittleKnowledge", that we created for the CTFZone 2019 Finals (although they were held in April 2020).
We now publish this code for the community to use for new tasks, educational purposes, etc. If you have any questions you can contact one of the authors:
+ Alina Garbuz (a.garbuz@bi.zone)
+ Igor Motroni (i.motroni@bi.zone)
+ Innokentii Sennovskii (i.sennovskiy@bi.zone)

## Files and folders
+ zknlib/ - contains C library that provides core functionality
+ Dockerfile - team server build
+ LICENSE
+ private_zkn.pem - private RSA key we used for the challenge
+ public.pem - public RSA key we use for the challenge
+ Readme.md - this file
+ requirements.txt - requirements you need to install for running the task locally
+ team_server.py - python script containing high-level team server functionality
+ test.py - python script that was used for first test of wrapper functionality
+ zkn_checker.py - checker implementation for testing (our infrastracture used a different version)
+ zkn_support.py - wrapper around the C library, providing easy API.

## Building and running the challenge
You can choose to build team server through docker or on host.
To build locally:
```bash
cd zknlib && make clean && make libzkn && cp obj/libzkn.so ../ && cd ../
```
Then you can start the server:
```bash
python3 team_server.py
```
It will run on port 1337.
Alternatively you can build a container:
```bash
docker build -t zkn_team_server:0.0.1 .
```
and run:
```bash
docker run -p1337:1337 -t zkn_team_server:0.0.1 .
```
To run the checker you'll need to build and copy the library anyway. After its done, run:
```bash
python3 zkn_checker.py
```
You can also build zkn for fuzzing (but you need to enable one of the harnesses in zknlib/test/fuzzing.c):
```bash
 cd zknlib &&  make clean && make fuzz
```
Or you can build a version for tests:
```bash
cd zknlib && make clean && make test_zkn
```
You can find minized corpora in zknlib/test/corpus_collection.
