<p align="center">
<img src="docs/Logo-VESTA-noir.png"/>
</p>

<div align="center">

![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)
![Powered By: CERT SYNETIS](https://img.shields.io/badge/Powered_By-CERT_SYNETIS-f80808.svg?style=for-the-badge)

</div>

<h1 align="center">Virtual Entity Service for Transfer & Access</h1>


## Description

Web service used to manage virtual machines when it is not accessible:
- Upload files
- Download files
- Start VM
- Stop VM

>You only have access to what your vCenter account gives you access.

## Configure

In docker-compose.yml file set:
* vcenter IP address in environment
* replace **xxx** by corresponding files and folder
* output volume stores downloaded files from VM to then give them to browser

## Create certificate
```bash
openssl req -x509 -out ssl/vesta.crt -keyout ssl/vesta.key -newkey rsa:2048 -nodes -days 1000 -sha256 -subj '/CN=vesta' -extensions EXT -config <( printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
```

## Install Docker
```bash
docker compose -f Docker/docker-compose.yml up -d
```
default service port 443.

# Issues
We use Github issues to track bugs and errors.
Do not hesitate to report any issue using Github issue page from this project.


# Contributors
* [A-Lvu](https://github.com/A-Lvu)