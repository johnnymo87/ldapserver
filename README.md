#### LDAP Server

This is just a proof of concept. It borrows example code from [here](https://github.com/vjeantet/ldapserver).

This works with [this LDAP client](https://github.com/johnnymo87/kubernetes-ldap/tree/proof-of-concept).

Server:
```sh
script/run_docker_env_setup
docker logs -f ldap_server
```

Client:
```sh
script/run_docker_env_setup
docker logs -f ldap_client
```

Assuming the IP of `docker-machine` is 192.168.99.100, do `curl -k https://192.168.99.100:4000/ldapAuth --user jon:secret`. You should get a token back.

Gif to demo: http://quick.as/x6y3tkbob
