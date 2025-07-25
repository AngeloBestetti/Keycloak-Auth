# NATS Callout with KeyCloak


## Generate NSC Keys

nsc generate nkey --account

and if you want curved key to encrypt:

nsc generate nkey --curve

change nats.conf with the keys generated!


## Run local Server

nats-server --config .\nats.conf

## Try to authenticate

nats s ls -s nats://192.168.0.200:4222 --user=someuser-on-keycloak --password=somepassword

