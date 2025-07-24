# NATS Callout with KeyCloak

## Run local Server

nats-server --config .\nats.conf

## Try to authenticate

nats s ls -s nats://192.168.0.200:4222 --user=someuser-on-keycloak --password=somepassword

