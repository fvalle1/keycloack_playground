# UI

## Admin
http://localhost:8080/

## accounts
http://localhost:8080/realms/filippo/account

# OIDC
http://localhost:8080/realms/filippo/.well-known/openid-configuration

http://localhost:8080/realms/filippo/protocol/openid-connect/certs

Add *-----BEGIN CERTIFICATE-----*

# step

`step oauth --client-id step --client-secret i59R4L6CsuJC
tuH49dUpZrHNQKNkpyBi --provider https://auth.fvalle.online/realms/filippo/.well-known/openid-configuration`
