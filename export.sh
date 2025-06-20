#!/bin/bash
# docker exec -it keycloak-keycloak-1 /opt/keycloak/bin/kc.sh show-config

# docker exec -it keycloak-keycloak-1 /opt/keycloak/bin/kc.sh export --realm filippo --file /tmp/realm-export.json

docker run --rm \
    -v ./keycloak/data:/opt/keycloak/data \
    -v ./realm-export.json:/tmp/realm-export.json \
    quay.io/keycloak/keycloak:26.2.5 \
      export \
      --realm filippo \
      --file /tmp/realm-export.json