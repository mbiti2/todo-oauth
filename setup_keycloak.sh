#!/bin/bash
# setup_keycloak.sh - Configure Keycloak for the todo app (runs inside container via docker exec)

set -e

KEYCLOAK_URL="http://localhost:8080"
REALM_NAME="todo-realm"
CLIENT_ID="todo-client"
CLIENT_SECRET="18fYgnYsWEZIcDAQTb4vBdLjdcLdMidS"
TEST_USER="testuser"
TEST_PASS="testpass"
ADMIN_USER="admin"
ADMIN_PASS="admin"

# Name of the Keycloak container (matches docker-compose service name)
KC_CONTAINER="keycloak"

# Helper to run kcadm inside container
kc() {
  docker exec -it "$KC_CONTAINER" /opt/keycloak/bin/kcadm.sh "$@"
}

echo "Logging in as Keycloak admin..."
kc config credentials --server "$KEYCLOAK_URL" --realm master \
  --user "$ADMIN_USER" --password "$ADMIN_PASS"

echo "Creating realm: $REALM_NAME..."
if ! kc get realms/$REALM_NAME >/dev/null 2>&1; then
  kc create realms -s realm="$REALM_NAME" -s enabled=true
else
  echo "Realm $REALM_NAME already exists."
fi

echo "Creating client: $CLIENT_ID..."
if ! kc get clients -r "$REALM_NAME" --fields clientId | grep -q "\"$CLIENT_ID\""; then
  kc create clients -r "$REALM_NAME" \
    -s clientId="$CLIENT_ID" \
    -s enabled=true \
    -s publicClient=false \
    -s 'redirectUris=["http://localhost:3000/*"]' \
    -s directAccessGrantsEnabled=true
  # Now set secret after creation
  CLIENT_UUID=$(kc get clients -r "$REALM_NAME" -q clientId="$CLIENT_ID" --fields id | grep '"id"' | sed 's/.*"id" : "\([^"]*\)".*/\1/')
  kc update clients/$CLIENT_UUID -r "$REALM_NAME" -s secret="$CLIENT_SECRET"
else
  echo "Client $CLIENT_ID already exists."
fi


echo "Creating test user..."
if ! kc get users -r "$REALM_NAME" -q username="$TEST_USER" | grep -q "$TEST_USER"; then
  kc create users -r "$REALM_NAME" \
    -s username="$TEST_USER" \
    -s enabled=true \
    -s emailVerified=true \
    -s email="$TEST_USER@example.com"
  echo "Setting password for new user $TEST_USER..."
  USER_ID=$(kc get users -r "$REALM_NAME" -q username="$TEST_USER" --fields id | grep '"id"' | sed 's/.*"id" : "\([^"]*\)".*/\1/')
  kc set-password -r "$REALM_NAME" --userid "$USER_ID" --new-password "$TEST_PASS"
  # Ensure user is fully set up - update all required fields
  kc update users/"$USER_ID" -r "$REALM_NAME" \
    -s emailVerified=true \
    -s enabled=true \
    -s firstName="Test" \
    -s lastName="User"
else
  echo "User $TEST_USER already exists."
  echo "Resetting password for $TEST_USER..."
  USER_ID=$(kc get users -r "$REALM_NAME" -q username="$TEST_USER" --fields id | grep '"id"' | sed 's/.*"id" : "\([^"]*\)".*/\1/')
  kc set-password -r "$REALM_NAME" --userid "$USER_ID" --new-password "$TEST_PASS"
  # Ensure user is fully set up - update all required fields
  kc update users/"$USER_ID" -r "$REALM_NAME" \
    -s emailVerified=true \
    -s enabled=true \
    -s firstName="Test" \
    -s lastName="User" \
    -s email="$TEST_USER@example.com"
fi

echo "Keycloak setup complete."