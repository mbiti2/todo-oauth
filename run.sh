#!/bin/bash
# run.sh - Start Keycloak and the Rust todo-service, set up Keycloak, run tests, and clean up
set -e

echo "Building and starting Keycloak and todo-service..."
docker-compose up --build -d

# Wait for Keycloak
echo "Waiting for Keycloak..."
until curl -s http://localhost:8080/realms/master/.well-known/openid-configuration > /dev/null; do
  sleep 2
done
echo "Keycloak is up."

# Wait for todo-service
echo "Waiting for todo-service..."
until curl -s http://localhost:3000/ > /dev/null; do
  sleep 2
done
echo "todo-service is up."


# Setup Keycloak realm, client, and test user
./setup_keycloak.sh

# Wait a bit to ensure Keycloak is ready to issue tokens
sleep 5

# Test variables
TEST_USER="testuser"
TEST_PASS="testpass"
# Load CLIENT_SECRET from .env file
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi
CLIENT_SECRET="${CLIENT_SECRET:-18fYgnYsWEZIcDAQTb4vBdLjdcLdMidS}"


# Get token and print full response for debugging
TOKEN_RESPONSE=$(curl -s -X POST "http://localhost:8080/realms/todo-realm/protocol/openid-connect/token" \
  -d "client_id=todo-client" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "grant_type=password" \
  -d "username=$TEST_USER" \
  -d "password=$TEST_PASS")
echo "Token endpoint response: $TOKEN_RESPONSE"
TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to get token. Exiting."
  docker-compose down
  exit 1
fi

echo "Token acquired."

# List todos (should be empty)
echo "Listing todos (should be empty):"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:3000/

# Add a todo
echo -e "\nAdding a todo..."
curl -s -X POST -H "Authorization: Bearer $TOKEN" -d "title=Test todo" http://localhost:3000/add

# List todos (should show one)
echo -e "\nListing todos (should show one):"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:3000/

# Get todo ID
TODO_ID=$(curl -s -H "Authorization: Bearer $TOKEN" http://localhost:3000/ | grep -oE 'toggle/[0-9a-f\-]+' | head -n1 | cut -d'/' -f2)
echo -e "\nFirst todo ID: $TODO_ID"

# Toggle todo
echo -e "\nToggling todo..."
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://localhost:3000/toggle/$TODO_ID

# Delete todo
echo -e "\nDeleting todo..."
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://localhost:3000/delete/$TODO_ID

# List todos (should be empty again)
echo -e "\nListing todos (should be empty again):"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:3000/

# Cleanup
echo -e "\nCleaning up containers..."
docker-compose down
echo "Done."