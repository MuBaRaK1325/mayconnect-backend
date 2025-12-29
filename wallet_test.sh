#!/bin/bash

# Replace this with your latest token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiaWF0IjoxNzY2NTM1NDk1LCJleHAiOjE3NjcxNDAyOTV9.RqphdJRDtFnS2blgQDCAzNMJOhOF-rD"

echo "=== Checking Wallet Balance ==="
curl -X GET http://localhost:3000/api/wallet \
-H "Authorization: Bearer $TOKEN"
echo -e "\n"

echo "=== Funding Wallet with 5000 ==="
curl -X POST http://localhost:3000/api/wallet/fund \
-H "Authorization: Bearer $TOKEN" \
-H "Content-Type: application/json" \
-d '{"amount":5000}'
echo -e "\n"

echo "=== Fetching Transaction History ==="
curl -X GET http://localhost:3000/api/wallet/transactions \
-H "Authorization: Bearer $TOKEN"
echo -e "\n"
#!/bin/bash

# Ask user for the token
read -p "Enter your JWT token: " TOKEN

echo -e "\n=== Checking Wallet Balance ==="
curl -X GET http://localhost:3000/api/wallet \
-H "Authorization: Bearer $TOKEN"
echo -e "\n"

echo "=== Funding Wallet with 5000 ==="
curl -X POST http://localhost:3000/api/wallet/fund \
-H "Authorization: Bearer $TOKEN" \
-H "Content-Type: application/json" \
-d '{"amount":5000}'
echo -e "\n"

echo "=== Fetching Transaction History ==="
curl -X GET http://localhost:3000/api/wallet/transactions \
-H "Authorization: Bearer $TOKEN"
echo -e "\n"
