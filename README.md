3. Running & Testing
Start your server via go run main.go. Open a separate terminal and use the following curl commands to test the lifecycle:

1. Create a User

```sh
curl -X POST http://localhost:8080/graphql \
-H "Content-Type: application/json" \
-d '{"query":"mutation { createUser(username: \"john_doe\", password: \"secret123\") { id username } }"}'

curl -X POST http://localhost:8080/graphql \
-H "Content-Type: application/json" \
-d '{"query":"mutation { createUser(username: \"jane_doe\", password: \"secret123\") { id username } }"}'
```

2. Login (Exchange Username/Password for JWT)

```sh
curl -X POST http://localhost:8080/graphql \
-H "Content-Type: application/json" \
-d '{"query":"mutation { login(username: \"john_doe\", password: \"secret123\") { token user { id } } }"}'
# (Copy the string token and id from the JSON response for the next queries).

```

3. Get the "Me" Profile (Authenticated Query)
Replace YOUR_TOKEN with the token string you just generated. If this header is missing, the resolver throws a graceful GraphQL unauthorized error.

```sh
export YOUR_TOKEN=$(curl -X POST http://localhost:8080/graphql \
-H "Content-Type: application/json" \
-d '{"query":"mutation { login(username: \"john_doe\", password: \"secret123\") { token user { id } } }"}' | jq -r .data.login.token)

export USER_ID=$(curl -X POST http://localhost:8080/graphql \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $YOUR_TOKEN" \
-d '{"query":"query { me { id username } }"}' | jq -r .data.me.id)


2. Create a Service Account
Using the <USER_TOKEN> from the previous step in your header, generate the Service Account.

Bash
curl -X POST http://localhost:8080/graphql \
-H "Content-Type: application/json" \
-H "Authorization: Bearer <USER_TOKEN>" \
-d '{"query":"mutation { createServiceAccount(name: \"Background Job\") { serviceAccount { id name } secret } }"}'
Note: Copy the id and secret here. The generated plain-text secret is hashed dynamically on the backend and cannot be queried again.

3. Authenticate as the Service Account
Your external worker uses its id and secret to request its own JWT (mimicking an OAuth2 Client Credentials flow).

Bash
curl -X POST http://localhost:8080/graphql \
-H "Content-Type: application/json" \
-d '{"query":"mutation { loginServiceAccount(id: \"<SA_ID>\", secret: \"<SA_SECRET>\") { token serviceAccount { name } } }"}'
4. Query me using Union Types
Because the me endpoint now returns a GraphQL Union, we can use inline fragments (... on TypeName). Depending on whether you provide the User's JWT or the Service Account's JWT, the backend dynamically adapts and returns the specific schema details for that profile:

Bash
curl -X POST http://localhost:8080/graphql \
-H "Content-Type: application/json" \
-H "Authorization: Bearer <SERVICE_ACCOUNT_TOKEN>" \
-d '{
  "query": "query { me { __typename ... on User { id username } ... on ServiceAccount { id name } } }"
}'



```

4. Delete User (Authenticated Mutation)
Replace YOUR_TOKEN and <USER_ID> with your credentials. The resolvers pull the JWT properties from the context, ensuring users can only delete their own authenticated ID.

```sh
curl -X POST http://localhost:8080/graphql \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $YOUR_TOKEN" \
-d '{"query":"mutation { deleteUser(id: \"$USER_ID$\") }"}'

```