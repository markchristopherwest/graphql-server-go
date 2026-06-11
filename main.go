// graphql-server-go: the GraphQL identity server that
// vault-plugin-secrets-graphql speaks to.
//
// The wire contract is shaped around the plugin's client (client.go +
// graphql_operations.go) and must stay in lockstep with it:
//
//   - Single endpoint: POST /graphql with {"query": "<document>"} only.
//     No variables object, no operation names. Arguments arrive inlined
//     as GraphQL string literals.
//   - Resolver failures are encoded into the body by graphql.Do and
//     returned over HTTP 200; the top-level "errors" array is the signal.
//   - Auth is "Authorization: Bearer <jwt>". Tokens are stateless
//     HMAC-signed JWTs with a 24h exp, BUT the subject is re-resolved
//     against live storage on every request, so deleting an account kills
//     its tokens immediately (this is what makes account deletion a real
//     teardown despite there being no signout mutation).
//
// Schema (matches graphql_operations.go exactly):
//
//	Query
//	  me: Identity                                            [auth]
//	Mutation
//	  login(username: String!, password: String!): AuthPayload          (open)
//	  createUser(input: CreateUserInput!): User                         (open)
//	  deleteUser(username: String!): Boolean                  [auth]  idempotent
//	  createServiceAccount(name: String!): CreateServiceAccountPayload  [auth]
//	  deleteServiceAccount(name: String!): Boolean            [auth]  idempotent
//
//	union Identity = User | ServiceAccount
//	type User            { id: ID!  username: String! }
//	type ServiceAccount  { id: ID!  name: String! }
//	type AuthPayload     { token: String!  user: User }
//	type CreateServiceAccountPayload { serviceAccount: ServiceAccount  secret: String }
//
// Contract points the Vault plugin depends on:
//
//   - createServiceAccount mints the service account's JWT AT CREATION and
//     returns it in the SECRET field. Service accounts have no password and
//     never go through login; the creation payload is the only place their
//     token exists. The minted token is signed for the NEW service account's
//     id — never an echo of the caller's bearer (client.go guards this).
//   - deleteUser / deleteServiceAccount are keyed by USERNAME / NAME (not
//     id) and are idempotent: deleting an absent account returns true, so
//     retried Vault lease revocations always succeed.
//   - me resolves whoever the bearer belongs to, as the Identity union; the
//     plugin uses it to vet stored sessions and verify freshly minted
//     credentials belong to the right identity.
//   - Auth failures surface as the GraphQL error "unauthorized: missing or
//     invalid token" over HTTP 200 — the exact marker the plugin's
//     isCredentialGone matches so dead credentials never wedge revocation.
//
// Verified curl interface:
//
//	curl -s -X POST http://localhost:8080/graphql \
//	  -H "Content-Type: application/json" \
//	  -d '{"query":"mutation { login(username: \"admin\", password: \"changeme\") { token user { id } } }"}'
//
//	curl -s -X POST http://localhost:8080/graphql \
//	  -H "Content-Type: application/json" \
//	  -H "Authorization: Bearer $TOKEN" \
//	  -d '{"query":"mutation { createServiceAccount(name: \"vault-demo\") { serviceAccount { id name } secret } }"}'
//
//	curl -s -X POST http://localhost:8080/graphql \
//	  -H "Content-Type: application/json" \
//	  -H "Authorization: Bearer $TOKEN" \
//	  -d '{"query":"mutation { deleteServiceAccount(name: \"vault-demo\") }"}'
//
// Environment:
//
//	PORT            listen port               (default 8080)
//	JWT_SECRET      HMAC signing key          (default insecure dev value)
//	ADMIN_USERNAME  seeded root user          (default "admin")
//	ADMIN_PASSWORD  seeded root password      (default "changeme")
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/graphql-go/graphql"
	"golang.org/x/crypto/bcrypt"
)

// tokenTTL matches the documented 24h stateless JWT lifetime.
const tokenTTL = 24 * time.Hour

// errUnauthorized is the exact message the Vault plugin's isCredentialGone
// matches ("unauthorized", "invalid token"). Do not reword casually.
var errUnauthorized = errors.New("unauthorized: missing or invalid token")

// --- storage -----------------------------------------------------------------

// user is a password-bearing account. IDs are prefixed "usr_" — the plugin's
// graphqlToken.UserID is a string for exactly this reason.
type user struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	passHash []byte // unexported: never serialized, never resolvable
}

// serviceAccount is a passwordless machine identity. IDs are prefixed "svc_".
// Its only credential is the JWT minted at creation.
type serviceAccount struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// store is the in-memory identity database. Accounts are keyed by their
// human-facing name because that is what the delete mutations take, and by
// id because that is what JWT subjects carry.
type store struct {
	mu          sync.RWMutex
	usersByName map[string]*user
	usersByID   map[string]*user
	sasByName   map[string]*serviceAccount
	sasByID     map[string]*serviceAccount
}

func newStore() *store {
	return &store{
		usersByName: map[string]*user{},
		usersByID:   map[string]*user{},
		sasByName:   map[string]*serviceAccount{},
		sasByID:     map[string]*serviceAccount{},
	}
}

// newID returns a prefixed random id like "usr_3f9c2a1b8d4e".
func newID(prefix string) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing means the host is broken; a timestamp id is
		// still unique enough to keep the server limping for a homelab.
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(b)
}

func (s *store) createUser(username, password string) (*user, error) {
	if username == "" || password == "" {
		return nil, errors.New("username and password are required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.usersByName[username]; exists {
		return nil, fmt.Errorf("user %q already exists", username)
	}
	u := &user{ID: newID("usr"), Username: username, passHash: hash}
	s.usersByName[username] = u
	s.usersByID[u.ID] = u
	return u, nil
}

// authenticate verifies username/password. The error is deliberately the
// same for unknown-user and bad-password so login can't be used as an
// account oracle.
func (s *store) authenticate(username, password string) (*user, error) {
	s.mu.RLock()
	u := s.usersByName[username]
	s.mu.RUnlock()
	if u == nil || bcrypt.CompareHashAndPassword(u.passHash, []byte(password)) != nil {
		return nil, errors.New("invalid credentials")
	}
	return u, nil
}

// deleteUser removes a user by username. Idempotent: absent users return
// true so retried Vault lease revocations always succeed.
func (s *store) deleteUser(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.usersByName[username]; ok {
		delete(s.usersByName, username)
		delete(s.usersByID, u.ID)
	}
	return true
}

func (s *store) createServiceAccount(name string) (*serviceAccount, error) {
	if name == "" {
		return nil, errors.New("name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sasByName[name]; exists {
		return nil, fmt.Errorf("service account %q already exists", name)
	}
	sa := &serviceAccount{ID: newID("svc"), Name: name}
	s.sasByName[name] = sa
	s.sasByID[sa.ID] = sa
	return sa, nil
}

// deleteServiceAccount removes a service account by name. Idempotent for the
// same reason deleteUser is: lease revocation must be safe to retry.
func (s *store) deleteServiceAccount(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sa, ok := s.sasByName[name]; ok {
		delete(s.sasByName, name)
		delete(s.sasByID, sa.ID)
	}
	return true
}

func (s *store) userByID(id string) *user {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.usersByID[id]
}

func (s *store) saByID(id string) *serviceAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sasByID[id]
}

// --- JWTs --------------------------------------------------------------------

const (
	typUser           = "user"
	typServiceAccount = "service_account"
)

// mintToken signs a 24h HMAC JWT for the given identity. "typ" routes the
// subject lookup on validation; "name" is informational only.
func mintToken(secret []byte, id, typ, name string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  id,
		"typ":  typ,
		"name": name,
		"iat":  now.Unix(),
		"exp":  now.Add(tokenTTL).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// identityFromToken validates the JWT and re-resolves its subject against
// live storage. Returning the live record (not the claims) is what makes
// account deletion immediately invalidate outstanding tokens even though the
// JWTs themselves are stateless until exp.
func identityFromToken(s *store, secret []byte, tokenString string) (any, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !token.Valid {
		return nil, errUnauthorized
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errUnauthorized
	}
	sub, _ := claims["sub"].(string)
	typ, _ := claims["typ"].(string)

	switch typ {
	case typUser:
		if u := s.userByID(sub); u != nil {
			return u, nil
		}
	case typServiceAccount:
		if sa := s.saByID(sub); sa != nil {
			return sa, nil
		}
	}
	// Valid signature but the account is gone (revoked lease, deleted user).
	return nil, errUnauthorized
}

// --- request identity --------------------------------------------------------

type ctxKey int

const identityKey ctxKey = 0

// callerIdentity returns the authenticated identity attached to the request
// context, or errUnauthorized. Resolvers gate on this; the HTTP layer never
// rejects, so auth failures surface as GraphQL errors over 200 exactly as
// the plugin expects.
func callerIdentity(p graphql.ResolveParams) (any, error) {
	if v := p.Context.Value(identityKey); v != nil {
		return v, nil
	}
	return nil, errUnauthorized
}

// --- schema ------------------------------------------------------------------

func buildSchema(s *store, secret []byte) (graphql.Schema, error) {
	userType := graphql.NewObject(graphql.ObjectConfig{
		Name: "User",
		Fields: graphql.Fields{
			"id":       &graphql.Field{Type: graphql.NewNonNull(graphql.ID)},
			"username": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		},
	})

	serviceAccountType := graphql.NewObject(graphql.ObjectConfig{
		Name: "ServiceAccount",
		Fields: graphql.Fields{
			"id":   &graphql.Field{Type: graphql.NewNonNull(graphql.ID)},
			"name": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		},
	})

	// Identity is a UNION (not an interface): the two members share no
	// common field names, and the plugin's opMe selects them with inline
	// fragments.
	identityUnion := graphql.NewUnion(graphql.UnionConfig{
		Name:  "Identity",
		Types: []*graphql.Object{userType, serviceAccountType},
		ResolveType: func(p graphql.ResolveTypeParams) *graphql.Object {
			switch p.Value.(type) {
			case *user:
				return userType
			case *serviceAccount:
				return serviceAccountType
			}
			return nil
		},
	})

	authPayloadType := graphql.NewObject(graphql.ObjectConfig{
		Name: "AuthPayload",
		Fields: graphql.Fields{
			"token": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
			"user":  &graphql.Field{Type: userType},
		},
	})

	// secret carries the JWT minted for the NEW service account at
	// creation — the only place this credential ever exists, since service
	// accounts have no password and cannot log in.
	createSAPayloadType := graphql.NewObject(graphql.ObjectConfig{
		Name: "CreateServiceAccountPayload",
		Fields: graphql.Fields{
			"serviceAccount": &graphql.Field{Type: serviceAccountType},
			"secret":         &graphql.Field{Type: graphql.String},
		},
	})

	createUserInput := graphql.NewInputObject(graphql.InputObjectConfig{
		Name: "CreateUserInput",
		Fields: graphql.InputObjectConfigFieldMap{
			"username": &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
			"password": &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
		},
	})

	queryType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			// me: identity behind the bearer. [auth]
			"me": &graphql.Field{
				Type: identityUnion,
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return callerIdentity(p)
				},
			},
		},
	})

	mutationType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			// login(username, password) -> AuthPayload. Open. Bare args —
			// this is the document opSignin sends; do not move it back to
			// an input object without changing graphql_operations.go too.
			"login": &graphql.Field{
				Type: authPayloadType,
				Args: graphql.FieldConfigArgument{
					"username": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"password": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					username, _ := p.Args["username"].(string)
					password, _ := p.Args["password"].(string)
					u, err := s.authenticate(username, password)
					if err != nil {
						return nil, err
					}
					tok, err := mintToken(secret, u.ID, typUser, u.Username)
					if err != nil {
						return nil, fmt.Errorf("minting token: %w", err)
					}
					return map[string]any{"token": tok, "user": u}, nil
				},
			},

			// createUser(input) -> User. Open (matches the plugin, which
			// still sends its admin bearer in case this is gated later).
			"createUser": &graphql.Field{
				Type: userType,
				Args: graphql.FieldConfigArgument{
					"input": &graphql.ArgumentConfig{Type: graphql.NewNonNull(createUserInput)},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					input, _ := p.Args["input"].(map[string]any)
					username, _ := input["username"].(string)
					password, _ := input["password"].(string)
					u, err := s.createUser(username, password)
					if err != nil {
						return nil, err
					}
					log.Printf("created user id=%s username=%s", u.ID, u.Username)
					return u, nil
				},
			},

			// deleteUser(username) -> Boolean. [auth] Idempotent: absent
			// users return true so retried lease revocations succeed.
			"deleteUser": &graphql.Field{
				Type: graphql.Boolean,
				Args: graphql.FieldConfigArgument{
					"username": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if _, err := callerIdentity(p); err != nil {
						return nil, err
					}
					username, _ := p.Args["username"].(string)
					log.Printf("deleting user username=%s", username)
					return s.deleteUser(username), nil
				},
			},

			// createServiceAccount(name) -> { serviceAccount secret }.
			// [auth] The secret is a JWT signed for the NEW service
			// account's id — by construction it can never equal the
			// caller's bearer (different sub/typ/iat), which is the
			// invariant client.go's anti-echo guard enforces.
			"createServiceAccount": &graphql.Field{
				Type: createSAPayloadType,
				Args: graphql.FieldConfigArgument{
					"name": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if _, err := callerIdentity(p); err != nil {
						return nil, err
					}
					name, _ := p.Args["name"].(string)
					sa, err := s.createServiceAccount(name)
					if err != nil {
						return nil, err
					}
					tok, err := mintToken(secret, sa.ID, typServiceAccount, sa.Name)
					if err != nil {
						// Roll back so a retry with the same name succeeds
						// instead of hitting "already exists".
						s.deleteServiceAccount(sa.Name)
						return nil, fmt.Errorf("minting service account secret: %w", err)
					}
					log.Printf("created service account id=%s name=%s", sa.ID, sa.Name)
					return map[string]any{"serviceAccount": sa, "secret": tok}, nil
				},
			},

			// deleteServiceAccount(name) -> Boolean. [auth] Idempotent like
			// deleteUser. Deletion also kills the account's outstanding
			// JWTs immediately because identityFromToken re-resolves the
			// subject against live storage.
			"deleteServiceAccount": &graphql.Field{
				Type: graphql.Boolean,
				Args: graphql.FieldConfigArgument{
					"name": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if _, err := callerIdentity(p); err != nil {
						return nil, err
					}
					name, _ := p.Args["name"].(string)
					log.Printf("deleting service account name=%s", name)
					return s.deleteServiceAccount(name), nil
				},
			},
		},
	})

	return graphql.NewSchema(graphql.SchemaConfig{
		Query:    queryType,
		Mutation: mutationType,
	})
}

// --- HTTP --------------------------------------------------------------------

// graphqlRequest mirrors the plugin's transport: {"query": "<document>"}
// only. Variables/operationName are accepted-and-ignored on the wire by
// virtue of not being decoded.
type graphqlRequest struct {
	Query string `json:"query"`
}

func graphqlHandler(schema graphql.Schema, s *store, secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed; POST {\"query\": ...}", http.StatusMethodNotAllowed)
			return
		}

		var req graphqlRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("decoding request body: %v", err), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Query) == "" {
			http.Error(w, "request body must carry a non-empty \"query\"", http.StatusBadRequest)
			return
		}

		// Resolve the bearer (if any) to a live identity. Invalid or stale
		// tokens are NOT an HTTP error: gated resolvers surface
		// errUnauthorized as a GraphQL error over 200, which is the marker
		// the Vault plugin's isCredentialGone matches.
		ctx := r.Context()
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			if id, err := identityFromToken(s, secret, strings.TrimPrefix(auth, "Bearer ")); err == nil {
				ctx = context.WithValue(ctx, identityKey, id)
			}
		}

		result := graphql.Do(graphql.Params{
			Schema:        schema,
			RequestString: req.Query,
			Context:       ctx,
		})

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			log.Printf("encoding response: %v", err)
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	secret := []byte(envOr("JWT_SECRET", "dev-secret-change-me"))
	if string(secret) == "dev-secret-change-me" {
		log.Printf("WARNING: using the default JWT_SECRET; set JWT_SECRET in any real deployment")
	}

	s := newStore()

	// Seed the root user the Vault plugin's config points at.
	adminUser := envOr("ADMIN_USERNAME", "admin")
	adminPass := envOr("ADMIN_PASSWORD", "changeme")
	if _, err := s.createUser(adminUser, adminPass); err != nil {
		log.Fatalf("seeding admin user: %v", err)
	}
	log.Printf("seeded admin user %q", adminUser)

	schema, err := buildSchema(s, secret)
	if err != nil {
		log.Fatalf("building schema: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", graphqlHandler(schema, s, secret))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	addr := ":" + envOr("PORT", "8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("graphql-server-go listening on %s (endpoint /graphql)", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server exited: %v", err)
	}
}
