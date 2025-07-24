package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Nerzal/gocloak/v13"
)

// type UserResponse struct {
// 	Attributes map[string]interface{} `json:"attributes"`
// }

type AllowContainer struct {
	Allow interface{} `json:"Allow"` // You can change interface{} to []string or []any if you know the structure
}

type UserAttributes struct {
	Sub               string  `json:"sub"`
	EmailVerified     bool    `json:"email_verified"`
	FamilyName        string  `json:"family_name"`
	Name              string  `json:"name"`
	PreferredUsername string  `json:"preferred_username"`
	GivenName         string  `json:"given_name"`
	Locale            string  `json:"locale"`
	Email             string  `json:"email"`
	Account           string  `json:"account"`
	Nats              NatsTag `json:"nats"`
}

type NatsPermission struct {
	Allow []string `json:"Allow"`
	Deny  []string `json:"Deny"`
}

type NatsPermissions struct {
	Pub NatsPermission `json:"Pub"`
	Sub NatsPermission `json:"Sub"`
}

type NatsTag struct {
	Account     string          `json:"account"`
	Permissions NatsPermissions `json:"Permissions"`
}

func KeycloakUser(username string, password string) (UserAttributes, error) {

	var attrs UserAttributes
	var realm = "labs"
	gocloakClient := gocloak.NewClient("https://your-keycloak-server")
	ctx := context.Background()
	token, err := gocloakClient.Login(ctx, "client-id", "client-secret", realm, username, password)
	if err != nil {
		return attrs, fmt.Errorf("failed to get token: %w", err)
	}

	user, err := gocloakClient.GetRawUserInfo(ctx, token.AccessToken, realm)
	if err != nil {
		return attrs, fmt.Errorf("failed to get user info: %w", err)
	}

	jsonBytes, _ := json.Marshal(user) // user is map[string]interface{}
	json.Unmarshal(jsonBytes, &attrs)

	fmt.Println("User Attributes:")
	fmt.Printf("Sub: %s\n", attrs.Sub)
	fmt.Printf("Email Verified: %t\n", attrs.EmailVerified)
	fmt.Printf("Family Name: %s\n", attrs.FamilyName)
	fmt.Printf("Name: %s\n", attrs.Name)
	fmt.Printf("Preferred Username: %s\n", attrs.PreferredUsername)
	fmt.Printf("Given Name: %s\n", attrs.GivenName)
	fmt.Printf("Account: %s\n", attrs.Account)
	fmt.Println("NATS Account:", attrs.Nats.Account)
	fmt.Println("NATS Pub Permissions:", attrs.Nats.Permissions.Pub.Allow, attrs.Nats.Permissions.Pub.Deny)
	fmt.Println("NATS Sub Permissions:", attrs.Nats.Permissions.Sub.Allow, attrs.Nats.Permissions.Sub.Deny)
	return attrs, nil
}
