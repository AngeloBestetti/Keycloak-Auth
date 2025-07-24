package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/nats-io/nkeys"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var (
		natsUrl    string
		natsUser   string
		natsPass   string
		issuerSeed string
		xkeySeed   string
	)

	// Note: Replace these with your actual NATS server details and keys.

	fmt.Println("Starting Auth Server: ", time.Now().Format(time.RFC3339))
	natsUrl = "nats://192.168.0.200:4222"
	natsUser = "auth"
	natsPass = "auth"

	issuerSeed = "SAADEBUENR2CHV6N4OQISSSYJKILIMIDM7PBLJVET6332JB46BV6TE2CGM"
	xkeySeed = "SXABJ3YJ55FXJNTIHJHGTVIZ4QK6APL76ZFRPKBIMBJQCKGK6ICZN5JZTY"

	serverName, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("error get server name: %s", err)
	}

	// Parse the issuer account signing key.
	issuerKeyPair, err := nkeys.FromSeed([]byte(issuerSeed))
	if err != nil {
		return fmt.Errorf("error parsing issuer seed: %s", err)
	}

	// Parse the xkey seed if present.
	var curveKeyPair nkeys.KeyPair
	if len(xkeySeed) > 0 {
		curveKeyPair, err = nkeys.FromSeed([]byte(xkeySeed))
		if err != nil {
			return fmt.Errorf("error parsing xkey seed: %s", err)
		}
	}

	// Model the user encoded in the users file.
	type User struct {
		Pass        string
		Account     string
		Permissions jwt.Permissions
	}

	// Open the NATS connection passing the auth account creds file.
	fmt.Println("Connecting Servers: ", natsUrl)

	nc, err := nats.Connect(natsUrl, nats.UserInfo(natsUser, natsPass))
	if err != nil {
		return err
	}
	defer nc.Drain()

	fmt.Println("Connected!")

	// Helper function to construct an authorization response.
	respondMsg := func(req micro.Request, userNkey, serverId, userJwt, errMsg string) {
		rc := jwt.NewAuthorizationResponseClaims(userNkey)
		rc.Audience = serverId
		rc.Error = errMsg
		rc.Jwt = userJwt

		token, err := rc.Encode(issuerKeyPair)
		if err != nil {
			log.Printf("error encoding response JWT: %s", err)
			req.Respond(nil)
			return
		}

		data := []byte(token)
		// println("Responding to Auth Request: \r\n", string(data))

		// Check if encryption is required.
		xkey := req.Headers().Get("Nats-Server-Xkey")
		if len(xkey) > 0 {
			data, err = curveKeyPair.Seal(data, xkey)
			if err != nil {
				log.Printf("error encrypting response JWT: %s", err)
				req.Respond(nil)
				return
			}
		}

		req.Respond(data)
	}

	// Define the message handler for the authorization request.
	msgHandler := func(req micro.Request) {
		//fmt.Println("Received Auth Request: \r\n")
		var token []byte

		// Check for Xkey header and decrypt
		xkey := req.Headers().Get("Nats-Server-Xkey")
		if len(xkey) > 0 {
			if curveKeyPair == nil {
				respondMsg(req, "", "", "", "xkey not supported")
				return
			}

			// Decrypt the message.
			token, err = curveKeyPair.Open(req.Data(), xkey)
			if err != nil {
				respondMsg(req, "", "", "", "error decrypting message")
				return
			}
		} else {
			token = req.Data()

		}

		// Decode the authorization request claims.
		rc, err := jwt.DecodeAuthorizationRequestClaims(string(token))
		if err != nil {
			respondMsg(req, "", "", "", err.Error())
			return
		}

		// Used for creating the auth response.
		userNkey := rc.UserNkey
		serverId := rc.Server.ID

		//println(token)

		// KeyCloak

		fmt.Println("Start Authenticating: ", time.Now().Format(time.RFC3339))

		k, err := KeycloakUser(rc.ConnectOptions.Username, rc.ConnectOptions.Password)
		if err != nil {
			log.Fatal(err)
		}

		message := fmt.Sprintf("Autentication: %s:%s \r\n", rc.ConnectOptions.Username, rc.ConnectOptions.Password)
		fmt.Println(message)

		println("End Authentication: ", time.Now().Format(time.RFC3339))

		// Validate the claims.

		userInfo := User{}
		userInfo.Account = k.Nats.Account

		permissions := jwt.Permissions{
			Sub: jwt.Permission{
				Allow: k.Nats.Permissions.Sub.Allow,
				Deny:  k.Nats.Permissions.Sub.Deny,
			},
			Pub: jwt.Permission{
				Allow: k.Nats.Permissions.Pub.Allow,
				Deny:  k.Nats.Permissions.Pub.Deny,
			},
		}
		userInfo.Permissions = permissions

		uc := jwt.NewUserClaims(rc.UserNkey)
		uc.Name = rc.ConnectOptions.Username

		// Audience contains the account in non-operator mode.
		uc.Audience = userInfo.Account

		// Set the associated permissions if present.
		uc.Permissions = userInfo.Permissions

		vr := jwt.CreateValidationResults()
		uc.Validate(vr)
		if len(vr.Errors()) > 0 {
			respondMsg(req, userNkey, serverId, "", "error validating claims")
			return
		}

		// Sign it with the issuer key since this is non-operator mode.
		ejwt, err := uc.Encode(issuerKeyPair)
		if err != nil {
			respondMsg(req, userNkey, serverId, "", "error signing user JWT")
			return
		}
		//println(ejwt)
		//time.Sleep(1 * time.Second)
		respondMsg(req, userNkey, serverId, ejwt, "")
	}

	// Create a service for auth callout with an endpoint binding to
	// the required subject. This allows for running multiple instances
	// to distribute the load, observe stats, and provide high availability.
	srv, err := micro.AddService(nc, micro.Config{
		Name:        "auth-callout",
		Version:     "1.0.0",
		Description: "Auth callout service.",
		Metadata:    map[string]string{"Environment": serverName, "Description": "Auth Service", "Origen": "labs", "Transaction": "auth"},
	})
	if err != nil {
		return err
	}

	g := srv.
		AddGroup("$SYS").
		AddGroup("REQ").
		AddGroup("USER")

	err = g.AddEndpoint("AUTH", micro.HandlerFunc(msgHandler))
	if err != nil {
		return err
	}

	// Block and wait for interrupt.
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)
	<-sigch

	return nil
}
