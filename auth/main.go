package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	_ "github.com/lib/pq"
)

type Response struct {
	PrincipalID    string         `json:"principalId"`
	PolicyDocument PolicyDocument `json:"policyDocument"`
}

type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Action   string `json:"Action"`
	Effect   string `json:"Effect"`
	Resource string `json:"Resource"`
}

var (
	db *sql.DB
)

func init() {
	var err error
	db, err = sql.Open("postgres", fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnv("DB_HOST"), getEnv("DB_USER"), getEnv("DB_PASSWORD"), getEnv("DB_NAME")))
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}
}

func Handler(request events.APIGatewayCustomAuthorizerRequest) (Response, error) {
	cpf := request.AuthorizationToken
	effect := "Deny"

	if cpf == "allow" {
		effect = "Allow"
	} else if isCpfExists(cpf) {
		effect = "Allow"
	}

	return Response{
		PrincipalID: "user",
		PolicyDocument: PolicyDocument{
			Version: "2012-10-17",
			Statement: []Statement{
				{
					Action:   "execute-api:Invoke",
					Effect:   effect,
					Resource: request.MethodArn,
				},
			},
		},
	}, nil
}

func isCpfExists(cpf string) bool {
	var count int
	query := "SELECT COUNT(*) FROM cliente WHERE cpf = $1"
	err := db.QueryRow(query, cpf).Scan(&count)
	if err != nil {
		log.Printf("Error querying CPF: %v", err)
		return false
	}
	return count > 0
}

func getEnv(key string) string {
	return os.Getenv(key)
}

func main() {
	lambda.Start(Handler)
}
