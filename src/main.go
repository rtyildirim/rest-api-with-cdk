package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"

	"encoding/json"
)

type userType struct {
	UserName  string `json:"userName"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Password  string `json:"password"`
	Address1  string `json:"address1"`
	Address2  string `json:"address2"`
	City      string `json:"city"`
	State     string `json:"state"`
	Zipcode   string `json:"zipcode"`
}

type itemDdb struct {
	Id          string  `json:"id"`
	Owner       string  `json:"owner"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	Quantity    int     `json:"quantity"`
}

type item struct {
	Item    itemDdb  `json:"item"`
	Reviews []review `json:"reviews"`
}

type review struct {
	Id         string `json:"id"`
	ItemId     string `json:"itemId"`
	ReviewerId string `json:"reviewerId"`
	Review     string `json:"review"`
	Rating     int    `json:"rating"`
	Time       string `json:"time"`
}

type errorResponse struct {
	Message string `json:"message"`
	Detail  string `json:"Detail"`
}

type loginResponse struct {
	Token   string `json:"token"`
	Expires string `json:"expires"`
}

var tokenKeyId string
var awsRegion string

func main() {
	tokenKeyId = os.Getenv("KMS_TOKEN_KEY_ID")
	if tokenKeyId == "" {
		log.Fatal("Missing KMS Key ID")
	}
	awsRegion = os.Getenv("AWS_REGION")
	if tokenKeyId == "" {
		log.Fatal("Missing AWS Region")
	}
	lambda.Start(handler)
}

func handler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.Path {
	case "/users":
		return userHandler(req)
	case "/items":
		return itemHandler(req)
	case "/login":
		return loginHandler(req)
	default:
		return unhandledPath(req)
	}
}

func userHandler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.HTTPMethod {
	case "GET":
		return getUsers(req)
	case "POST":
		return createUser(req)
	default:
		return unhandledMethod(req)
	}
}

func itemHandler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.HTTPMethod {
	case "GET":
		return getItems(req)
	case "POST":
		return createItem(req)
	default:
		return unhandledMethod(req)
	}
}

func loginHandler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.HTTPMethod {
	case "POST":
		return loginUser(req)
	default:
		return unhandledMethod(req)
	}
}

func loginUser(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {

	user := userType{}

	err := json.Unmarshal([]byte(req.Body), &user)
	if err != nil || user.UserName == "" || user.Password == "" {
		result := errorResponse{
			Message: "Invalid request",
			Detail:  "Request body must include username and password",
		}
		return apiResponse(http.StatusBadRequest, result)
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)

	queryInput := &dynamodb.QueryInput{
		TableName: aws.String("userTable"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":userName": {
				S: aws.String(strings.ToLower(user.UserName)),
			},
		},
		KeyConditionExpression: aws.String("userName = :userName"),
	}

	res, err := svc.Query(queryInput)
	if err != nil {
		return apiResponse(http.StatusInternalServerError, errorResponse{
			Message: "Unable to get users",
			Detail:  err.Error(),
		})
	}

	record := userType{}

	authenticated := false
	for _, j := range res.Items {
		err = dynamodbattribute.UnmarshalMap(j, &record)
		if err != nil {
			return apiResponse(http.StatusInternalServerError, errorResponse{
				Message: "Unable to parse users",
				Detail:  err.Error(),
			})
		}
		if strings.EqualFold(user.UserName, record.UserName) && comparePasswords(record.Password, user.Password) {
			authenticated = true
		}
	}

	if !authenticated {
		return apiResponse(http.StatusForbidden, errorResponse{
			Message: "Forbidden",
		})
	}

	loginResponse, err := createJwt(strings.ToLower(user.UserName))

	if err != nil {
		return apiResponse(http.StatusForbidden, errorResponse{
			Message: "Forbidden",
			Detail:  err.Error(),
		})
	}

	return apiResponse(http.StatusOK, loginResponse)
}

func getUsers(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)

	tableName := "userTable"

	scanInput := &dynamodb.ScanInput{
		TableName: aws.String(tableName),
	}

	res, err := svc.Scan(scanInput)
	if err != nil {
		return apiResponse(http.StatusInternalServerError, errorResponse{
			Message: "Unable to get users",
			Detail:  err.Error(),
		})
	}

	out := []userType{}

	var record userType

	for _, j := range res.Items {
		err = dynamodbattribute.UnmarshalMap(j, &record)
		if err == nil {
			record.Password = "****"
			out = append(out, record)
		}
	}

	return apiResponse(http.StatusOK, out)
}

func createUser(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	var newUser userType

	err := json.Unmarshal([]byte(req.Body), &newUser)
	if err != nil || newUser.Email == "" || newUser.UserName == "" || newUser.Password == "" {
		result := errorResponse{
			Message: "Invalid request",
			Detail:  "Request body is invalid. Please see the documentation.",
		}
		return apiResponse(http.StatusBadRequest, result)
	}

	//TODO: validate email address, username, make sure they are not already in the db
	//TODO: Validate password for requirements

	hashedSaltedPwd, err := hashAndSalt(newUser.Password)

	if err != nil {
		result := errorResponse{
			Message: "Invalid password",
			Detail:  "Request body is invalid. Please see the documentation.",
		}
		return apiResponse(http.StatusBadRequest, result)
	}

	newUser.Password = hashedSaltedPwd

	err = storeUser(newUser)
	if err != nil {
		result := errorResponse{
			Message: "Unable to store new user",
			Detail:  err.Error(),
		}
		return apiResponse(http.StatusInternalServerError, result)
	}

	newUser.Password = "**********"
	newUser.UserName = strings.ToLower(newUser.UserName)

	return apiResponse(http.StatusOK, newUser)
}

func storeUser(newUser userType) error {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := dynamodb.New(sess)

	nu, err := dynamodbattribute.MarshalMap(newUser)
	if err != nil {
		return err
	}

	tableName := "userTable"

	input := &dynamodb.PutItemInput{
		Item:      nu,
		TableName: aws.String(tableName),
	}

	_, err = svc.PutItem(input)

	return err
}

func createItem(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	var newItem itemDdb

	err := json.Unmarshal([]byte(req.Body), &newItem)
	if err != nil || newItem.Name == "" || newItem.Description == "" || newItem.Owner == "" {
		result := errorResponse{
			Message: "Invalid request",
			Detail:  "Request body is invalid. Please see the documentation.",
		}
		return apiResponse(http.StatusBadRequest, result)
	}

	//assign an item id (uid)
	newItem.Id = uuid.New().String()

	//TODO: validate item (owener, quantitiy, price name, description)
	//TODO: Owner should be get from auth token. Only the owner can create items

	err = storeItem(newItem)
	if err != nil {
		result := errorResponse{
			Message: "Unable to store new item",
			Detail:  err.Error(),
		}
		return apiResponse(http.StatusInternalServerError, result)
	}

	return apiResponse(http.StatusOK, newItem)
}

func storeItem(newItem itemDdb) error {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := dynamodb.New(sess)

	ni, err := dynamodbattribute.MarshalMap(newItem)
	if err != nil {
		return err
	}

	tableName := "itemTable"

	input := &dynamodb.PutItemInput{
		Item:      ni,
		TableName: aws.String(tableName),
	}

	_, err = svc.PutItem(input)

	return err
}

func getItems(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)

	tableName := "itemTable"

	scanInput := &dynamodb.ScanInput{
		TableName: aws.String(tableName),
	}

	res, err := svc.Scan(scanInput)
	if err != nil {
		return apiResponse(http.StatusInternalServerError, errorResponse{
			Message: "Unable to get items",
			Detail:  err.Error(),
		})
	}

	out := []item{}

	var record itemDdb

	for _, j := range res.Items {
		err = dynamodbattribute.UnmarshalMap(j, &record)
		if err == nil {
			item := item{
				Item:    record,
				Reviews: []review{},
			}
			//TODO: add reviews
			out = append(out, item)
		}
	}

	return apiResponse(http.StatusOK, out)
}

func unhandledMethod(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	result := errorResponse{
		Message: fmt.Sprintf("%s method is not supported for %s path", req.HTTPMethod, req.Path),
		Detail:  "Try again",
	}
	return apiResponse(http.StatusNotFound, result)
}

func unhandledPath(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	result := errorResponse{
		Message: fmt.Sprintf("Invalid path %s", req.Path),
		Detail:  "Try valid paths",
	}
	return apiResponse(http.StatusNotFound, result)
}

func apiResponse(status int, body interface{}) (*events.APIGatewayProxyResponse, error) {
	resp := events.APIGatewayProxyResponse{Headers: map[string]string{"Content-Type": "application/json"}}
	resp.StatusCode = status
	stringBody, _ := json.Marshal(body)
	resp.Body = string(stringBody)
	return &resp, nil
}

func hashAndSalt(pwd string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func comparePasswords(hashedPwd string, plainPwd string) bool {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, []byte(plainPwd))
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func createJwt(userName string) (loginResponse, error) {

	res := loginResponse{}
	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(awsRegion))
	if err != nil {
		return res, err
	}

	now := time.Now()
	expiresAt := now.Add(1 * time.Hour)
	jwtToken := jwt.NewWithClaims(jwtkms.SigningMethodRS512, &jwt.StandardClaims{
		Audience:  "my-rest-api.example.com",
		ExpiresAt: expiresAt.Unix(),
		Id:        "1234-5678",
		IssuedAt:  now.Unix(),
		Issuer:    "my-rest-api-auth.example.com",
		NotBefore: now.Unix(),
		Subject:   userName,
	})

	kmsConfig := jwtkms.NewKMSConfig(kms.NewFromConfig(awsCfg), tokenKeyId, false)

	token, err := jwtToken.SignedString(kmsConfig.WithContext(context.Background()))
	if err != nil {
		return res, err
	}
	res.Token = token
	res.Expires = expiresAt.Format(time.RFC3339)
	return res, nil
}

func validateToken(tokenStr string, userName string) (bool, error) {
	claims := jwt.StandardClaims{}

	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(awsRegion))
	if err != nil {
		return false, err
	}

	kmsConfig := jwtkms.NewKMSConfig(kms.NewFromConfig(awsCfg), tokenKeyId, false)

	_, err = jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		return kmsConfig, nil
	})
	if err != nil {
		return false, err
	}

	return strings.EqualFold(claims.Subject, userName), nil
}
