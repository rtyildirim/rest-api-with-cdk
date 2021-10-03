package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"

	"github.com/google/uuid"

	"encoding/json"
)

type user struct {
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

type item struct {
	Id          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Price       float64  `json:"price"`
	Quantity    int      `json:"quantity"`
	Reviews     []review `json:"reviews"`
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

func main() {
	lambda.Start(handler)
}

func handler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.Path {
	case "/users":
		return userHandler(req)
	case "/items":
		return itemHandler(req)
	default:
		return unhandledPath(req)
	}
}

func userHandler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.HTTPMethod {
	case "GET":
		return getUser(req)
	case "POST":
		return createUser(req)
	default:
		return unhandledMethod(req)
	}
}

func itemHandler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.HTTPMethod {
	case "GET":
		return getItem(req)
	case "POST":
		return createItem(req)
	default:
		return unhandledMethod(req)
	}
}

func getUser(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	result := user{
		UserName: "rtyildirim",
		Email:    "blah@gmail.com",
		Address1: "My Address",
		City:     "EC",
		State:    "OK",
		Zipcode:  "23456",
		Password: "*********",
	}
	return apiResponse(http.StatusOK, result)
}

func createUser(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	var newUser user

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

	//TODO: save user to db
	err = storeUser(newUser)
	if err != nil {
		result := errorResponse{
			Message: "Unable to store new user",
			Detail:  err.Error(),
		}
		return apiResponse(http.StatusInternalServerError, result)
	}

	newUser.Password = "**********"

	return apiResponse(http.StatusOK, newUser)
}

func storeUser(newUser user) error {
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
	var newItem item

	err := json.Unmarshal([]byte(req.Body), &newItem)
	if err != nil || newItem.Name == "" || newItem.Description == "" {
		result := errorResponse{
			Message: "Invalid request",
			Detail:  "Request body is invalid. Please see the documentation.",
		}
		return apiResponse(http.StatusBadRequest, result)
	}

	//assign an item id (uid)
	newItem.Id = uuid.New().String()

	//TODO: validate item (quantitiy, price name, description)

	//TODO: save item to db

	return apiResponse(http.StatusOK, newItem)
}

func getItem(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {

	newItem := item{
		Id:          uuid.NewString(),
		Name:        "New item",
		Description: "Good stuff",
		Price:       1.99,
		Quantity:    23,
		Reviews: []review{
			{
				Id:         uuid.NewString(),
				ReviewerId: "rtyildirim",
				Review:     "Very good I am happy",
				Rating:     5,
				Time:       time.Now().Format("RFC1123"),
			},
			{
				Id:         uuid.NewString(),
				ReviewerId: "jschmuk",
				Review:     "Very bad I am unhappy",
				Rating:     5,
				Time:       time.Now().Add(-64 * time.Hour).Format("RFC1123"),
			},
		},
	}

	newItem.Id = uuid.New().String()

	//TODO: validate item (quantitiy, price name, description)

	//TODO: save item to db

	return apiResponse(http.StatusOK, newItem)
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
