package main

import (
	//"aws-lambda-in-go-lang/pkg/handlers"
	"fmt"
	"log"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"encoding/json"
)

type okResponse struct {
	UserName string `json:"userName"`
	Email    string `json:"emailName"`
	Address  string `json:"address"`
	Id       int    `json:"id"`
}

type errorResponse struct {
	Message string `json:"message"`
	Detail  string `json:"Detail"`
}

func main() {
	lambda.Start(handler)
}

func handler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	log.Println("reuqest path", req.Path)
	log.Println("request body", req.Body)
	log.Println("request query params", req.QueryStringParameters)

	log.Println("req", req)

	switch req.Path {
	case "/users":
		return UserHandler(req)
	default:
		return UnhandledMethod(req)
	}
}

func UserHandler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	log.Println("reuqest path", req.HTTPMethod)
	switch req.HTTPMethod {
	case "GET":
		log.Println("Processing GET")
		return GetUser(req)
	case "POST":
		log.Println("Processing POST")
		return UnhandledMethod(req)
	default:
		return UnhandledMethod(req)
	}
}

func GetUser(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {

	result := okResponse{
		UserName: "Tolga Yildirim",
		Email:    "blah@gmail.com",
		Address:  "My Address",
		Id:       1,
	}
	return apiResponse(http.StatusOK, result)
}

func UnhandledMethod(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	result := errorResponse{
		Message: fmt.Sprintf("%s method is not supported for %s path", req.HTTPMethod, req.Path),
		Detail:  "Try again",
	}
	return apiResponse(http.StatusNotFound, result)
}

func UnhandledPath(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
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
