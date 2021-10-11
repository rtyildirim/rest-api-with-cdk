package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

type errorResponse struct {
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

type loginResponse struct {
	Token        string `json:"token"`
	TokenType    string `json:"tokenType"`
	IdToken      string `json:"idToken"`
	RefreshToken string `json:"refreshToken"`
	Expires      int64  `json:"expires"`
}

type genericResponse struct {
	Status string `json:"status"`
}

type userType struct {
	UserName    string `json:"userName"`
	Password    string `json:"password"`
	NewPassword string `json:"newPassword"`
}

type refreshTokenInput struct {
	RefreshToken string `json:"refreshToken"`
	UserName     string `json:"userName"`
}

var userPoolId string
var clientId string
var clientSecret string
var awsRegion string

func main() {

	userPoolId = os.Getenv("USER_POOL_ID")
	if userPoolId == "" {
		log.Fatal("Missing USER_POOL_ID")
	}
	clientId = os.Getenv("CLIENT_ID")
	if clientId == "" {
		log.Fatal("Missing CLIENT_ID")
	}
	awsRegion = os.Getenv("AWS_REGION")
	if awsRegion == "" {
		log.Fatal("Missing AWS Region")
	}

	mySession := session.Must(session.NewSession())
	svc := cognito.New(mySession, aws.NewConfig().WithRegion(awsRegion))

	input := cognito.DescribeUserPoolClientInput{
		ClientId:   aws.String(clientId),
		UserPoolId: &userPoolId,
	}

	csOut, err := svc.DescribeUserPoolClient(&input)
	if err != nil {
		log.Fatal(fmt.Sprintf("unable to describe user pool client. (%v)", err))
	}

	clientSecret = *csOut.UserPoolClient.ClientSecret
	log.Println("Succesfully obtained client secret")

	lambda.Start(handler)
}

func handler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.Path {
	case "/login":
		return loginHandler(req)
	case "/change-password":
		return changePasswordHandler(req)
	case "/refresh-token":
		return refreshTokenHandler(req)
	default:
		return unhandledPath(req)
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

func refreshTokenHandler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.HTTPMethod {
	case "POST":
		return refreshToken(req)
	default:
		return unhandledMethod(req)
	}
}

func changePasswordHandler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.HTTPMethod {
	case "POST":
		return changeUserPassword(req)
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

	log.Printf("Logging user %s in\n", user.UserName)

	out, err := authenticateUser(user)
	if err != nil {
		return apiResponse(http.StatusForbidden, errorResponse{
			Message: "Forbidden",
			Detail:  err.Error(),
		})
	}

	expires := *out.ExpiresIn

	resp := loginResponse{
		Token:        *out.AccessToken,
		TokenType:    *out.TokenType,
		IdToken:      *out.IdToken,
		RefreshToken: *out.RefreshToken,
		Expires:      expires,
	}

	return apiResponse(http.StatusOK, resp)
}

func refreshToken(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {

	input := refreshTokenInput{}

	err := json.Unmarshal([]byte(req.Body), &input)
	if err != nil || input.RefreshToken == "" || input.UserName == "" {
		result := errorResponse{
			Message: "Invalid request",
			Detail:  "Request body must include refreshToken",
		}
		return apiResponse(http.StatusBadRequest, result)
	}

	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(input.UserName + clientId))
	secretHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	iaInput := cognito.AdminInitiateAuthInput{
		AuthFlow:   aws.String("REFRESH_TOKEN_AUTH"),
		ClientId:   aws.String(clientId),
		UserPoolId: aws.String(userPoolId),
		AuthParameters: map[string]*string{
			"REFRESH_TOKEN": aws.String(input.RefreshToken),
			"SECRET_HASH":   aws.String(secretHash),
		},
	}
	mySession := session.Must(session.NewSession())
	svc := cognito.New(mySession, aws.NewConfig().WithRegion(awsRegion))

	out, err := svc.AdminInitiateAuth(&iaInput)

	if err != nil {
		return apiResponse(http.StatusForbidden, errorResponse{
			Message: "Forbidden",
			Detail:  err.Error(),
		})
	}

	resp := loginResponse{
		Token:     *out.AuthenticationResult.AccessToken,
		TokenType: *out.AuthenticationResult.TokenType,
		IdToken:   *out.AuthenticationResult.IdToken,
		Expires:   *out.AuthenticationResult.ExpiresIn,
	}

	return apiResponse(http.StatusOK, resp)
}

func changeUserPassword(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {

	user := userType{}

	err := json.Unmarshal([]byte(req.Body), &user)

	//TODO: validate new password
	if err != nil || user.UserName == "" || user.Password == "" || user.NewPassword == "" {
		result := errorResponse{
			Message: "Invalid request",
			Detail:  "Request body must include username and password",
		}
		return apiResponse(http.StatusBadRequest, result)
	}

	err = changePassword(user)
	if err != nil {
		return apiResponse(http.StatusForbidden, errorResponse{
			Message: "Forbidden",
			Detail:  err.Error(),
		})
	}

	resp := genericResponse{
		Status: "Password succesfully changed",
	}

	return apiResponse(http.StatusOK, resp)
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

func authenticateUser(user userType) (*cognito.AuthenticationResultType, error) {
	//TODO: check if password change required
	var res *cognito.AuthenticationResultType
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(user.UserName + clientId))
	secretHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	iaInput := cognito.AdminInitiateAuthInput{
		AuthFlow:   aws.String("ADMIN_NO_SRP_AUTH"),
		ClientId:   aws.String(clientId),
		UserPoolId: aws.String(userPoolId),
		AuthParameters: map[string]*string{
			"USERNAME":    aws.String(user.UserName),
			"PASSWORD":    aws.String(user.Password),
			"SECRET_HASH": aws.String(secretHash),
		},
	}
	mySession := session.Must(session.NewSession())
	svc := cognito.New(mySession, aws.NewConfig().WithRegion(awsRegion))

	out, err := svc.AdminInitiateAuth(&iaInput)
	if err == nil {
		res = out.AuthenticationResult
	} else {
		log.Printf("Error admin init auth %v\n", err)
	}
	return res, err
}

func changePassword(user userType) error {

	//To change password, first validate initial password is correct
	//Then change password.
	_, err := authenticateUser(user)
	if err != nil {
		return (err)
	}

	spInput := cognito.AdminSetUserPasswordInput{
		UserPoolId: aws.String(userPoolId),
		Username:   aws.String(user.UserName),
		Password:   aws.String(user.NewPassword),
		Permanent:  aws.Bool(true),
	}

	mySession := session.Must(session.NewSession())
	svc := cognito.New(mySession, aws.NewConfig().WithRegion(awsRegion))
	_, err = svc.AdminSetUserPassword(&spInput)

	return err
}
