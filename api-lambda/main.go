package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	//"github.com/golang-jwt/jwt"
	//"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
)

type secretType struct {
	UserPoolId   string `json:"userPoolId"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

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
	Item    itemDdb      `json:"item"`
	Reviews []reviewType `json:"reviews"`
}

type reviewType struct {
	Id         string `json:"id"`
	ItemId     string `json:"itemId"`
	ReviewerId string `json:"reviewerId"`
	Review     string `json:"review"`
	Rating     int    `json:"rating"`
	Time       string `json:"time"`
}

type errorResponse struct {
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

type loginResponse struct {
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
}

type ontologyResponse struct {
	Ontology string `json:"ontology"`
}

var tokenKeyId string
var awsRegion string
var userPoolId string

func main() {
	tokenKeyId = os.Getenv("KMS_TOKEN_KEY_ID")
	if tokenKeyId == "" {
		log.Fatal("Missing KMS Key ID")
	}
	awsRegion = os.Getenv("AWS_REGION")
	if awsRegion == "" {
		log.Fatal("Missing AWS Region")
	}
	userPoolId = os.Getenv("USER_POOL_ID")
	if userPoolId == "" {
		log.Fatal("Missing USER_POOL_ID")
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
	case "/reviews":
		return reviewHandler(req)
	default:
		if strings.Contains(req.Path, "/ontologies/") {
			return ontologyHandler(req)
		} else {
			return unhandledPath(req)
		}
	}
}

func ontologyHandler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.HTTPMethod {
	case "GET":
		return getOntology(req)
	default:
		return unhandledMethod(req)
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

func reviewHandler(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	switch req.HTTPMethod {
	case "GET":
		return getReviews(req)
	case "POST":
		return createReview(req)
	default:
		return unhandledMethod(req)
	}
}

func loginUser(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {

	secret, err := getSecrets()
	if err != nil {
		result := errorResponse{
			Message: "Internal server error while fetching secret",
			Detail:  err.Error(),
		}
		return apiResponse(http.StatusInternalServerError, result)
	}

	user := userType{}

	err = json.Unmarshal([]byte(req.Body), &user)
	if err != nil || user.UserName == "" || user.Password == "" {
		result := errorResponse{
			Message: "Invalid request",
			Detail:  "Request body must include username and password",
		}
		return apiResponse(http.StatusBadRequest, result)
	}

	mySession := session.Must(session.NewSession())

	// Create a CognitoIdentityProvider client with additional configuration
	svc := cognito.New(mySession, aws.NewConfig().WithRegion(awsRegion))

	mac := hmac.New(sha256.New, []byte(secret.ClientSecret))
	mac.Write([]byte(user.UserName + secret.ClientId))
	secretHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	adminInitiateAuthRequest := cognito.AdminInitiateAuthInput{
		AuthFlow:   aws.String("ADMIN_NO_SRP_AUTH"),
		ClientId:   aws.String(secret.ClientId),
		UserPoolId: aws.String(secret.UserPoolId),
		AuthParameters: map[string]*string{
			"USERNAME":    aws.String(user.UserName),
			"PASSWORD":    aws.String(user.Password),
			"SECRET_HASH": aws.String(secretHash),
		},
	}

	out, err := svc.AdminInitiateAuth(&adminInitiateAuthRequest)
	if err != nil {
		return apiResponse(http.StatusForbidden, errorResponse{
			Message: "Forbidden",
			Detail:  err.Error(),
		})
	}

	expires := *out.AuthenticationResult.ExpiresIn

	resp := loginResponse{
		Token:   *out.AuthenticationResult.AccessToken,
		Expires: expires,
	}

	return apiResponse(http.StatusOK, resp)
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
				Reviews: []reviewType{},
			}
			//TODO: add reviews
			out = append(out, item)
		}
	}

	return apiResponse(http.StatusOK, out)
}

func getOntology(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	ontName := strings.Replace(req.Path, "/ontologies/", "", 1)

	cols := strings.Split(req.Headers["Authorization"], " ")

	token := ""

	if len(cols) > 0 {
		token = cols[1]
	}

	authorized, err := authorize(token, ontName+"Admin")

	if err != nil {
		return apiResponse(http.StatusUnauthorized, errorResponse{
			Message: "You cannot view ontology " + ontName,
			Detail:  err.Error(),
		})
	}

	if !authorized {
		return apiResponse(http.StatusUnauthorized, errorResponse{
			Message: "You are not a member of " + ontName + "Admin group",
			Detail:  err.Error(),
		})
	}

	return apiResponse(http.StatusOK, ontologyResponse{
		Ontology: ontName,
	})
}

func getReviews(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)

	tableName := "reviewTable"

	scanInput := &dynamodb.ScanInput{
		TableName: aws.String(tableName),
	}

	res, err := svc.Scan(scanInput)
	if err != nil {
		return apiResponse(http.StatusInternalServerError, errorResponse{
			Message: "Unable to get reviews",
			Detail:  err.Error(),
		})
	}

	out := []reviewType{}

	var record reviewType

	for _, j := range res.Items {
		err = dynamodbattribute.UnmarshalMap(j, &record)
		if err == nil {
			out = append(out, record)
		}
	}

	return apiResponse(http.StatusOK, out)
}

func createReview(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	var review reviewType

	err := json.Unmarshal([]byte(req.Body), &review)
	if err != nil || review.ItemId == "" || review.ReviewerId == "" || review.Review == "" {
		result := errorResponse{
			Message: "Invalid request",
			Detail:  "Request body is invalid. Please see the documentation.",
		}
		return apiResponse(http.StatusBadRequest, result)
	}

	//TODO: validate if user exists, item exists

	review.Id = uuid.NewString()
	review.Time = time.Now().Format(time.RFC3339)

	err = storeReview(review)
	if err != nil {
		result := errorResponse{
			Message: "Unable to store new review",
			Detail:  err.Error(),
		}
		return apiResponse(http.StatusInternalServerError, result)
	}

	return apiResponse(http.StatusOK, review)
}

func storeReview(review reviewType) error {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := dynamodb.New(sess)

	nr, err := dynamodbattribute.MarshalMap(review)
	if err != nil {
		return err
	}

	tableName := "reviewTable"

	input := &dynamodb.PutItemInput{
		Item:      nr,
		TableName: aws.String(tableName),
	}

	_, err = svc.PutItem(input)

	return err
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

func authorize(token string, requiredGroup string) (bool, error) {

	out, err := jwt.Parse(token, verifyToken)
	if err != nil {
		return false, err
	}

	//TODO: more validation of token
	if !out.Valid {
		return false, errors.New("token not valid")
	}

	groups := getGroups(out.Claims)

	groupContainsRequiredName := false

	for _, grp := range groups {
		if grp == requiredGroup {
			groupContainsRequiredName = true
		}
	}
	if !groupContainsRequiredName {
		return false, fmt.Errorf("user not a member of %s group", requiredGroup)
	}
	return true, nil
}

func getGroups(claims jwt.Claims) []string {
	if claim, ok := claims.(jwt.MapClaims); ok {
		grps := fmt.Sprintf("%v", claim["cognito:groups"])
		grps = strings.Replace(grps, "[", "", -1)
		grps = strings.Replace(grps, "]", "", -1)
		return strings.Split(grps, " ")
	}
	return []string{}
}

func getSecrets() (secretType, error) {
	res := secretType{}
	secretName := os.Getenv("SECRET_NAME") //"lambda-rest-api-secret-HOrKhw"
	if secretName == "" {
		return res, errors.New("missing SECRET_NAME")
	}

	region := os.Getenv("AWS_REGION") //"us-west-2"
	if region == "" {
		return res, errors.New("missing AWS_REGION")
	}

	sess, err := session.NewSession()
	if err != nil {
		return res, err
	}
	//Create a Secrets Manager client
	svc := secretsmanager.New(sess, aws.NewConfig().WithRegion(region))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := svc.GetSecretValue(input)
	if err != nil {
		fmt.Println(err.Error())
		return res, err
	}

	var secretString string
	if result.SecretString != nil {
		secretString = *result.SecretString
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			return res, err
		}
		secretString = string(decodedBinarySecretBytes[:len])
	}

	if err := json.Unmarshal([]byte(secretString), &res); err != nil {
		return res, err
	}
	return res, nil
}

func verifyToken(token *jwt.Token) (interface{}, error) {
	// make sure to replace this with your actual URL
	// https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html#amazon-cognito-user-pools-using-tokens-step-2
	jwksURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", awsRegion, userPoolId)
	keySet, err := jwk.Fetch(jwksURL)

	if err != nil {
		return nil, err
	}

	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("kid header not found")
	}
	keys := keySet.LookupKeyID(kid)

	if len(keys) == 0 {
		return nil, fmt.Errorf("key %v not found", kid)
	}
	var raw interface{}
	return raw, keys[0].Raw(&raw)
}
