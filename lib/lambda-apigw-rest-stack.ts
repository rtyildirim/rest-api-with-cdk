import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda';
import { LambdaIntegration, MethodLoggingLevel, RestApi, CfnAuthorizer, AuthorizationType, Authorizer } from "@aws-cdk/aws-apigateway"
import { PolicyStatement } from '@aws-cdk/aws-iam';
import * as dynamodb from '@aws-cdk/aws-dynamodb';
import * as kms from '@aws-cdk/aws-kms';
import * as secretsmanager from '@aws-cdk/aws-secretsmanager';
import * as cognito from '@aws-cdk/aws-cognito';


export class LambdaApigwRestStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    //const existingUserPool = cognito.UserPool.fromUserPoolId(this, 'RestApiUserPool', 'us-west-2_btpuZn6Ej')

    const restApiUserPool = new cognito.UserPool(this, 'ApiUserPool', {
      userPoolName: 'rest-api-userpool',
      selfSignUpEnabled: false, //TODO: this can be made tru to enable self signup
      userInvitation: {
        emailSubject: 'Invite to join our rest api!',
        emailBody: 'Hello {username}, you have been invited to join our rest-api! Your temporary password is {####}',
        smsMessage: 'Hello {username}, you have been invited to join our rest-api! Your temporary password is {####}'
      },

      signInAliases: {
        username: true,
        email: true
      },

      standardAttributes: {
        fullname: {
          required: true,
          mutable: false,
        },
        address: {
          required: false,
          mutable: true,
        },
      },

      // mfa: cognito.Mfa.REQUIRED,
      // mfaSecondFactor: {
      //   sms: true,
      //   otp: true,
      // },

      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
        tempPasswordValidity: cdk.Duration.days(3),
      },

      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,


      // emailSettings: {
      //   from: 'noreply@tolga24.com',
      //   replyTo: 'support@tolga24.com',
      // },
    });

    const dmePosGroup = new cognito.CfnUserPoolGroup(this, "DmePosAdminGroup", {
      groupName: "dmeposAdmin",
      description: "User group for dmepos ontology admins",
      userPoolId: restApiUserPool.userPoolId,
    })

    const superAdminGroup = new cognito.CfnUserPoolGroup(this, "SuperAdminGroup", {
      groupName: "admin",
      description: "User group for service admins",
      userPoolId: restApiUserPool.userPoolId,
    })


    const appClient = restApiUserPool.addClient('customer-app-client', {
      authFlows: {
        userPassword: true,
        userSrp: true,
        adminUserPassword: true,
      },
      accessTokenValidity: cdk.Duration.minutes(60),
      idTokenValidity: cdk.Duration.minutes(60),
      refreshTokenValidity: cdk.Duration.days(30),
      enableTokenRevocation: true,
      generateSecret: true,

    });

    const tokenKey = new kms.Key(this, 'MyKey', {
      alias: 'rest-api-token-key',
      keySpec: kms.KeySpec.RSA_4096,
      keyUsage: kms.KeyUsage.SIGN_VERIFY
    });

    const restApiSecret = new secretsmanager.Secret(this, 'RestApiSecret', {
      secretName: "lambda-rest-api-secret",
    });

    const userTable = new dynamodb.Table(this, "UserTable", {
      tableName: "userTable",
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      partitionKey: { name: 'userName', type: dynamodb.AttributeType.STRING },
      pointInTimeRecovery: false,
    });

    const itemTable = new dynamodb.Table(this, "ItemTable", {
      tableName: "itemTable",
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      pointInTimeRecovery: false,
    });

    itemTable.addGlobalSecondaryIndex({
      indexName: 'ownerIndex',
      partitionKey: { name: 'owner', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    const reviewTable = new dynamodb.Table(this, "ReviewTable", {
      tableName: "reviewTable",
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      pointInTimeRecovery: false,
    });

    reviewTable.addGlobalSecondaryIndex({
      indexName: 'reviewerIdIndex',
      partitionKey: { name: 'reviewerId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'itemId', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    reviewTable.addGlobalSecondaryIndex({
      indexName: 'itemIdIndex',
      partitionKey: { name: 'itemId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'reviewerId', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });


    const lambdaFunction = new lambda.Function(this, "LambdaApiFunction", {
      runtime: lambda.Runtime.GO_1_X,
      handler: "main",
      code: lambda.Code.fromAsset("./api-lambda/lambda-api-function.zip"),
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        'KMS_TOKEN_KEY_ID': tokenKey.keyId,
        'SECRET_NAME': restApiSecret.secretName,
        'USER_POOL_ID': restApiUserPool.userPoolId,
        'CLIENT_ID': appClient.userPoolClientId,
      }
    });


    const adminLambdaFunction = new lambda.Function(this, "AdminLambdaApiFunction", {
      runtime: lambda.Runtime.GO_1_X,
      handler: "main",
      code: lambda.Code.fromAsset("./admin-lambda/lambda-admin-api-function.zip"),
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        'USER_POOL_ID': restApiUserPool.userPoolId,
        'CLIENT_ID': appClient.userPoolClientId,
      }
    });

    // grant the lambda role read/write permissions to our table
    userTable.grantReadWriteData(lambdaFunction);
    itemTable.grantReadWriteData(lambdaFunction);
    reviewTable.grantReadWriteData(lambdaFunction);

    //create new rest api on Api Gateway
    const restApi = new RestApi(this, "LambdaApiFunctionRestApi", {
      description: "Rest API Demo Using CDK",
      defaultCorsPreflightOptions: {
        allowHeaders: ["*"],
        allowMethods: ['OPTIONS', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        allowCredentials: true,
        allowOrigins: ["*"],
      },
      deployOptions: {
        stageName: "beta",
        metricsEnabled: true,
        loggingLevel: MethodLoggingLevel.INFO,
        dataTraceEnabled: true,
      },
    })

    const auth = new CfnAuthorizer(this, 'APIGatewayAuthorizer', {
      name: 'customer-authorizer',
      identitySource: 'method.request.header.Authorization',
      providerArns: [restApiUserPool.userPoolArn],
      restApiId: restApi.restApiId,
      type: AuthorizationType.COGNITO,
    });

    //Create paths and methods
    const users = restApi.root.addResource('users', {});
    const getUserMethod = users.addMethod("GET", new LambdaIntegration(lambdaFunction, {}), {
      apiKeyRequired: true,
    })
    const postUserMethod = users.addMethod("POST", new LambdaIntegration(lambdaFunction, {}), {
      apiKeyRequired: false,
    })

    const items = restApi.root.addResource('items', {});
    const getItemsMethod = items.addMethod("GET", new LambdaIntegration(lambdaFunction, {}), {
      apiKeyRequired: true,
    })
    const postItemsMethod = items.addMethod("POST", new LambdaIntegration(lambdaFunction, {}), {
      apiKeyRequired: false,
    })

    const login = restApi.root.addResource('login', {});
    const postLoginMethod = login.addMethod("POST", new LambdaIntegration(lambdaFunction, {}), {
      apiKeyRequired: false,
    })

    const review = restApi.root.addResource('reviews', {});
    const postReview = review.addMethod("POST", new LambdaIntegration(lambdaFunction, {}), {
      apiKeyRequired: false,
    })
    const getReviews = review.addMethod("GET", new LambdaIntegration(lambdaFunction, {}), {
      apiKeyRequired: true,
    })

    const ontologies = restApi.root.addResource('ontologies', {});
    const ontology = ontologies.addResource('{ontology}', {});
    const getOntologyMethod = ontology.addMethod("GET", new LambdaIntegration(lambdaFunction, {}), {
      apiKeyRequired: false,
      authorizationType: AuthorizationType.COGNITO,
      authorizer: { authorizerId: auth.ref },
     //authorizationScopes
    });


    //create usage plan
    const plan = restApi.addUsagePlan('UsagePlan', {
      name: 'UsersUsagePlan',
      description: "Usage plan for rest api",
      apiStages: [{ api: restApi, stage: restApi.deploymentStage }],
      throttle: {
        rateLimit: 10,
        burstLimit: 2
      }
    });

    //create api key and add it to usage plan
    const key = restApi.addApiKey('ApiKey');
    plan.addApiKey(key);

    const adminApi = new RestApi(this, "LambdaApiFunctionAdminApi", {
      description: "Admin API Demo Using CDK",
      defaultCorsPreflightOptions: {
        allowHeaders: ["*"],
        allowMethods: ['OPTIONS', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        allowCredentials: true,
        allowOrigins: ["*"],
      },
      deployOptions: {
        stageName: "beta",
        metricsEnabled: true,
        loggingLevel: MethodLoggingLevel.INFO,
        dataTraceEnabled: true,
      },
    })

    const adminLogin = adminApi.root.addResource('login', {});
    const adminPostLoginMethod = adminLogin.addMethod("POST", new LambdaIntegration(adminLambdaFunction, {}), {
      apiKeyRequired: false,
    })

    const adminChangePassword = adminApi.root.addResource('change-password', {});
    const adminPostChangePasswordMethod = adminChangePassword.addMethod("POST", new LambdaIntegration(adminLambdaFunction, {}), {
      apiKeyRequired: false,
    })

    const adminRefreshToken = adminApi.root.addResource('refresh-token', {});
    const adminPostrefreshTokenMethod = adminRefreshToken.addMethod("POST", new LambdaIntegration(adminLambdaFunction, {}), {
      apiKeyRequired: false,
    })

    //allow lambda function to create log groups and write logs on CloudWatch
    const logPermission = new PolicyStatement();
    logPermission.addResources('arn:aws:logs:*:*:*');
    logPermission.addActions('logs:CreateLogGroup');
    logPermission.addActions('logs:CreateLogStream');
    logPermission.addActions('logs:PutLogEvents');
    lambdaFunction.addToRolePolicy(logPermission);

    const tokenKeyPermission = new PolicyStatement();
    tokenKeyPermission.addResources(tokenKey.keyArn)
    tokenKeyPermission.addActions('kms:Decrypt');
    tokenKeyPermission.addActions('kms:Encrypt');
    tokenKeyPermission.addActions('kms:Sign');
    tokenKeyPermission.addActions('kms:Verify');
    tokenKeyPermission.addActions('kms:GetPublicKey');
    lambdaFunction.addToRolePolicy(tokenKeyPermission);

    const secretPermission = new PolicyStatement();
    secretPermission.addResources(restApiSecret.secretArn);
    secretPermission.addActions('secretsmanager:GetSecret');
    secretPermission.addActions('secretsmanager:GetSecretValue');
    lambdaFunction.addToRolePolicy(secretPermission);

    const userPoolPermission = new PolicyStatement();
    userPoolPermission.addResources(restApiUserPool.userPoolArn);
    userPoolPermission.addActions('cognito-identity:*');
    userPoolPermission.addActions('cognito-idp:*');
    userPoolPermission.addActions('cognito-sync:*');
    lambdaFunction.addToRolePolicy(userPoolPermission);

    adminLambdaFunction.addToRolePolicy(logPermission);
    adminLambdaFunction.addToRolePolicy(userPoolPermission);

    new cdk.CfnOutput(this, 'apiUrl', { value: restApi.url });
    new cdk.CfnOutput(this, 'adminApiUrl', { value: adminApi.url });
    new cdk.CfnOutput(this, 'userTable', { value: userTable.tableName });
    new cdk.CfnOutput(this, 'itemTable', { value: itemTable.tableName });
    new cdk.CfnOutput(this, 'reviewTable', { value: reviewTable.tableName });
  }
}
