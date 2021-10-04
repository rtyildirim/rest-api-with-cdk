import * as cdk from '@aws-cdk/core';
import s3 = require('@aws-cdk/aws-s3');
import * as lambda from '@aws-cdk/aws-lambda';
import s3deploy = require('@aws-cdk/aws-s3-deployment');
import { LambdaIntegration, MethodLoggingLevel, RestApi } from "@aws-cdk/aws-apigateway"
import { PolicyStatement } from '@aws-cdk/aws-iam';
import * as dynamodb from '@aws-cdk/aws-dynamodb';
import * as kms from '@aws-cdk/aws-kms';


export class LambdaApigwRestStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const tokenKey = new kms.Key(this, 'MyKey', {
      alias: 'rest-api-token-key',
      keySpec: kms.KeySpec.RSA_4096,
      keyUsage: kms.KeyUsage.SIGN_VERIFY
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
      partitionKey: {name: 'owner', type: dynamodb.AttributeType.STRING},
      sortKey: {name: 'id', type: dynamodb.AttributeType.STRING},
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
      partitionKey: {name: 'reviewerId', type: dynamodb.AttributeType.STRING},
      sortKey: {name: 'itemId', type: dynamodb.AttributeType.STRING},
      projectionType: dynamodb.ProjectionType.ALL,
    });

    reviewTable.addGlobalSecondaryIndex({
      indexName: 'itemIdIndex',
      partitionKey: {name: 'itemId', type: dynamodb.AttributeType.STRING},
      sortKey: {name: 'reviewerId', type: dynamodb.AttributeType.STRING},
      projectionType: dynamodb.ProjectionType.ALL,
    });


    const lambdaFunction = new lambda.Function(this, "LambdaApiFunction", {
      runtime: lambda.Runtime.GO_1_X,
      handler: "main",
      code: lambda.Code.fromAsset("./src/lambda-api-function.zip"),
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        'KMS_TOKEN_KEY_ID': tokenKey.keyId,
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
    lambdaFunction.addToRolePolicy(tokenKeyPermission);

    new cdk.CfnOutput(this, 'apiUrl', { value: restApi.url });
    new cdk.CfnOutput(this, 'userTable', { value: userTable.tableName });
    new cdk.CfnOutput(this, 'itemTable', { value: itemTable.tableName });
    new cdk.CfnOutput(this, 'reviewTable', { value: reviewTable.tableName });

  }
}
