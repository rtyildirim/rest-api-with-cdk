import * as cdk from '@aws-cdk/core';
import s3 = require('@aws-cdk/aws-s3');
import * as lambda from '@aws-cdk/aws-lambda';
import s3deploy = require('@aws-cdk/aws-s3-deployment');
import { LambdaIntegration, MethodLoggingLevel, RestApi } from "@aws-cdk/aws-apigateway"
import { PolicyStatement } from '@aws-cdk/aws-iam';

import path = require("path")


export class LambdaApigwRestStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const lambdaFunction = new lambda.Function(this, "LambdaApiFunction", {
      runtime: lambda.Runtime.GO_1_X,
      handler: "main",
      code: lambda.Code.fromAsset("./src/lambda-api-function.zip"),
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
    });

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

    const users = restApi.root.addResource('users', {});

    const getUserMethod = users.addMethod("GET", new LambdaIntegration(lambdaFunction, {}), {
      apiKeyRequired: true,
    })
    const postUserMethod = users.addMethod("POST", new LambdaIntegration(lambdaFunction, {}), {
      apiKeyRequired: true,
    })


    const plan = restApi.addUsagePlan('UsagePlan', {
      name: 'UsersUsagePlan',
      description: "Usage plan for rest api",
      apiStages: [{ api: restApi, stage: restApi.deploymentStage }],
      throttle: {
        rateLimit: 10,
        burstLimit: 2
      }
    });

    const key = restApi.addApiKey('ApiKey');
    plan.addApiKey(key);

    // plan.addApiStage({
    //   stage: restApi.deploymentStage,
    //   require: true,
    //   throttle: [
    //     {
    //       method: getUserMethod,
    //       throttle: {
    //         rateLimit: 10,
    //         burstLimit: 2
    //       }
    //     },
    //     {
    //       method: postUserMethod,
    //       throttle: {
    //         rateLimit: 10,
    //         burstLimit: 2
    //       }
    //     }
    //   ]
    // });


    const logPermission = new PolicyStatement();
    logPermission.addResources('arn:aws:logs:*:*:*');
    logPermission.addActions('logs:CreateLogGroup');
    logPermission.addActions('logs:CreateLogStream');
    logPermission.addActions('logs:PutLogEvents');
    lambdaFunction.addToRolePolicy(logPermission);

    new cdk.CfnOutput(this, 'apiUrl', { value: restApi.url });

  }
}
