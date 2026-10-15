"use strict";

const serverlessExpress = require("@codegenie/serverless-express");
const { app } = require("./server");
// API Gateway HTTP API v2 owns TLS. Authentication and authorization execute
// inside the Express app, including the OIDC callback and session CSRF checks.
exports.handler = serverlessExpress({ app });
