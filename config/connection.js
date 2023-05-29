require("dotenv").config();
const mongoose = require("mongoose");

function getConnectionInfo() {

  // To override the database name, set the DATABASE_NAME environment variable in the .env file
  const DATABASE_NAME = process.env.DATABASE_NAME || "node-login-passport";

  return {
    DATABASE_URL: process.env.DATABASE_URL,
    DATABASE_NAME: process.env.DATABASE_NAME
  }
}


module.exports = {
  getConnectionInfo
}