const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const client = new MongoClient(process.env.MONGODB_SERVER);

const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utility-functions");

const saltRounds = 10;

async function insertUser(user) {
  try {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    const usersCollection = db.collection("users");
    user.password = await bcrypt.hash(user.password, saltRounds);
    return await usersCollection.insertOne(user);
  } catch (error) {
    throw error;
  } finally {
    client.close();
  }
}

async function checkUserIdentity(user) {
  try {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    const usersCollection = db.collection("users");
    let existingUser = await usersCollection.findOne({ email: user.email });
    if (existingUser) {
      let passwordCheck = await bcrypt.compare(
        user.password,
        existingUser.password
      );
      if (passwordCheck === true) {
        return {
          accessToken: await generateAccessToken(
            existingUser.email,
            existingUser.role
          ),
          refreshToken: await generateRefreshToken(
            existingUser.email,
            existingUser.role
          ),
        };
      } else {
        return {
          message: "Please check your password! Password is wrong!",
          success: false,
        };
      }
    } else {
      return {
        message: "Please check your email Id! It does not exist!",
        success: false,
      };
    }
  } catch (error) {
    throw error;
  } finally {
    client.close();
  }
}

module.exports = {
  insertUser,
  checkUserIdentity,
};
