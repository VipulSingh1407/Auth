# User Authentication API

This is a Node.js-based user authentication API that supports user registration, login, OTP verification, and password reset functionalities.

## Project Structure

backend/ 
.env 
app.js
config/
  db.js
controllers/ 
  authController.js
models/ 
   User.js
package.json
routes/ 
   authRoutes.js
server.js
utils/ 
   sendEmail.js

## Installation

1. Clone the repository.
2. Navigate to the `backend` directory.
3. Install the dependencies using npm:

```sh
npm install

Create a .env file in the backend directory and add the following environment variables:

MONGO_URI=your_mongodb_connection_string
EMAIL=your_email_address
EMAIL_PASSWORD=your_email_password
JWT_SECRET=your_jwt_secret_key


Running the Server
Start the server using the following command:

npm start

Project Files
server.js
This file is the entry point of the application. It loads environment variables, connects to the MongoDB database, and starts the Express server.

app.js
This file sets up the Express application, including middleware for CORS and JSON parsing. It also defines the routes for the authentication API.

config/db.js
This file contains the configuration for connecting to the MongoDB database using Mongoose.

controllers/authController.js
This file contains the controller functions for handling authentication-related requests, including:

requestOTP: Sends an OTP to the user's email for registration.
verifyOTP: Verifies the OTP and registers the user.
login: Authenticates the user and returns a JWT token.
requestPasswordResetOTP: Sends an OTP to the user's email for password reset.
resetPassword: Resets the user's password after verifying the OTP.
models/User.js
This file defines the Mongoose schema and model for the User collection in MongoDB.

routes/authRoutes.js
This file defines the routes for the authentication API and maps them to the corresponding controller functions.

utils/sendEmail.js
This file contains a utility function for sending emails using Nodemailer.

API Endpoints
POST /api/auth/request-otp
Request an OTP for user registration.

Request Body:

POST /api/auth/verify-otp
Verify the OTP and register the user.

Request Body:

POST /api/auth/login
Authenticate the user and return a JWT token.

Request Body:

POST /api/auth/request-password-reset-otp
Request an OTP for password reset.

Request Body:

POST /api/auth/reset-password
Reset the user's password after verifying the OTP.

Request Body:

License
This project is licensed under the MIT License. ```