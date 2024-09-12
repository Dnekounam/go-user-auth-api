# Go JWT Authentication API

This project is a simple REST API built in **Go** (Golang) using the **Gin** web framework, which provides user authentication with **JWT (JSON Web Tokens)**. It supports user registration, login, protected routes, token expiration, and token refresh mechanisms.

## Features

- **User Registration**: Create a new user with a username and password.
- **User Login**: Authenticate a user and issue JWT access and refresh tokens.
- **JWT Authentication**: Protect routes using JWT access tokens.
- **Token Expiration**: Access tokens expire after a short period (default: 5 minutes).

- ## Tech Stack

- [Go](https://golang.org/) (Golang)
- [Gin](https://gin-gonic.com/) Web Framework
- [SQLite](https://www.sqlite.org/index.html) Database
- [bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) for password hashing
- [JWT](https://jwt.io/) for authentication

The server will start and listen on port `9092`.

### Endpoints

#### 1. Register a new user

- **URL**: `/register`
- **Method**: `POST`
- **Payload**:
    ```json
    {
        "username": "your_username",
        "password": "your_password"
    }
    ```
- **Response**:
    ```json
    {
        "message": "Registration successful"
    }
    ```

#### 2. Login and receive tokens

- **URL**: `/login`
- **Method**: `POST`
- **Payload**:
    ```json
    {
        "username": "your_username",
        "password": "your_password"
    }
    ```
- **Response**:
    ```json
    {
        "access_token": "your_access_token",
        "refresh_token": "your_refresh_token"
    }
    ```

#### 3. Access a protected route

- **URL**: `/profile`
- **Method**: `GET`
- **Headers**:
    - `Authorization: Bearer <your_access_token>`
- **Response**:
    ```json
    {
        "message": "Welcome to your profile",
        "username": "your_username"
    }
    ```
