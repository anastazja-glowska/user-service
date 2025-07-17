# 📸 User Management REST API

A lightweight and fully-tested **Spring Boot** application that provides a RESTful API for managing users. Built with clean code principles, layered architecture, and full test coverage.

## 🚀 Features

- ✅ User registration via `POST /users`
- 🛡️ Input validation and password encryption
- 📦 Layered structure (Controller → Service → Repository)
- 🔐 Secure password storage with BCrypt
- 🌐 RESTful JSON responses

## 🧪 Testing

- 🧩 **Unit & Web Layer Tests** with JUnit and MockMvc
- 🧪 **Integration Tests** using TestContainers and real MySQL database
- 🔄 Full test coverage for business logic and endpoints

## 🛠️ Tech Stack

- Java 17
- Spring Boot 3
- Spring Data JPA
- MySQL (via TestContainers)
- REST Assured (for endpoint testing)
- JUnit 5
- Mockito
- ModelMapper

## 🧠 What I learned

This project helped me strengthen my skills in:
- Designing clean REST APIs
- Writing testable and modular code
- Working with TestContainers and dynamic properties
- Understanding the importance of integration vs unit testing
- Using Git and GitHub in real-world workflow

## 📁 How to run

1. Clone the repo
2. Run `./mvnw test` to verify everything works
3. Start the app with your favorite IDE or `./mvnw spring-boot:run`

---

🎯 *Built 100% by me as part of hands-on learning and portfolio development.*

