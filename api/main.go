package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)
var jwtSecret = []byte("abdullah55")
var mongoURI = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
var client *mongo.Client
var usersCollection *mongo.Collection

type login struct{
	Email string `json:"email"`
	Password string `json:"password"`
}

type User struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	Gender      string `json:"gender"`
	CompanyName string `json:"companyname"`
}

type claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
	
}
// init function to set up MongoDB connection
func init() {
	initMongo()
}

func initMongo() {
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}
	usersCollection = client.Database("test").Collection("users")
}


func Login(w http.ResponseWriter, r *http.Request) {
	var loginData login;
	if err :=json.NewDecoder(r.Body).Decode(&loginData);err !=nil {
		http.Error(w,"invalid request body",http.StatusBadRequest)
		return
	}

      var existingUser User
	  
	  err :=usersCollection.FindOne(context.TODO(),map[string]string{"email":loginData.Email}).Decode(&existingUser)

	  if err !=nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	  }
	  err =bcrypt.CompareHashAndPassword([]byte(existingUser.Password),[]byte(loginData.Password))

	  if err !=nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	  }

	  claims := &claims{
		Email: loginData.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(20 * time.Hour).Unix(),
		},
	}

		  token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
          tokenString, err := token.SignedString(jwtSecret)
		

		  if err!= nil {
                http.Error(w, "Could not create token", http.StatusInternalServerError)
                return
          }

		  w.WriteHeader(http.StatusOK)
          json.NewEncoder(w).Encode(map[string]string{"token": tokenString})

	}

func sigup(w http.ResponseWriter, r *http.Request) {

	var user User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var existingUser User
	err := usersCollection.FindOne(context.TODO(), map[string]string{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}



	hasshedpassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}



	
	user.Password = string(hasshedpassword)


	_, err = usersCollection.InsertOne(context.TODO(), user)

	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "User created successfully",
		"data": map[string]interface{}{
			"Username":  user.Username,
			"email": user.Email,
			"Password":  user.Password,
			"CompanyName":   user.CompanyName,
			"Gender":   user.Gender,

		},
	})
	
}

























// Handler function to handle incoming requests
func Handler(w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()

	// Route to handle a simple GET request
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "hello worldd",
		})
	}).Methods("GET")
	router.HandleFunc("/signup", sigup).Methods("POST")
	router.HandleFunc("/Login", Login).Methods("POST")

	
	// CORS handler setup
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(router)

	// Serve HTTP with CORS enabled
	corsHandler.ServeHTTP(w, r)
}
