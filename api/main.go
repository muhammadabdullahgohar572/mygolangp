package handler

import (
	"context"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"sync"
	"time"
)

const mongoURI = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
var jwtSecret = []byte("abdullah")

var client *mongo.Client // MongoDB client
var usersCollection *mongo.Collection
var once sync.Once

func initMongo() {
	// Ensure the MongoDB connection is initialized only once
	once.Do(func() {
		mongoClient, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
		if err != nil {
			log.Fatal("Error connecting to MongoDB:", err)
		}
		client = mongoClient
		usersCollection = client.Database("test").Collection("users")
		log.Println("Connected to MongoDB")
	})
}

// Signup Handler
func signup(w http.ResponseWriter, r *http.Request) {
	user := User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if email already exists
	var existingUser User
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "Email already exists", http.StatusBadRequest)
		return
	}

	// Hash the user's password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Insert the user into MongoDB
	_, err = usersCollection.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

// Login Handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	loginData := Login{}
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Find the user in the database
	var existingUser User
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": loginData.Email}).Decode(&existingUser)
	if err != nil {
		http.Error(w, "Invalid email", http.StatusUnauthorized)
		return
	}

	// Compare the provided password with the stored hash
	err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(loginData.Password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Create JWT token
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Email:       existingUser.Email,
		Username:    existingUser.Username,
		Gender:      existingUser.Gender,
		CompanyName: existingUser.CompanyName,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// Router and Middleware
func Handler(w http.ResponseWriter, r *http.Request) {
	initMongo() // Ensure MongoDB is initialized

	router := mux.NewRouter()

	// Define routes
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Welcome to the API"})
	}).Methods("GET")
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", loginHandler).Methods("POST")

	// Add CORS middleware
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(router)

	// Serve the request
	corsHandler.ServeHTTP(w, r)
}
