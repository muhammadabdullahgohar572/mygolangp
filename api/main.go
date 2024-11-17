package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var mongoURI = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
var client *mongo.Client
var usersCollection *mongo.Collection

// User struct with JSON tags
type User struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	CompanyName string `json:"companyName"`
	Age         string `json:"age"`
}

// Initialize MongoDB connection
func init() {
	connectToDB()
}

func connectToDB() {
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	usersCollection = client.Database("test").Collection("userdata")
}

// Signup handler
func Signup(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request yyy", http.StatusBadRequest)
		return
	}

	// Check if email already exists
	var existingUser User
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Insert user into MongoDB
	_, err = usersCollection.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, "Error inserting user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User created successfully",
		"data": map[string]interface{}{
			"username":    user.Username,
			"email":       user.Email,
			"companyName": user.CompanyName,
			"age":         user.Age,
		},
	})
}

// Exported function required by Vercel
func handler(w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()

	// Define routes
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to User Registration API"))
	}).Methods("GET")

	router.HandleFunc("/signup", Signup).Methods("POST")

	// Apply CORS middleware
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
	}).Handler(router)

	// Serve the HTTP request
	corsHandler.ServeHTTP(w, r)
}
