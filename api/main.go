package handler

import (
	"context"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

var mongoURI = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
var jwtSecret = []byte("abdullah")

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	Email       string `json:"email"`
	password    string `json:"password"`
	Username    string `json:"username"` // Add Username field
	Gender      string `json:"gender"`   // Add Gender field
	CompanyName string `json:"company_name"`
	jwt.StandardClaims
}

type User struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	Gender      string `json:"gender"`
	CompanyName string `json:"company_name"`
}

var client *mongo.Client              // MongoDB client (line 18)
var usersCollection *mongo.Collection // Collection handle (line 19)

// Initialize MongoDB connection
func initMongo() { // (line 22)
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err) // (line 26)
	}
	usersCollection = client.Database("test").Collection("users") // (line 29)
	log.Println("Connected to MongoDB")                           // (line 30)
}


func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginData Login
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var existingUser User
	err := usersCollection.FindOne(context.TODO(), map[string]string{"email": loginData.Email}).Decode(&existingUser)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(loginData.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

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


func signup(w http.ResponseWriter, r *http.Request) {
	var user User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var existingUser User

	err := usersCollection.FindOne(context.TODO(), map[string]string{"email": user.Email}).Decode(&existingUser)

	if err == nil {
		http.Error(w, "email already exists", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	user.Password = string(hashedPassword)

	_, err = usersCollection.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(&user)

}

func Handler(w http.ResponseWriter, r *http.Request) {
	initMongo() // Ensure this runs once, consider using `sync.Once` to avoid repeated calls

	router := mux.NewRouter() // Initialize router (line 38)
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": " create sigup api "}) // (line 41)
	}).Methods("GET")
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", loginHandler).Methods("POST")
	
	
	 // (line 43)
	corsHandler := cors.New(cors.Options{                // (line 45)
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(router)

	corsHandler.ServeHTTP(w, r) // Serve requests (line 52)
}
