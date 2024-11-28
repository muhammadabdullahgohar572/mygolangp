package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// Database and JWT configuration
var (
	mongoURI  = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
	jwtSecret = []byte("abdullah")
	client    *mongo.Client
	usersCollection *mongo.Collection
)

// User and JWT claims structures
type User struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	Gender      string `json:"gender"`
	CompanyName string `json:"company_name"`
}

type Claims struct {
	Email       string `json:"email"`
	Username    string `json:"username"`
	Gender      string `json:"gender"`
	CompanyName string `json:"company_name"`
	jwt.StandardClaims
}

// Initialize MongoDB connection
func initMongo() {
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}
	usersCollection = client.Database("test").Collection("users")
	log.Println("Connected to MongoDB")
}

// Signup handler
func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if the email already exists
	var existingUser User
	err := usersCollection.FindOne(context.TODO(), map[string]string{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "Email already exists", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Insert user into database
	_, err = usersCollection.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginData User
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Find user in database
	var existingUser User
	err := usersCollection.FindOne(context.TODO(), map[string]string{"email": loginData.Email}).Decode(&existingUser)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(loginData.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT
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

// Protected route handler
func decodeHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r) // Extract URL parameters
    tokenString, exists := vars["token"]
    if !exists || tokenString == "" {
        http.Error(w, "Token is missing from the URL", http.StatusUnauthorized)
        return
    }

    // Parse the token
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })
    if err != nil || !token.Valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // If token is valid, respond with success
    claims, ok := token.Claims.(*Claims)
    if !ok {
        http.Error(w, "Invalid token structure", http.StatusUnauthorized)
        return
    }

    response := map[string]interface{}{
        "message":     "Welcome to the protected route",
        "email":       claims.Email,
        "username":    claims.Username,
        "gender":      claims.Gender,
        "companyName": claims.CompanyName,
    }
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
}


// Main function
func Handler(w http.ResponseWriter, r *http.Request) {
	initMongo()

	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/protected/{token}", decodeHandler).Methods("GET")


	// CORS settings
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}).Handler(router)

	corsHandler.ServeHTTP(w, r)

}
