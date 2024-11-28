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
	"sync"
	"time"
)

var (
	mongoURI     = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
	jwtSecret    = []byte("abdullah")
	client       *mongo.Client
	usersCollection *mongo.Collection
	once         sync.Once
)

// Login struct for login request
type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Claims for JWT
type Claims struct {
	Email       string `json:"email"`
	Username    string `json:"username"` // Added Username field
	Gender      string `json:"gender"`   // Added Gender field
	CompanyName string `json:"company_name"`
	jwt.StandardClaims
}

// User struct for user data
type User struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	Gender      string `json:"gender"`
	CompanyName string `json:"company_name"`
}

// Initialize MongoDB connection
func initMongo() {
	once.Do(func() {
		var err error
		client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
		if err != nil {
			log.Fatal("Error connecting to MongoDB:", err)
		}
		usersCollection = client.Database("test").Collection("users")
		log.Println("Connected to MongoDB")
	})
}

// Signup handler
func signup(w http.ResponseWriter, r *http.Request) {
	initMongo()
	var user User

	// Decode user data
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if email already exists
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
	initMongo()
	var loginData Login

	// Decode login data
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

	// Check password
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

// Decode handler for JWT-protected route

func Decode(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
			log.Println("Decode: Authorization header is missing")
			return
		}
	
		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			log.Println("Decode: Invalid Authorization header format:", authHeader)
			return
		}
	
		tokenString := authHeader[7:]
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
	
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			log.Println("Decode: Token parse error:", err)
			return
		}
	
		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			log.Println("Decode: Token is invalid")
			return
		}
	
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Welcome to the protected route"})
		log.Println("Decode: Token is valid, user authenticated")
	}
	


// Handler for setting up routes and middleware
func Handler(w http.ResponseWriter, r *http.Request) {
	initMongo()
	router := mux.NewRouter()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Welcome to the API"})
	}).Methods("GET")
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/protected", Decode).Methods("GET")

	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(router)

	corsHandler.ServeHTTP(w, r)
}
