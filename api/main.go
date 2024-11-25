package handler

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "github.com/gorilla/mux"
    "github.com/rs/cors"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

var mongoURI = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

type User struct {
    Username    string `json:"username"`
    Password    string `json:"password"`
    Email       string `json:"email"`
    Gender      string `json:"gender"`
    CompanyName string `json:"company_name"`
}

var client *mongo.Client // MongoDB client (line 18)
var usersCollection *mongo.Collection // Collection handle (line 19)

// Initialize MongoDB connection
func initMongo() { // (line 22)
    var err error
    client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
    if err != nil {
        log.Fatal("Error connecting to MongoDB:", err) // (line 26)
    }
    usersCollection = client.Database("test").Collection("users") // (line 29)
    log.Println("Connected to MongoDB") // (line 30)
}

// Handler serves as the entry point for Vercel (line 34)
func Handler(w http.ResponseWriter, r *http.Request) {
    initMongo() // Ensure this runs once, consider using `sync.Once` to avoid repeated calls

    router := mux.NewRouter() // Initialize router (line 38)
    router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{"message": "Welcome to the API!"}) // (line 41)
    }).Methods("GET")

    corsHandler := cors.New(cors.Options{ // (line 45)
        AllowedOrigins: []string{"*"},
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
        AllowedHeaders: []string{"Authorization", "Content-Type"},
    }).Handler(router)

    corsHandler.ServeHTTP(w, r) // Serve requests (line 52)
}
