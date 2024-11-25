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

// var jwtSecret = []byte("abdullah55")
var mongoURI = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

type User struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	Gender      string `json:"gender"`
	CompanyName string `json:"company_name"`
}


var client *mongo.Client
var usersCollection *mongo.Collection

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





func Handler() {

	initMongo()

	
	router := mux.NewRouter()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Welcome to the API!"})
	}).Methods("GET")


	// Configure CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(router)

	// Start the server
	log.Println("Server running on port 8080")
	if err := http.ListenAndServe(":8080", corsHandler); err != nil {
		log.Fatal("Error starting server:", err)
	}
}
