package main

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

var mongodburl = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
var client *mongo.Client
var usercollection *mongo.Collection

// init function to set up MongoDB connection
func init() {
	initMongo()
}

// Function to initialize MongoDB connection
func initMongo() {
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongodburl))
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}
	usercollection = client.Database("test").Collection("userdata")
}

// Handler function to handle incoming requests
func handler(w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()

	// Route to handle a simple GET request
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "hello go from vercel!!!",
		})
	}).Methods("GET")

	// CORS handler setup
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(router)

	// Serve HTTP with CORS enabled
	corsHandler.ServeHTTP(w, r)
}

// main function to start the server
func main() {
	// Define the endpoint and the handler
	http.HandleFunc("/", handler)

	// Start the server
	log.Println("Server is starting on port 8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Error starting server:", err)
	}
}
