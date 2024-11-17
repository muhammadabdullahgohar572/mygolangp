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
	"golang.org/x/crypto/bcrypt"
)
var mongodburl = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
var client *mongo.Client
var usersCollection *mongo.Collection
type User struct {
	username    string `json:"username"`
	password    string `json:"password"`
	email       string `json:"email"`
	CompanyName string `json:"CompanyName"`
	Age         string `json:"Age"`
}
func init() {
	bdconnect()
}

func bdconnect() {
	var err error
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongodburl))
	if err != nil {
		log.Fatal("Data base connection error bdconnect")
	}

	usersCollection = client.Database("test").Collection("userdata")
}

func sigup(w http.ResponseWriter, r *http.Request) {
    var user User
    if  err :=json.NewDecoder(r.Body).Decode(&user);err != nil {
        http.Error(w,"Invalid request body",http.StatusBadRequest)
        return
    }
    var existingUser User
    err :=usersCollection.FindOne(context.TODO(),map[string]string{"email":user.email}).Decode(&existingUser)
    
    if err == nil {
        http.Error(w,"Email already exists",http.StatusConflict)
        return
    }
    hasshedpassword,err :=bcrypt.GenerateFromPassword([]byte(user.password),bcrypt.DefaultCost);
   
   
     if err!= nil {
        http.Error(w,"Error hashing password",http.StatusInternalServerError)
        return
    }
     
    user.password = string(hasshedpassword)

    _,err =usersCollection.InsertOne(context.TODO(),user)
      if err!= nil {
        http.Error(w,"Error inserting user",http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusCreated)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": "User created successfully",
        "status":"status created",
        "data":map[string]interface{}{
            "username": user.username,
            "email": user.email,
            "CompanyName": user.CompanyName,
            "Age": user.Age,
            "status":"status created",
        },

    })

}

func Handler(w http.ResponseWriter, r *http.Request) {
    router :=mux.NewRouter()

     router.HandleFunc("/",func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Welcome to User Registration API"))
     }).Methods("GET")

    router.HandleFunc("/signup", sigup).Methods("POST")
    corsHandler :=cors.New(
        cors.Options{
            AllowedOrigins: []string{"*"},
            AllowedMethods:   []string{"GET", "POST"},
            AllowedHeaders:    []string{"Content-Type"},
            AllowCredentials: true,
        },
    ).Handler(router)
    corsHandler.ServeHTTP(w,r)
}

