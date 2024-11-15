
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

var mongodburl = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
var client *mongo.Client

var usercollection *mongo.Collection;

func init(){
	initMongo()
}

func initMongo(){
	var err error;
	client,err =mongo.Connect(context.TODO(),options.Client().ApplyURI(mongodburl))
      if err !=nil{
		log.Fatal("error connection mongodb",err)
	  }
    usercollection=client.Database("test").Collection("userdata")
}

func handler(w http.ResponseWriter, r *http.Request) {
	router :=mux.NewRouter();
	router.HandleFunc("/",func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "hello go from vercel!!!",
		})
	}).Methods("GET")


	corsHandler:=cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
        AllowedMethods: []string{"GET","POST","PUT","DELETE"},
        AllowedHeaders: []string{"Authorization","Content-Type"},
	}).Handler(router)
	corsHandler.ServeHTTP(w,r)
}

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