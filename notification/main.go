package main

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"net/http"
	"nistagram/notification/handler"
	"nistagram/notification/repository"
	"nistagram/notification/service"
	"nistagram/util"
	"os"
	"time"
)

func initDB() *mongo.Client {
	var dbHost, dbPort, dbUsername, dbPassword = "localhost", "8084", "root", "root" // dev.db environment
	_, ok := os.LookupEnv("DOCKER_ENV_SET_PROD")                                     // production environment
	if ok {
		dbHost = "mongo1"
		dbPort = "27017"
		dbUsername = os.Getenv("DB_USERNAME")
		dbPassword = os.Getenv("DB_PASSWORD")
	} else {
		_, ok := os.LookupEnv("DOCKER_ENV_SET_DEV") // dev front environment
		if ok {
			dbHost = "mongo1"
			dbPort = "27017"
			dbUsername = os.Getenv("DB_USERNAME")
			dbPassword = os.Getenv("DB_PASSWORD")
		}
	}

	clientOptions := options.Client().ApplyURI("mongodb://" + dbUsername + ":" + dbPassword + "@" + dbHost + ":" + dbPort)
	for {
		client, err := mongo.Connect(context.TODO(), clientOptions)

		if err != nil {
			fmt.Println("Cannot connect to MongoDB! Sleeping 10s and then retrying....")
			time.Sleep(10 * time.Second)
		} else {
			fmt.Println("Connected to MongoDB")
			return client
		}
	}
}

func initRepo(client *mongo.Client) *repository.NotificationRepository {
	return &repository.NotificationRepository{Client: client}
}

func initService(notificationRepository *repository.NotificationRepository) *service.NotificationService {
	return &service.NotificationService{NotificationRepository: notificationRepository}
}
func initHandler(notificationService *service.NotificationService) *handler.Handler {
	return &handler.Handler{NotificationService: notificationService}
}

func handleFunc(handler *handler.Handler) {
	router := mux.NewRouter().StrictSlash(true)


	fmt.Println("Starting server..")
	host, port := util.GetNotificationHostAndPort()
	var err error
	if util.DockerChecker() {
		err = http.ListenAndServeTLS(":"+port, "../cert.pem", "../key.pem", router)
	} else {
		err = http.ListenAndServe(host+":"+port, router)
	}
	if err != nil {
		fmt.Println(err)
		return
	}
}

func closeConnection(client *mongo.Client) {
	err := client.Disconnect(context.TODO())
	if err != nil {
		fmt.Println("Failed to close MongoDB.")
		return
	}
	fmt.Println("Connection to MongoDB closed.")
}

func main() {
	util.TracerInit("notification")
	client := initDB()
	defer closeConnection(client)
	repo := initRepo(client)
	service := initService(repo)
	handler := initHandler(service)
	_ = util.SetupMSAuth("notification")
	handleFunc(handler)
}