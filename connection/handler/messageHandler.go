package handler

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"net/http"
	"nistagram/util"
)

func (handler *Handler) ToggleNotifyMessageProfile(writer http.ResponseWriter, request *http.Request) {
	followerId := util.GetLoggedUserIDFromToken(request)
	if followerId == 0 {
		writer.Write([]byte("{\"status\":\"error\"}"))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	vars := mux.Vars(request)
	profileId := util.String2Uint(vars["profileId"])

	message, ok := handler.ConnectionService.ToggleNotifyMessage(followerId, profileId)

	if !ok {
		writer.Write([]byte("{\"status\":\"error\"}"))
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.WriteHeader(http.StatusOK)
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(*message)
}

func (handler *Handler) GetMessageRelationship(writer http.ResponseWriter, request *http.Request) {
	followerId := util.GetLoggedUserIDFromToken(request)
	if followerId == 0 {
		writer.Write([]byte("{\"status\":\"error\"}"))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	vars := mux.Vars(request)
	profileId := util.String2Uint(vars["profileId"])

	message := handler.ConnectionService.GetMessage(followerId, profileId)

	if message == nil {
		writer.Write([]byte("{\"status\":\"error\"}"))
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.WriteHeader(http.StatusOK)
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(*message)
}

func (handler *Handler) MessageRequest(writer http.ResponseWriter, request *http.Request) {
	followerId := util.GetLoggedUserIDFromToken(request)
	if followerId == 0 {
		writer.Write([]byte("{\"status\":\"error\"}"))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	vars := mux.Vars(request)
	profileId := util.String2Uint(vars["profileId"])

	message, ok := handler.ConnectionService.MessageRequest(followerId, profileId)

	if !ok || message == nil {
		writer.Write([]byte("{\"status\":\"error\"}"))
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.WriteHeader(http.StatusOK)
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(*message)
}

func (handler *Handler) MessageConnect(writer http.ResponseWriter, request *http.Request) {
	followerId := util.GetLoggedUserIDFromToken(request)
	if followerId == 0 {
		writer.Write([]byte("{\"status\":\"error\"}"))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	vars := mux.Vars(request)
	profileId := util.String2Uint(vars["profileId"])

	message, ok := handler.ConnectionService.MessageConnect(followerId, profileId)

	if !ok || message == nil {
		writer.Write([]byte("{\"status\":\"error\"}"))
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.WriteHeader(http.StatusOK)
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(*message)
}