package util

import (
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"strings"
)

func RBAC(handler func(http.ResponseWriter, *http.Request), privilege string, returnCollection bool) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("initiator", "NO_TOKEN")
		var handleFunc func(http.ResponseWriter, *http.Request)

		id := GetLoggedUserIDFromToken(request)

		if id == 0 {
			writer.Header().Set("initiator", "UNAUTHORIZED")
			handleFunc = unauthorizedAccessHandler(handler, returnCollection)
		}else {
			writer.Header().Set("initiator", strconv.Itoa(int(id)))
			if hasPrivilege(id, privilege) {
				handleFunc = handler
			} else {
				handleFunc = unauthorizedAccessHandler(handler, returnCollection)
			}
		}
		handleFunc(writer, request)
	}
}

func hasPrivilege(id uint, privilege string) bool {
	privileges, ok := GetUserPrivileges(id)
	if !ok {
		return false
	}
	for _, val := range privileges {
		if val == privilege {
			return true
		}
	}
	return false
}

func unauthorizedAccessHandler(handler func(http.ResponseWriter, *http.Request), returnCollection bool) func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		handlerFunctionName := runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name()
		parts := strings.Split(handlerFunctionName, "/")
		Logging(WARN, handlerFunctionName, GetIPAddress(request), "Unauthorized access", parts[1])
		writer.Header().Set("Content-Type", "application/json")
		if returnCollection {
			_, _ = writer.Write([]byte("[{\"status\":\"fail\", \"reason\":\"unauthorized\"}]"))
		} else {
			_, _ = writer.Write([]byte("{\"status\":\"fail\", \"reason\":\"unauthorized\"}"))
		}
	}
}
