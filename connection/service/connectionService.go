package service

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"nistagram/connection/dto"
	"nistagram/connection/model"
	"nistagram/connection/repository"
	model2 "nistagram/profile/model"
	"nistagram/util"
)

type ConnectionService struct {
	ConnectionRepository *repository.ConnectionRepository
	BlockRepository *repository.BlockRepository
}

func (service *ConnectionService) AddProfile(id uint) (*model.Profile, bool) {
	profile := model.Profile{ProfileID: id}
	ret := service.ConnectionRepository.CreateProfile(profile)
	return ret, ret.ProfileID == id
}

func (service *ConnectionService) GetConnection(followerId, profileId uint) *model.Connection {
	connection, _ := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	return connection
}

func getProfile(id uint) *model2.Profile {
	var p model2.Profile
	profileHost, profilePort := util.GetProfileHostAndPort()
	resp, err := util.CrossServiceRequest(http.MethodGet,
		util.CrossServiceProtocol+"://"+profileHost+":"+profilePort+"/get-by-id/"+util.Uint2String(id),
		nil, map[string]string{})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)
	body, err1 := ioutil.ReadAll(resp.Body)
	if err1 != nil {
		fmt.Println(err1)
		return nil
	}
	err = json.Unmarshal(body, &p)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return &p
}

func (service *ConnectionService) FollowRequest(followerId, profileId uint) (*model.Connection, bool) {
	if service.IsInBlockingRelationship(followerId, profileId) {
		return nil, false
	}
	connection := service.ConnectionRepository.SelectOrCreateConnection(followerId, profileId)
	if connection.Approved {
		return nil, false
	}
	//conn2, ok2 := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	//profile1 := getProfile(followerId)
	profile2 := getProfile(profileId)
	if /*profile1 == nil ||*/ profile2 == nil {
		return nil, false
	}
	/*if !ok2 || profile1 == nil || profile2 == nil {
		return nil, false
	}*/
	/*if connection.Block == true || (conn2 != nil && conn2.Block == true) {
		return nil, false
	}*/
	if /*profile1.ProfileSettings.IsPrivate == false &&*/ profile2.ProfileSettings.IsPrivate == false {
		connection.Approved = true
	} else {
		connection.ConnectionRequest = true
	}
	resConnection, ok := service.ConnectionRepository.UpdateConnection(connection)
	if ok {
		return resConnection, true
	} else {
		return connection, false
	}
}

func (service *ConnectionService) ToggleBlock(followerId, profileId uint) (*model.Block, bool) {
	block, ok := service.BlockRepository.SelectBlock(followerId, profileId)
	if !ok || block == nil {
		service.ConnectionRepository.SelectOrCreateConnection(followerId, profileId)
		connection := model.Connection{
			PrimaryProfile:    followerId,
			SecondaryProfile:  profileId,
			Muted:             false,
			CloseFriend:       false,
			NotifyPost:        false,
			NotifyStory:       false,
			NotifyMessage:     false,
			NotifyComment:     false,
			ConnectionRequest: false,
			Approved:          false,
			MessageRequest:    false,
			MessageConnected:  false,
		}
		service.ConnectionRepository.UpdateConnection(&connection)
		block, ok = service.BlockRepository.CreateBlock(followerId, profileId)
	} else {
		block, ok = service.BlockRepository.DeleteBlock(followerId, profileId)
	}
	return block, ok
}

func (service *ConnectionService) MessageConnect(followerId, profileId uint) (*model.Connection, bool) {
	connection, ok := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	conn2, ok2 := service.ConnectionRepository.SelectConnection(profileId, followerId, false)
	if !connection.MessageRequest || (!ok || !ok2) {
		return nil, false
	}
	connection.MessageRequest = false
	connection.MessageConnected = true
	conn2.MessageRequest = false
	conn2.MessageConnected = true
	service.ConnectionRepository.UpdateConnection(connection)
	resConnection, ok1 := service.ConnectionRepository.UpdateConnection(conn2)
	if ok1 {
		return resConnection, true
	} else {
		return conn2, false
	}
}

func (service *ConnectionService) MessageRequest(followerId, profileId uint) (*model.Connection, bool) {
	if service.IsInBlockingRelationship(followerId, profileId) {
		return nil, false
	}
	connection := service.ConnectionRepository.SelectOrCreateConnection(followerId, profileId)
	if connection.MessageConnected {
		return nil, false
	}
	connection.MessageRequest = true
	conn2 := service.ConnectionRepository.SelectOrCreateConnection(profileId, followerId)
	if conn2.MessageConnected {
		return nil, false
	}
	if !conn2.Approved {
		conn2.MessageRequest = false
	}
	resConnection, ok := service.ConnectionRepository.UpdateConnection(connection)
	service.ConnectionRepository.UpdateConnection(conn2)
	if ok {
		return resConnection, true
	} else {
		return connection, false
	}
}

func (service *ConnectionService) ApproveConnection(followerId, profileId uint) (*model.Connection, bool) {
	connection, okSelect := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	if okSelect && connection == nil {
		return connection, false
	}
	//conn2, ok2 := service.ConnectionRepository.SelectConnection(profileId, followerId, false)
	profile1 := getProfile(followerId)
	profile2 := getProfile(profileId)
	if profile1 == nil || profile2 == nil {
		return nil, false
	}
	/*if !ok2 || profile1 == nil || profile2 == nil {
		return nil, false
	}
	if connection.Block == true || (conn2 != nil && conn2.Block == true) {
		return nil, false
	}
	if conn2 == nil {
		conn2 = service.ConnectionRepository.SelectOrCreateConnection(profileId, followerId)
	}*/
	if !connection.ConnectionRequest {
		return nil, false
	}
	connection.ConnectionRequest = false
	connection.Approved = true
	//conn2.ConnectionRequest = false
	//conn2.Approved = true
	return service.ConnectionRepository.UpdateConnection(connection)
	/*var ok bool
	conn2, ok = service.ConnectionRepository.UpdateConnection(conn2)
	if ok {
		return conn2, true
	} else {
		return conn2, false
	}*/
}

func (service *ConnectionService) ToggleNotifyComment(followerId, profileId uint) (*model.Connection, bool) {
	if service.IsInBlockingRelationship(followerId, profileId) {
		return nil, false
	}
	connection, okSelect := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	if okSelect && connection == nil {
		return connection, false
	}
	connection.NotifyComment = !connection.NotifyComment
	resConnection, ok := service.ConnectionRepository.UpdateConnection(connection)
	if ok {
		return resConnection, true
	} else {
		return connection, false
	}
}

func (service *ConnectionService) ToggleNotifyMessage(followerId, profileId uint) (*model.Connection, bool) {
	if service.IsInBlockingRelationship(followerId, profileId) {
		return nil, false
	}
	connection, okSelect := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	if okSelect && connection == nil {
		return connection, false
	}
	connection.NotifyMessage = !connection.NotifyMessage
	resConnection, ok := service.ConnectionRepository.UpdateConnection(connection)
	if ok {
		return resConnection, true
	} else {
		return connection, false
	}
}

func (service *ConnectionService) ToggleNotifyStory(followerId, profileId uint) (*model.Connection, bool) {
	if service.IsInBlockingRelationship(followerId, profileId) {
		return nil, false
	}
	connection, okSelect := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	if okSelect && connection == nil {
		return connection, false
	}
	connection.NotifyStory = !connection.NotifyStory
	resConnection, ok := service.ConnectionRepository.UpdateConnection(connection)
	if ok {
		return resConnection, true
	} else {
		return connection, false
	}
}

func (service *ConnectionService) ToggleNotifyPost(followerId, profileId uint) (*model.Connection, bool) {
	if service.IsInBlockingRelationship(followerId, profileId) {
		return nil, false
	}
	connection, okSelect := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	if okSelect && connection == nil {
		return connection, false
	}
	connection.NotifyPost = !connection.NotifyPost
	resConnection, ok := service.ConnectionRepository.UpdateConnection(connection)
	if ok {
		return resConnection, true
	} else {
		return connection, false
	}
}

func (service *ConnectionService) ToggleCloseFriend(followerId, profileId uint) (*model.Connection, bool) {
	if service.IsInBlockingRelationship(followerId, profileId) {
		return nil, false
	}
	connection, okSelect := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	if okSelect && connection == nil {
		return connection, false
	}
	connection.CloseFriend = !connection.CloseFriend
	resConnection, ok := service.ConnectionRepository.UpdateConnection(connection)
	if ok {
		return resConnection, true
	} else {
		return connection, false
	}
}

func (service *ConnectionService) ToggleMuted(followerId, profileId uint) (*model.Connection, bool) {
	if service.IsInBlockingRelationship(followerId, profileId) {
		return nil, false
	}
	connection, okSelect := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	if okSelect && connection == nil {
		return connection, false
	}
	connection.Muted = !connection.Muted
	resConnection, ok := service.ConnectionRepository.UpdateConnection(connection)
	if ok {
		return resConnection, true
	} else {
		return connection, false
	}
}

func contains(s *[]uint, e uint) bool {
	for _, a := range *s {
		if a == e {
			return true
		}
	}
	return false
}

func (service *ConnectionService) GetConnectedProfiles(conn model.Connection, excludeMuted, excludeBlocked bool) *[]uint {
	ret := service.ConnectionRepository.GetConnectedProfiles(conn, excludeMuted)
	if ret == nil {
		temp := make([]uint, 0)
		return &temp
	}
	if !excludeBlocked {
		var final []uint
		blocking := service.BlockRepository.GetBlockedProfiles(conn.PrimaryProfile, false)
		for _, val := range *ret {
			if !contains(blocking, val) {
				final = append(final, val)
			}
		}
		return &final
	}
	return ret
}

func (service *ConnectionService) UpdateConnection(id uint, conn model.Connection) (*model.Connection, bool) {
	if id == conn.PrimaryProfile {
		return service.ConnectionRepository.UpdateConnection(&conn)
	} else {
		return nil, false
	}
}

func (service *ConnectionService) DeleteConnection(followerId, profileId uint) (*model.Connection, bool) {
	return service.ConnectionRepository.DeleteConnection(followerId, profileId)
}

func (service *ConnectionService) GetAllFollowRequests(id uint) *[]dto.UserDTO {
	var result = service.ConnectionRepository.GetAllFollowRequests(id)
	var ret = make([]dto.UserDTO, 0) // 0, :)
	for _, profileId := range *result {
		var p model2.Profile
		profileHost, profilePort := util.GetProfileHostAndPort()
		resp, err := util.CrossServiceRequest(http.MethodGet,
			util.CrossServiceProtocol+"://"+profileHost+":"+profilePort+"/get-by-id/"+util.Uint2String(profileId),
			nil, map[string]string{})
		if err != nil {
			fmt.Println(err)
			return nil
		}
		body, err1 := ioutil.ReadAll(resp.Body)
		if err1 != nil {
			fmt.Println(err1)
			return nil
		}
		err = json.Unmarshal(body, &p)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		ret = append(ret, dto.UserDTO{
			Username:  p.Username,
			ProfileID: p.ID,
		})
		resp.Body.Close()
	}
	return &ret
}

func (service *ConnectionService) IsInBlockingRelationship(id1, id2 uint) bool {
	lst := service.BlockRepository.GetBlockedProfiles(id1, false)
	if lst == nil || len(*lst) == 0 {
		return false
	}
	for _, val := range *lst {
		if val == id2 {
			return true
		}
	}
	return false
}

func (service *ConnectionService) IsBlocked(id1, id2 uint) bool {
	lst := service.BlockRepository.GetBlockedProfiles(id1, true)
	fmt.Println(*lst,id1, id2)
	if lst == nil || len(*lst) == 0 {
		return false
	}
	for _, val := range *lst {
		if val == id2 {
			return true
		}
	}
	return false
}

func (service *ConnectionService) Unfollow(followerId, profileId uint) (*model.Connection, bool) {
	if service.IsInBlockingRelationship(followerId, profileId) {
		return nil, false
	}
	connection, okSelect := service.ConnectionRepository.SelectConnection(followerId, profileId, false)
	if okSelect && connection == nil {
		return connection, false
	}
	newConnection := model.Connection{
		PrimaryProfile:    connection.PrimaryProfile,
		SecondaryProfile:  connection.SecondaryProfile,
		Muted:             false,
		CloseFriend:       false,
		NotifyPost:        false,
		NotifyStory:       false,
		NotifyMessage:     false,
		NotifyComment:     false,
		ConnectionRequest: false,
		Approved:          false,
		MessageRequest:    connection.MessageRequest,
		MessageConnected:  connection.MessageConnected,
	}
	resConnection, ok := service.ConnectionRepository.UpdateConnection(&newConnection)
	if ok {
		return resConnection, true
	} else {
		return connection, false
	}
}
