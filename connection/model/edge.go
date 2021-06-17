package model

import "encoding/json"

type Connection struct {
	PrimaryProfile    uint `json:"primary"`
	SecondaryProfile  uint `json:"secondary"`
	Muted             bool `json:"muted"`
	CloseFriend       bool `json:"closeFriend"`
	NotifyPost        bool `json:"notifyPost"`
	NotifyStory       bool `json:"notifyStory"`
	NotifyMessage     bool `json:"notifyMessage"`
	NotifyComment     bool `json:"notifyComment"`
	ConnectionRequest bool `json:"connectionRequest"`
	Approved          bool `json:"approved"`
	MessageRequest    bool `json:"messageRequest"`
	MessageConnected  bool `json:"messageConnected"`
}

type Block struct {
	PrimaryProfile    uint `json:"primary"`
	SecondaryProfile  uint `json:"secondary"`
}

func (conn *Connection) ToMap() map[string]interface{} {
	var res map[string]interface{}
	connJson, _ := json.Marshal(conn)
	json.Unmarshal([]byte(connJson), &res)
	return res
}

func (block *Block) ToMap() map[string]interface{} {
	var res map[string]interface{}
	blockJson, _ := json.Marshal(block)
	json.Unmarshal([]byte(blockJson), &res)
	return res
}
