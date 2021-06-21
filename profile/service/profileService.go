package service

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis/v8"
	"io"
	"net/http"
	"nistagram/profile/dto"
	"nistagram/profile/model"
	"nistagram/profile/repository"
	"nistagram/profile/saga"
	"nistagram/util"
	"os"
	"time"
)

type ProfileService struct {
	ProfileRepository *repository.ProfileRepository
	Orchestrator *saga.Orchestrator
}

func (service *ProfileService) Register(dto dto.RegistrationDto) error {
	profileSettings := model.ProfileSettings{IsPrivate: dto.IsPrivate, CanReceiveMessageFromUnknown: true, CanBeTagged: true}
	personalData := model.PersonalData{Name: dto.Name, Surname: dto.Surname, Telephone: dto.Telephone,
		Gender: dto.Gender, BirthDate: dto.BirthDate}
	for _, item := range dto.InterestedIn {
		interest := service.ProfileRepository.FindInterestByName(item)
		personalData.AddItem(interest)
	}
	profile := model.Profile{Username: dto.Username, Email: dto.Email, ProfileSettings: profileSettings,
		PersonalData: personalData, Biography: dto.Biography, Website: dto.WebSite, Type: model.REGULAR,
		IsVerified: false}
	err := service.ProfileRepository.CreateProfile(&profile)
	if err != nil {
		return err
	}
	postBody, _ := json.Marshal(map[string]string{
		"profileId": util.Uint2String(profile.ID),
		"password":  dto.Password,
		"email":     profile.Email,
		"username":  profile.Username,
	})
	//responseBody := bytes.NewBuffer(postBody)
	go func() {
		err := registerInAuth(postBody)
		if err != nil {
			fmt.Println("auth bug")
			fmt.Println(err)
		}
	}()
	go func() {
		err := registerInConnection(profile.ID, postBody)
		if err != nil {
			fmt.Println("conn bug")
			fmt.Println(err)
		}
	}()
	return nil
}

func registerInAuth(postBody []byte) error {
	authHost, authPort := util.GetAuthHostAndPort()
	_, err := util.CrossServiceRequest(http.MethodPost,
		util.CrossServiceProtocol+"://"+authHost+":"+authPort+"/register", postBody,
		map[string]string{"Content-Type": "application/json;"})
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func registerInConnection(profileId uint, postBody []byte) error {
	connHost, connPort := util.GetConnectionHostAndPort()
	_, err := util.CrossServiceRequest(http.MethodPost,
		util.CrossServiceProtocol+"://"+connHost+":"+connPort+"/profile/"+util.Uint2String(profileId), postBody,
		map[string]string{"Content-Type": "application/json;"})
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func (service *ProfileService) Search(username string) []string {
	return service.ProfileRepository.FindUsernameContains(username)
}

func (service *ProfileService) SearchForTag(loggedUserId uint, username string) ([]string, error) {
	var ret []string
	usernames := service.ProfileRepository.FindUsernameContains(username)

	resp, err := getUserFollowers(loggedUserId)

	if err != nil {
		return nil, err
	}

	var followingProfiles []uint
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if err = json.Unmarshal(body, &followingProfiles); err != nil {
		return nil, err
	}

	fmt.Println(followingProfiles)

	for i := 0; i < len(usernames); i++ {
		profile, err := service.GetProfileByUsername(usernames[i])
		if err != nil {
			fmt.Println("Can't get profile by username!")
		}
		if util.Contains(followingProfiles, profile.ID) && profile.ProfileSettings.CanBeTagged {
			ret = append(ret, profile.Username)
		}
	}

	return ret, nil
}

func getUserFollowers(loggedUserId uint) (*http.Response, error) {
	connHost, connPort := util.GetConnectionHostAndPort()
	resp, err := util.CrossServiceRequest(http.MethodGet,
		util.CrossServiceProtocol+"://"+connHost+":"+connPort+"/connection/following/show/"+util.Uint2String(loggedUserId),
		nil, map[string]string{})
	return resp, err
}

func (service *ProfileService) GetProfileByUsername(username string) (*model.Profile, error) {
	profile, err := service.ProfileRepository.FindProfileByUsername(username)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

func (service *ProfileService) ChangeProfileSettings(dto dto.ProfileSettingsDTO, loggedUserId uint) error {
	profile, err := service.ProfileRepository.GetProfileByID(loggedUserId)
	if err != nil {
		return err
	}
	profileSettings := profile.ProfileSettings
	var privacyChanged = false
	if profileSettings.IsPrivate != dto.IsPrivate {
		privacyChanged = true
		/*err = service.changePrivacyInPostService(dto.IsPrivate, loggedUserId)
		if err != nil {
			return err
		}*/
	}
	profileSettings.IsPrivate = dto.IsPrivate
	profileSettings.CanBeTagged = dto.CanBeTagged
	profileSettings.CanReceiveMessageFromUnknown = dto.CanReceiveMessageFromUnknown
	err = service.ProfileRepository.UpdateProfileSettings(profileSettings)

	if err != nil{
		return err
	}

	if privacyChanged{
		profile.ProfileSettings = profileSettings
		m := saga.Message{NextService: saga.PostService, SenderService: saga.ProfileService,
			Action: saga.ActionStart, Functionality: saga.ChangeProfilesPrivacy, Profile: profile}
		service.Orchestrator.Next(saga.PostChannel, saga.PostService, m)
	}

	return err
}

func (service *ProfileService) ChangePersonalData(dto dto.PersonalDataDTO, loggedUserId uint) (string, string, error) {
	profile, err := service.ProfileRepository.GetProfileByID(loggedUserId)
	if err != nil {
		return "", "", err
	}
	oldUsername, oldEmail := "", ""
	callAuth := false
	callPost := false
	if profile.Email != dto.Email {
		oldEmail = profile.Email
		callAuth = true
	}
	if profile.Username != dto.Username {
		//TODO: change data in other ms
		oldUsername = profile.Username
		callAuth = true
		callPost = true
	}
	profile.Username = dto.Username
	profile.Website = dto.Website
	profile.Biography = dto.Biography
	profile.Email = dto.Email
	profile.PersonalData.Name = dto.Name
	profile.PersonalData.BirthDate = dto.BirthDate
	profile.PersonalData.Gender = dto.Gender
	profile.PersonalData.Surname = dto.Surname
	profile.PersonalData.Telephone = dto.Telephone
	err = service.ProfileRepository.UpdateProfile(profile)
	if err != nil {
		return "", "", err
	}
	if callAuth {
		postBody, _ := json.Marshal(map[string]string{
			"profileId": util.Uint2String(profile.ID),
			"email":     profile.Email,
			"username":  profile.Username,
		})
		authHost, authPort := util.GetAuthHostAndPort()
		_, err = util.CrossServiceRequest(http.MethodPost,
			util.CrossServiceProtocol+"://"+authHost+":"+authPort+"/update-user", postBody,
			map[string]string{"Content-Type": "application/json;"})
		if err != nil {
			fmt.Println(err)
			return "", "", err
		}
	}
	if callPost {
		err = service.changeUsernameInPostService(loggedUserId, dto.Username)
		if err != nil {
			return "", "", err
		}
	}
	err = service.ProfileRepository.UpdatePersonalData(profile.PersonalData)
	return oldUsername, oldEmail, err
}

func (service *ProfileService) GetAllInterests() ([]string, error) {
	interests, err := service.ProfileRepository.GetAllInterests()
	return interests, err
}

func (service *ProfileService) GetAllCategories() ([]string, error) {
	categories, err := service.ProfileRepository.GetAllCategories()
	return categories, err
}

func (service *ProfileService) CreateVerificationRequest(profileId uint, requestDTO dto.VerificationRequestDTO, fileName string) error {
	category, err := service.ProfileRepository.GetCategoryByName(requestDTO.Category)
	if err != nil {
		fmt.Println(err)
		return err
	}
	var verReq = model.VerificationRequest{ProfileID: profileId, Name: requestDTO.Name, Surname: requestDTO.Surname,
		VerificationStatus: model.SENT, ImagePath: fileName, Category: *category}
	err = service.ProfileRepository.CreateVerificationRequest(&verReq)
	return err
}

func (service *ProfileService) UpdateVerificationRequest(verifyDTO dto.VerifyDTO) error {
	request, err := service.ProfileRepository.GetVerificationRequestById(verifyDTO.VerificationId)
	if err != nil {
		return err
	}
	if verifyDTO.Status {
		request.VerificationStatus = model.VERIFIED
		err = service.ProfileRepository.UpdateVerificationRequest(*request)
		if err != nil {
			return err
		}
		profile, err := service.ProfileRepository.GetProfileByID(request.ProfileID)
		if err != nil {
			return err
		}
		profile.IsVerified = true
		err = service.ProfileRepository.UpdateProfile(profile)
	} else {
		err = service.ProfileRepository.DeleteVerificationRequest(request)
	}

	return err
}

func (service *ProfileService) GetMyProfileSettings(loggedUserId uint) (dto.ProfileSettingsDTO, error) {
	ret := dto.ProfileSettingsDTO{}
	profile, err := service.ProfileRepository.GetProfileByID(loggedUserId)
	if err != nil {
		return ret, err
	}
	ret.CanReceiveMessageFromUnknown = profile.ProfileSettings.CanReceiveMessageFromUnknown
	ret.CanBeTagged = profile.ProfileSettings.CanBeTagged
	ret.IsPrivate = profile.ProfileSettings.IsPrivate
	return ret, nil
}

func (service *ProfileService) GetMyPersonalData(loggedUserId uint) (dto.PersonalDataDTO, error) {
	profile, err := service.ProfileRepository.GetProfileByID(loggedUserId)
	if err != nil {
		return dto.PersonalDataDTO{}, err
	}
	personalData := profile.PersonalData
	ret := dto.PersonalDataDTO{Username: profile.Username, Name: personalData.Name, Surname: personalData.Surname,
		Email: profile.Email, Telephone: personalData.Telephone, Gender: personalData.Gender,
		BirthDate: personalData.BirthDate, Biography: personalData.BirthDate, Website: profile.Website}
	return ret, nil
}

func (service *ProfileService) GetProfileByID(id uint) (*model.Profile, error) {
	profile, err := service.ProfileRepository.GetProfileByID(id)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

func (service *ProfileService) GetVerificationRequests() ([]model.VerificationRequest, error) {
	return service.ProfileRepository.GetVerificationRequests()
}

func (service *ProfileService) DeleteProfile(profileId uint) error {
	err := service.ProfileRepository.DeleteProfile(profileId)
	if err != nil {
		return err
	}

	err = service.deleteProfileInAuth(profileId)
	if err != nil {
		return err
	}

	err = service.deleteProfilesPosts(profileId)
	if err != nil {
		return err
	}

	return nil
}

func (service *ProfileService) SendAgentRequest(loggedUserID uint) error {
	request := model.AgentRequest{ProfileId: loggedUserID}
	return service.ProfileRepository.SendAgentRequest(&request)
}

func (service *ProfileService) GetAgentRequests() ([]dto.AgentRequestDTO, error) {
	requests, err := service.ProfileRepository.GetAgentRequests()
	if err != nil {
		return nil, err
	}
	ret := make([]dto.AgentRequestDTO, 0)
	for _, value := range requests {
		profile, err := service.ProfileRepository.GetProfileByID(value.ProfileId)
		if err != nil {
			return nil, err
		}
		ret = append(ret, dto.AgentRequestDTO{Username: profile.Username, ProfileID: profile.ID,
			Email: profile.Email, Website: profile.Website})
	}
	return ret, nil
}

func (service *ProfileService) GetProfileUsernamesByIDs(ids []string) ([]string, error) {
	ret := make([]string, 0)
	for _, value := range ids {
		profile, err := service.GetProfileByID(util.String2Uint(value))
		if err != nil {
			return nil, err
		}
		ret = append(ret, profile.Username)
	}
	return ret, nil

}

func (service *ProfileService) GetByInterests(interests []string) ([]model.Profile, error) {
	return service.ProfileRepository.GetByInterests(interests)
}

func (service *ProfileService) deleteProfileInAuth(profileId uint) error {
	authHost, authPort := util.GetAuthHostAndPort()
	_, err := util.CrossServiceRequest(http.MethodDelete,
		util.CrossServiceProtocol+"://"+authHost+":"+authPort+"/ban/"+util.Uint2String(profileId), nil,
		map[string]string{})
	if err != nil {
		return err
	}
	return nil
}

func (service *ProfileService) deleteProfilesPosts(profileId uint) error {
	postHost, postPort := util.GetPostHostAndPort()
	_, err := util.CrossServiceRequest(http.MethodDelete,
		util.CrossServiceProtocol+"://"+postHost+":"+postPort+"/user/"+util.Uint2String(profileId), nil,
		map[string]string{})
	if err != nil {
		return err
	}
	return nil
}

func (service *ProfileService) Test(key string) error {
	return service.ProfileRepository.InsertInRedis(key, "test")
}

func (service *ProfileService) changePrivacyInPostService(isPrivate bool, loggedUserId uint) error {
	postHost, postPort := util.GetPostHostAndPort()
	type Privacy struct {
		IsPrivate bool `json:"isPrivate"`
	}
	input := Privacy{IsPrivate: isPrivate}
	jsonPrivacy, _ := json.Marshal(input)
	_, err := util.CrossServiceRequest(http.MethodPut,
		util.CrossServiceProtocol+"://"+postHost+":"+postPort+"/user/"+util.Uint2String(loggedUserId)+"/privacy",
		jsonPrivacy, map[string]string{"Content-Type": "application/json;"})
	if err != nil {
		fmt.Println(err)
	}
	return err
}

func (service *ProfileService) changeUsernameInPostService(loggedUserId uint, username string) error {
	postHost, postPort := util.GetPostHostAndPort()
	type UsernameDto struct {
		Username string `json:"username"`
	}
	input := UsernameDto{Username: username}
	jsonUsername, _ := json.Marshal(input)
	_, err := util.CrossServiceRequest(http.MethodPut,
		util.CrossServiceProtocol+"://"+postHost+":"+postPort+"/user/"+util.Uint2String(loggedUserId)+"/username",
		jsonUsername, map[string]string{"Content-Type": "application/json;"})
	if err != nil {
		fmt.Println(err)
	}
	return err
}

func (service *ProfileService) ConnectToRedis(){
	var (
		client *redis.Client
		err error
	)
	time.Sleep(5 * time.Second)
	var redisHost, redisPort = "localhost", "6379"          // dev.db environment
	_, ok := os.LookupEnv("DOCKER_ENV_SET_PROD")        // production environment
	if ok {
		redisHost = "message_broker"
		redisPort = "6379"
	} else {
		_, ok := os.LookupEnv("DOCKER_ENV_SET_DEV") // dev front environment
		if ok {
			redisHost = "message_broker"
			redisPort = "6379"
		}
	}
	for {
		client = redis.NewClient(&redis.Options{
			Addr:     redisHost + ":" + redisPort,
			Password: "",
			DB:       0,
		})

		if err := client.Ping(context.TODO()).Err(); err != nil {
			fmt.Println("Cannot connect to redis! Sleeping 10s and then retrying....")
			time.Sleep(10 * time.Second)
		} else {
			fmt.Println("Profile connected to redis.")
			break
		}
	}

	pubsub := client.Subscribe(context.TODO(),saga.ProfileChannel, saga.ReplyChannel)

	if _, err = pubsub.Receive(context.TODO()); err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = pubsub.Close() }()
	ch := pubsub.Channel()

	fmt.Println("Starting profile saga in go routine..")

	for{
		select{
		case msg := <-ch:
			m := saga.Message{}
			if err = json.Unmarshal([]byte(msg.Payload), &m); err != nil {
				fmt.Println(err)
				continue
			}

			switch msg.Channel {
			case saga.ProfileChannel:
				if m.Action == saga.ActionRollback {
					switch m.Functionality{
					case saga.ChangeProfilesPrivacy:
						profile := m.Profile
						togglePrivacy(profile)
						err = service.ProfileRepository.UpdateProfileSettings(profile.ProfileSettings)
						if err != nil{
							fmt.Println(err)
						}
						sendToReplyChannel(client, &m, saga.ActionError, saga.ProfileChannel, saga.ProfileChannel)
					}
				}
			}
		}

	}
}

func sendToReplyChannel(client *redis.Client, m *saga.Message, action string, nextService string, senderService string){
	var err error
	m.Action = action
	m.NextService = nextService
	m.SenderService = senderService
	if err = client.Publish(context.TODO(),saga.ReplyChannel, m).Err(); err != nil {
		fmt.Printf("Error publishing done-message to %s channel", saga.ReplyChannel)
	}
	fmt.Printf("Done message published to channel :%s", saga.ReplyChannel)
}

func togglePrivacy(profile *model.Profile) {
	isPrivate := profile.ProfileSettings.IsPrivate
	if isPrivate{
		profile.ProfileSettings.IsPrivate = false
	}else{
		profile.ProfileSettings.IsPrivate = true
	}
}