package service

import (
	"fmt"
	"gorm.io/gorm"
	"net/http"
	"nistagram/campaign/dto"
	"nistagram/campaign/model"
	"nistagram/campaign/repository"
	"nistagram/util"
	"time"
)

type CampaignService struct {
	CampaignRepository *repository.CampaignRepository
}

func (service *CampaignService) CreateCampaign (userId uint, campaignRequest dto.CampaignDTO) (model.Campaign,error){
	err := makeCampaign(campaignRequest.PostID, userId)
	if err != nil {
		return model.Campaign{}, err
	}
	campaignParams := model.CampaignParameters{
		Model:            gorm.Model{},
		Start:            campaignRequest.Start,
		End:              campaignRequest.End,
		CampaignID:       0,
		Interests:        service.getInterestsFromRequest(campaignRequest.Interests),
		CampaignRequests: getCampaignRequestsForProfileId(campaignRequest.InfluencerProfileIds),
		Timestamps:       getTimestampsFromRequest(campaignRequest.Timestamps),
	}

	campaign:=model.Campaign{
		Model:              gorm.Model{},
		PostID:             campaignRequest.PostID,
		AgentID:            userId,
		CampaignType:       getCampaignTypeFromRequest(campaignRequest.Start,campaignRequest.End,len(campaignRequest.Timestamps)),
		Start:              campaignRequest.Start,
		CampaignParameters: []model.CampaignParameters{campaignParams},
	}
	return service.CampaignRepository.CreateCampaign(campaign)
}

func getTimestampsFromRequest(timestamps []time.Time) []model.Timestamp{
	ret:= make([]model.Timestamp,0)
	for _,value:= range timestamps{
		ret = append(ret,model.Timestamp{
			Model:                gorm.Model{},
			CampaignParametersID: 0,
			Time:                 value,
		})
	}
	return ret
}

func getCampaignRequestsForProfileId(profileIds []string) []model.CampaignRequest{
	ret := make([]model.CampaignRequest,0)
	for _ , value := range profileIds{
		ret = append(ret,model.CampaignRequest{
			Model:                gorm.Model{},
			InfluencerID:         util.String2Uint(value),
			RequestStatus:        model.SENT,
			CampaignParametersID: 0,
		})
	}
	return ret
}

func (service *CampaignService) getInterestsFromRequest(interests []string) []model.Interest{
	return service.CampaignRepository.GetInterests(interests)
}

func (service *CampaignService) UpdateCampaignParameters(id uint, params dto.CampaignParametersDTO) error {
	newParams := model.CampaignParameters{
		Model:            gorm.Model{},
		Start:            time.Time{},
		End:              params.End,
		CampaignID:       id,
		Interests:        service.getInterestsFromRequest(params.Interests),
		CampaignRequests: getCampaignRequestsForProfileId(params.InfluencerProfileIds),
		Timestamps:       getTimestampsFromRequest(params.Timestamps),
	}
	return service.CampaignRepository.UpdateCampaignParameters(newParams)
}

func (service *CampaignService) DeleteCampaign(id uint) error {
	return service.CampaignRepository.DeleteCampaign(id)
}

func (service *CampaignService) GetMyCampaigns(agentID uint) ([]model.Campaign, error) {
	return service.CampaignRepository.GetMyCampaigns(agentID)
}

func getCampaignTypeFromRequest(start time.Time,end time.Time, timestampsLength int) model.CampaignType{
	if start.Equal(end) && timestampsLength == 1 {
		return model.ONE_TIME
	}else {
		return model.REPEATABLE
	}
}

func makeCampaign(postID string, loggedUserID uint) error {
	postHost, postPort := util.GetPostHostAndPort()
	resp, err := util.CrossServiceRequest(http.MethodPost,
		util.GetCrossServiceProtocol()+"://"+postHost+":"+postPort+"make-campaign/"+postID + "/" + util.Uint2String(loggedUserID),
		nil, map[string]string{})
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("BAD_POST_ID")
	}
	return nil
}

func (service *CampaignService) GetCurrentlyValidInterests(campaignId uint) ([]string,error) {
	var ret []string
	parameters, err := service.CampaignRepository.GetParametersByCampaignId(campaignId)

	for _, i := range parameters.Interests{
		ret = append(ret, i.Name)
	}

	return ret, err
}

func (service *CampaignService) GetCampaignByIdForMonitoring(campaignId uint) (dto.CampaignMonitoringDTO,error) {

	var ret dto.CampaignMonitoringDTO
	var retParams []dto.CampaignParametersMonitoringDTO

	campaign, err := service.CampaignRepository.GetCampaignById(campaignId)
	if err != nil{
		return ret, err
	}

	for _, param := range campaign.CampaignParameters{
		var paramDto dto.CampaignParametersMonitoringDTO
		var interests []string
		var timestamps []time.Time
		var requests []dto.CampaignRequestDTO
		for _, interest := range param.Interests{
			interests = append(interests, interest.Name)
		}
		for _, ts := range param.Timestamps{
			timestamps = append(timestamps, ts.Time)
		}
		for _, request := range param.CampaignRequests{
			reqDto := dto.CampaignRequestDTO{InfluencerID: request.InfluencerID,
				InfluencerUsername: "", RequestStatus: request.RequestStatus.ToString()}
			requests = append(requests, reqDto)
		}
		paramDto.Interests = interests
		paramDto.Timestamps = timestamps
		paramDto.Start = param.Start
		paramDto.End = param.End
		paramDto.CampaignRequests = requests

		retParams = append(retParams, paramDto)
	}

	ret.PostID = campaign.PostID
	ret.AgentID = campaign.AgentID
	ret.Start = campaign.Start
	ret.CampaignType = campaign.CampaignType.ToString()
	ret.CampaignParameters = retParams

	return ret, nil
}



