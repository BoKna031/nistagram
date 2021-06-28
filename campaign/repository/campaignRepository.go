package repository

import (
	"fmt"
	"gorm.io/gorm"
	"nistagram/campaign/model"
	"time"
)

type CampaignRepository struct {
	Database *gorm.DB
}


func (repo *CampaignRepository) CreateCampaign(campaign model.Campaign) (model.Campaign,error) {
	result := repo.Database.Create(&campaign)
	if result.RowsAffected == 0 {
		return campaign, fmt.Errorf("User not created")
	}
	fmt.Println("User Created")
	return campaign, nil
}

func (repo *CampaignRepository) UpdateCampaignParameters(campaignParameters model.CampaignParameters)  error {

	var oldValue model.CampaignParameters
	tomorrow := time.Now().Add(24 * time.Hour)
	tx := repo.Database.Begin()
	result := tx.Table("campaign_parameters").Exec("UPDATE campaign_parameters SET end = ? WHERE id IN" +
		"(SELECT searched.id FROM (SELECT * FROM campaign_parameters cp WHERE cp.campaign_id = ? AND cp.start < ? AND cp.deleted_at IS NULL " +
		"ORDER BY cp.start DESC LIMIT 1) searched)",tomorrow, campaignParameters.CampaignID, tomorrow).Scan(&oldValue)
	if result.Error != nil {
		return result.Error
	}

	newCampParams := model.CampaignParameters{
		Model:            gorm.Model{},
		Start:            tomorrow,
		End:              campaignParameters.End,
		CampaignID:       campaignParameters.CampaignID,
		Interests:        campaignParameters.Interests,
		CampaignRequests: campaignParameters.CampaignRequests,
		Timestamps:       campaignParameters.Timestamps,
	}


	if err := tx.Table("campaign_parameters").Create(&newCampParams).Error; err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func (repo *CampaignRepository) DeleteCampaign(campaignID uint) error{
	now := time.Now()
	//Check if campaign exists
	if err := repo.checkIfCampaignExists(campaignID); err != nil{
		return err
	}

	tx := repo.Database.Begin()

	//check if campaign have params in past
	if result := tx.Table("campaign_parameters").Find(&model.CampaignParameters{}, "start < ? AND id = ?",now,campaignID); result.Error != nil{
		return result.Error
	}else if result.RowsAffected == 0 {
		//if there is no params delete campaign
		if err := repo.forceDeleteCampaing(campaignID); err != nil{
			return err
		}
		tx.Commit()
		return nil
	}

	//delete all future campaign params
	if result := tx.Unscoped().Delete(&model.CampaignParameters{CampaignID: campaignID}, "start > ? AND campaign_id = ?", time.Now(), campaignID); result.Error != nil {
		return result.Error
	}

	//Set active CampaignParameter to end now
	result := tx.Table("campaign_parameters").Exec("UPDATE campaign_parameters SET end = ? WHERE id IN"+
		"(SELECT searched.id FROM (SELECT * FROM campaign_parameters cp WHERE cp.campaign_id = ? AND cp.end > ? AND cp.deleted_at IS NULL "+
		"ORDER BY cp.start DESC LIMIT 1) searched)", time.Now(), campaignID, time.Now()).Scan(&model.CampaignParameters{})
	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}

	tx.Commit()
	return nil
}

func (repo *CampaignRepository) checkIfCampaignExists(campaignID uint) error {
	if result := repo.Database.Find(&model.Campaign{},"id = ?", campaignID); result.Error != nil {
		return result.Error
	} else if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (repo *CampaignRepository) GetInterests(interests []string) []model.Interest {
	var ret []model.Interest

	if err := repo.Database.Table("interests").Find(&ret,"name IN ? ", interests).Error ; err != nil {
		return make([]model.Interest,0)
	}
	return ret
}

func (repo *CampaignRepository) forceDeleteCampaing(id uint, tx *gorm.DB) error {
	if err := beforeDeleteCampaign(id,tx); err != nil {
		return err
	}
	return tx.Unscoped().Delete(&model.Campaign{},"id = ?",id).Error
}

func  beforeDeleteCampaign(campaignId uint, tx *gorm.DB) error {
	if err := beforeDeleteCampaignParameters(campaignId,tx); err != nil {
		return err
	}
	return tx.Unscoped().Delete(&model.CampaignParameters{},"campaign_id = ?",campaignId).Error
}

func  beforeDeleteCampaignParameters(campaignParametersId uint,tx *gorm.DB) error {
	if err:= tx.Unscoped().Delete(&model.CampaignRequest{},"campaign_parameters_id = ?",campaignParametersId).Error; err != nil{
		return err
	}
	if err:= tx.Unscoped().Delete(&model.Timestamp{},"campaign_parameters_id = ?",campaignParametersId).Error; err != nil{
		return err
	}

	return nil
}

