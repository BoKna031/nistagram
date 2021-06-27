package repository

import (
	"fmt"
	"gorm.io/gorm"
	"nistagram/campaign/model"
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

func (repo *CampaignRepository) UpdateCampaignParameters(campaignParameters model.CampaignParameters) error {
	oldCampParam := &model.CampaignParameters{}
	tx := repo.Database.Table("campaignParameters").Begin()
	if result := tx.Where("campaignId = ? AND start < ?",campaignParameters.CampaignID, campaignParameters.Start).Last(&oldCampParam).Order("start desc"); result.Error != nil {
		return result.Error
	}

	oldCampParam.End = campaignParameters.Start

	if err := tx.Save(oldCampParam).Error; err != nil{
		tx.Rollback()
		return err
	}

	if err := tx.Create(campaignParameters).Error; err != nil {
		tx.Rollback()
		return err
	}
	return nil
}

func (repo *CampaignRepository) DeleteCampaign(campaignID uint) error{
	if err := repo.Database.Delete(&model.Campaign{},campaignID).Error; err!=nil{
		return err
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