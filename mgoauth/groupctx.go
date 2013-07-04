package mgoauth

import (
	"github.com/kidstuff/toys/model"
	"github.com/kidstuff/toys/secure/membership"
	"labix.org/v2/mgo"
)

type MgoGroupCtx struct {
	groupColl *mgo.Collection
}

func (ctx *MgoGroupCtx) AddGroupDetail(name string, info *membership.GroupInfo, pri map[string]bool) error {
	return nil
}

func (ctx *MgoGroupCtx) UpdateInfo(id model.Identifier, info *membership.GroupInfo) error {
	return nil
}

func (ctx *MgoGroupCtx) UpdatePrivilege(id model.Identifier, pri map[string]bool) error {
	return nil
}

func (ctx *MgoGroupCtx) FindGroup(id model.Identifier) (membership.Grouper, error) {
	return nil, nil
}

func (ctx *MgoGroupCtx) FindAllGroup(offsetId model.Identifier, limit int) ([]membership.Grouper, error) {
	return nil, nil
}
