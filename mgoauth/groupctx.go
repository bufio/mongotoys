package mgoauth

import (
	"github.com/kidstuff/mtoy"
	"github.com/kidstuff/toys/model"
	"github.com/kidstuff/toys/secure/membership"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

type MgoGroupCtx struct {
	groupColl *mgo.Collection
}

func NewMgoGroupCtx(groupColl *mgo.Collection) *MgoGroupCtx {
	ctx := &MgoGroupCtx{}
	ctx.groupColl = groupColl
	return ctx
}

func (ctx *MgoGroupCtx) AddGroupDetail(name string, info membership.GroupInfo,
	pri map[string]bool) (membership.Grouper, error) {
	g := &Group{}
	g.Id = bson.NewObjectId()
	g.Name = name
	g.Info = info
	g.Privilege = pri

	err := ctx.groupColl.Insert(g)
	if err != nil {
		if mgo.IsDup(err) {
			return nil, membership.ErrDuplicateName
		}
		return nil, err
	}

	return g, nil
}

func (ctx *MgoGroupCtx) UpdateInfo(id model.Identifier, info membership.GroupInfo) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}

	return ctx.groupColl.UpdateId(tid.ObjectId, bson.M{"$set": bson.M{"info": info}})
}

func (ctx *MgoGroupCtx) UpdatePrivilege(id model.Identifier, pri map[string]bool) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}

	return ctx.groupColl.UpdateId(tid.ObjectId, bson.M{"$set": bson.M{"privilege": pri}})
}

func (ctx *MgoGroupCtx) FindGroup(id model.Identifier) (membership.Grouper, error) {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return nil, membership.ErrInvalidId
	}

	g := &Group{}
	err := ctx.groupColl.FindId(tid.ObjectId).One(g)
	if err != nil {
		return nil, err
	}

	return g, nil
}

func (ctx *MgoGroupCtx) FindGroupByName(name string) (membership.Grouper, error) {
	g := &Group{}
	err := ctx.groupColl.Find(bson.M{"name": name}).One(g)
	if err != nil {
		return nil, err
	}

	return g, nil
}

func (ctx *MgoGroupCtx) FindAllGroup(offsetKey model.Identifier, limit int) ([]membership.Grouper, error) {
	if limit < 0 {
		return nil, nil
	}

	var filter bson.M

	if offsetKey != nil {
		tid, ok := offsetKey.(mtoy.ID)
		if !ok {
			return nil, membership.ErrInvalidId
		} else {
			filter["_id"] = bson.M{"$gt": tid.ObjectId}
		}
	}

	var groups []Group
	if limit > 0 {
		groups = make([]Group, 0, limit)
	} else {
		groups = []Group{}
	}

	err := ctx.groupColl.Find(filter).Limit(limit).All(&groups)
	if err != nil {
		return nil, err
	}

	n := len(groups)
	gLst := make([]membership.Grouper, n, n)

	for idx, g := range groups {
		gLst[idx] = &g
	}

	return gLst, nil
}
