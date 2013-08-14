package mgoauth

import (
	"github.com/kidstuff/mtoy"
	"github.com/kidstuff/toys/model"
	"github.com/kidstuff/toys/secure/membership"
	"labix.org/v2/mgo/bson"
)

type Account struct {
	Id                 bson.ObjectId `bson:"_id"`
	GroupIds           []bson.ObjectId
	membership.Account `bson:",inline"`
	BriefGroups        []struct {
		Id   bson.ObjectId
		Name string
	}
}

func (a *Account) GetId() model.Identifier {
	return mtoy.ID{a.Id}
}

func (a *Account) SetId(id model.Identifier) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		if !bson.IsObjectIdHex(tid.Encode()) {
			return membership.ErrInvalidId
		} else {
			a.Id = bson.ObjectIdHex(tid.Encode())
			return nil
		}
	}
	a.Id = tid.ObjectId
	return nil
}

func (a *Account) GetBriefGroups() []membership.BriefGroup {
	n := len(a.BriefGroups)
	idLst := make([]membership.BriefGroup, n, n)
	for idx, brief := range a.BriefGroups {
		idLst[idx] = membership.BriefGroup{mtoy.ID{brief.Id}, brief.Name}
	}

	return idLst
}
