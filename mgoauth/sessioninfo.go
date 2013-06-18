package mgoauth

import (
	"github.com/kidstuff/mtoy"
	"github.com/kidstuff/toys/model"
	"github.com/kidstuff/toys/secure/membership"
	"labix.org/v2/mgo/bson"
)

type SessionInfo struct {
	Id                     bson.ObjectId `bson:"_id"`
	membership.SessionInfo `bson:",inline"`
}

func (s *SessionInfo) GetId() model.Identifier {
	return mtoy.ID{s.Id}
}

func (s *SessionInfo) SetId(id model.Identifier) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}
	s.Id = tid.ObjectId
	return nil
}
