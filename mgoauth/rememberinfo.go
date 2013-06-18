package mgoauth

import (
	"github.com/kidstuff/mtoy"
	"github.com/kidstuff/toys/model"
	"github.com/kidstuff/toys/secure/membership"
	"labix.org/v2/mgo/bson"
)

type RememberInfo struct {
	Id                      bson.ObjectId `bson:"_id"`
	membership.RememberInfo `bson:",inline"`
}

func (r *RememberInfo) GetId() model.Identifier {
	return mtoy.ID{r.Id}
}

func (r *RememberInfo) SetId(id model.Identifier) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}
	r.Id = tid.ObjectId
	return nil
}
