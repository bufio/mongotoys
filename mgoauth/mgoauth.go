// Copyright 2012 The Toys Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package mgoauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/kidstuff/mtoy"
	"github.com/kidstuff/toys/model"
	"github.com/kidstuff/toys/secure"
	"github.com/kidstuff/toys/secure/membership"
	"github.com/kidstuff/toys/secure/membership/sessions"
	"hash"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"net/http"
	"strings"
	"time"
)

type MgoUserCtx struct {
	threshold    time.Duration
	sess         sessions.Provider
	req          *http.Request
	respw        http.ResponseWriter
	notifer      membership.Notificater
	fmtChecker   membership.FormatChecker
	groupMngr    membership.GroupManager
	pwdHash      hash.Hash
	userColl     *mgo.Collection
	rememberColl *mgo.Collection
	cookieName   string
	sessionName  string
	path         string
	domain       string
}

var _ membership.UserManager = &MgoUserCtx{}

func NewMgoUserCtx(w http.ResponseWriter, r *http.Request, sess sessions.Provider,
	userColl, rememberColl *mgo.Collection) *MgoUserCtx {
	ctx := &MgoUserCtx{}
	ctx.respw = w
	ctx.req = r
	ctx.sess = sess
	ctx.userColl = userColl
	ctx.rememberColl = rememberColl
	ctx.cookieName = "toysAuthCookie"
	ctx.sessionName = "toysAuthSession"
	ctx.fmtChecker, _ = membership.NewSimpleChecker(8)
	//ctx.notifer
	ctx.pwdHash = sha256.New()
	ctx.threshold = 15 * time.Minute
	return ctx
}

func (ctx *MgoUserCtx) SetPath(p string) {
	ctx.path = p
}

func (ctx *MgoUserCtx) SetDomain(d string) {
	ctx.domain = d
}

func (ctx *MgoUserCtx) SetOnlineThreshold(t time.Duration) {
	if t > 0 {
		ctx.threshold = t
	}
}

func (ctx *MgoUserCtx) SetNotificater(n membership.Notificater) {
	ctx.notifer = n
}

func (ctx *MgoUserCtx) SetHashFunc(h hash.Hash) {
	ctx.pwdHash = h
}

func (ctx *MgoUserCtx) SetFormatChecker(c membership.FormatChecker) {
	ctx.fmtChecker = c
}

func (ctx *MgoUserCtx) SetGroupManager(mngr membership.GroupManager) {
	ctx.groupMngr = mngr
}

func (ctx *MgoUserCtx) GroupManager() membership.GroupManager {
	return ctx.groupMngr
}

func (ctx *MgoUserCtx) GeneratePassword(password string) membership.Password {
	if len(password) == 0 {
		password = secure.RandomString(16)
	}

	pwd := membership.Password{}
	pwd.InitAt = time.Now()
	pwd.Salt = secure.RandomToken(32)
	ctx.pwdHash.Write([]byte(password))
	ctx.pwdHash.Write(pwd.Salt)
	pwd.Hashed = ctx.pwdHash.Sum(nil)
	ctx.pwdHash.Reset()

	return pwd
}

func (ctx *MgoUserCtx) createUser(email, password string, app bool) (*Account, error) {
	if !ctx.fmtChecker.EmailValidate(email) {
		return nil, membership.ErrInvalidEmail
	}
	if !ctx.fmtChecker.PasswordValidate(password) {
		return nil, membership.ErrInvalidPassword
	}

	u := &Account{}
	u.Id = bson.NewObjectId()
	u.Email = email
	u.Pwd = ctx.GeneratePassword(password)

	u.Approved = app
	return u, nil
}

func (ctx *MgoUserCtx) insertUser(u *Account, notif, app bool) error {
	err := ctx.userColl.Insert(u)
	if err != nil {
		if mgo.IsDup(err) {
			return membership.ErrDuplicateEmail
		}
		return err
	}

	if notif {
		return ctx.notifer.AccountAdded(u)
	}
	return nil
}

func (ctx *MgoUserCtx) AddUser(email, password string, notif, app bool) (membership.User, error) {
	u, err := ctx.createUser(email, password, app)
	if err != nil {
		return nil, err
	}

	err = ctx.insertUser(u, notif, app)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (ctx *MgoUserCtx) AddUserDetail(email, password string, info membership.UserInfo,
	pri map[string]bool, notif, app bool) (membership.User, error) {
	u, err := ctx.createUser(email, password, app)
	if err != nil {
		return nil, err
	}

	u.Info = info
	u.Privilege = pri

	err = ctx.insertUser(u, notif, app)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (ctx *MgoUserCtx) DeleteUser(id model.Identifier) error {
	tid, ok := id.(mtoy.ID)
	if ok && tid.Valid() {
		return ctx.userColl.RemoveId(tid.ObjectId)
	}
	return membership.ErrInvalidId
}

func (ctx *MgoUserCtx) GetUser() (membership.User, error) {
	//check for remember cookie
	cookie, err := ctx.req.Cookie(ctx.cookieName)
	if err == nil {
		//read and parse cookie
		pos := strings.Index(cookie.Value, "|")
		id := cookie.Value[:pos]
		token := cookie.Value[pos+1:]
		if bson.IsObjectIdHex(id) {
			r := RememberInfo{}
			oid := bson.ObjectIdHex(id)
			//validate
			err = ctx.rememberColl.FindId(oid).One(&r)
			if err == nil {
				if token == r.Token {
					if r.Exp.Before(time.Now()) {
						//delete expried auth
						goto DelCookie
					}
					user := Account{}
					err = ctx.userColl.FindId(oid).One(&user)
					if err == nil {
						//re-generate token
						token = base64.URLEncoding.EncodeToString(secure.RandomToken(128))
						http.SetCookie(ctx.respw, &http.Cookie{
							Name:    ctx.cookieName,
							Value:   id + "|" + token,
							Expires: r.Exp,
						})
						err = ctx.rememberColl.UpdateId(oid, bson.M{
							"$set": bson.M{"token": token},
						})
						if err == nil {
							return &user, nil
						}
					}
				}
			}
			ctx.rememberColl.RemoveId(oid)
		}
	DelCookie:
		http.SetCookie(ctx.respw, &http.Cookie{
			Name:   ctx.cookieName,
			MaxAge: -1,
		})
	}
	//check for session
	mapinf, ok := ctx.sess.Get(ctx.sessionName).(map[string]interface{})
	if ok {
		var inf SessionInfo
		inf.Id = mapinf["_id"].(mtoy.ID).ObjectId
		inf.At = mapinf["at"].(time.Time)
		if inf.At.Add(ctx.threshold).After(time.Now()) {
			user := Account{}
			err = ctx.userColl.FindId(inf.Id).One(&user)
			if err == nil {
				return &user, nil
			}
		} else {
			ctx.sess.Delete(ctx.sessionName)
		}
	}
	//not Loged-in
	return nil, errors.New("auth: not Loged-in")
}

func (ctx *MgoUserCtx) FindUser(id model.Identifier) (membership.User, error) {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return nil, membership.ErrInvalidId
	}

	u := &Account{}
	err := ctx.userColl.FindId(tid.ObjectId).One(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (ctx *MgoUserCtx) FindUserByEmail(email string) (membership.User, error) {
	if !ctx.fmtChecker.EmailValidate(email) {
		return nil, membership.ErrInvalidEmail
	}

	u := &Account{}
	err := ctx.userColl.Find(bson.M{"email": email}).One(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (ctx *MgoUserCtx) findAllUser(offsetKey model.Identifier, limit int, filter bson.M) ([]membership.User, error) {
	if limit < 0 {
		return nil, nil
	}

	if offsetKey != nil {
		tid, ok := offsetKey.(mtoy.ID)
		if !ok {
			return nil, membership.ErrInvalidId
		} else {
			if filter == nil {
				filter = bson.M{}
			}
			filter["_id"] = bson.M{"$gt": tid.ObjectId}
		}
	}

	var accounts []Account
	if limit > 0 {
		accounts = make([]Account, 0, limit)
	} else {
		accounts = []Account{}
	}

	err := ctx.userColl.Find(filter).Limit(limit).All(&accounts)
	if err != nil {
		return nil, err
	}

	n := len(accounts)
	userLst := make([]membership.User, n, n)

	for idx, acc := range accounts {
		userLst[idx] = &acc
	}

	return userLst, nil
}

func (ctx *MgoUserCtx) FindAllUser(offsetKey model.Identifier, limit int) ([]membership.User, error) {
	return ctx.findAllUser(offsetKey, limit, nil)
}

func (ctx *MgoUserCtx) FindAllUserOnline(offsetKey model.Identifier, limit int) ([]membership.User, error) {
	return ctx.findAllUser(offsetKey, limit, bson.M{"lastactivity": bson.M{"$lt": time.Now().Add(-ctx.sess.Expiration())}})
}

func (ctx *MgoUserCtx) CountUserOnline() int {
	n, err := ctx.userColl.Find(bson.M{"lastactivity": bson.M{
		"$lt": time.Now().Add(-ctx.sess.Expiration()),
	}}).Count()
	if err == nil {
		return n
	}

	return 0
}

func (ctx *MgoUserCtx) ValidateUser(email string, password string) (membership.User, error) {
	u := &Account{}
	err := ctx.userColl.Find(bson.M{"email": email}).One(&u)
	if err != nil {
		return nil, err
	}
	ctx.pwdHash.Write([]byte(password))
	ctx.pwdHash.Write(u.Pwd.Salt)
	hashed := ctx.pwdHash.Sum(nil)
	ctx.pwdHash.Reset()
	if bytes.Compare(u.Pwd.Hashed, hashed) != 0 {
		return nil, membership.ErrInvalidPassword
	}
	return u, nil
}

func (ctx *MgoUserCtx) Login(id model.Identifier, remember int) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}

	if remember > 0 {
		//use cookie a rememberColl
		//TODO: change the use of RememberInfo
		r := RememberInfo{}
		r.Id = tid.ObjectId
		r.Exp = time.Now().Add(time.Duration(remember) * time.Second)
		r.Token = base64.URLEncoding.EncodeToString(secure.RandomToken(128))
		http.SetCookie(ctx.respw, &http.Cookie{
			Name:    ctx.cookieName,
			Value:   tid.Encode() + "|" + r.Token,
			Expires: r.Exp,
		})
		return ctx.rememberColl.Insert(&r)
	} else {
		//use session
		s := SessionInfo{}
		s.At = time.Now()
		s.Id = tid.ObjectId
		return ctx.sess.Set(ctx.sessionName, s)
	}
	return nil
}

func (ctx *MgoUserCtx) Logout() error {
	cookie, err := ctx.req.Cookie(ctx.cookieName)
	http.SetCookie(ctx.respw, &http.Cookie{
		Name:   ctx.cookieName,
		MaxAge: -1,
	})

	if err == nil {
		//read and parse cookie
		id := cookie.Value[:strings.Index(cookie.Value, "|")]
		if bson.IsObjectIdHex(id) {
			oid := bson.ObjectIdHex(id)
			ctx.rememberColl.RemoveId(oid)
		}
	}

	ctx.sess.Delete(ctx.sessionName)

	return nil
}

func (ctx *MgoUserCtx) UpdateInfo(id model.Identifier, info membership.UserInfo, notif bool) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}
	return ctx.userColl.UpdateId(tid.ObjectId, bson.M{"$set": bson.M{"info": info}})
}

func (ctx *MgoUserCtx) UpdatePrivilege(id model.Identifier, pri map[string]bool, notif bool) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}
	return ctx.userColl.UpdateId(tid.ObjectId, bson.M{"$set": bson.M{"privilege": pri}})
}

func (ctx *MgoUserCtx) ChangePassword(id model.Identifier, password string, notif bool) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return membership.ErrInvalidId
	}

	acc := Account{}
	err := ctx.userColl.FindId(tid.ObjectId).One(&acc)
	if err != nil {
		return err
	}

	err = ctx.userColl.UpdateId(tid.ObjectId, bson.M{"$set": bson.M{
		"oldpwd": acc.GetOldPassword(),
		"pwd":    ctx.GeneratePassword(password),
	}})
	if err != nil {
		return err
	}

	return ctx.notifer.PasswordChanged(&acc)
}

func (ctx *MgoUserCtx) ValidConfirmCode(id model.Identifier, key, code string, regen, del bool) (bool, error) {
	tid, ok := id.(mtoy.ID)
	if !ok {
		return false, membership.ErrInvalidId
	}

	acc := Account{}
	err := ctx.userColl.FindId(tid.ObjectId).One(&acc)
	if err != nil {
		return false, err
	}

	ok = acc.ConfirmCodes[key] == code
	change := bson.M{}
	if del {
		change["$unset"] = bson.M{"confirmcodes." + key: false}
	} else {
		change["$set"] = bson.M{"confirmcodes." + key: secure.RandomString(32)}
	}

	ctx.userColl.UpdateId(tid.ObjectId, change)

	return ok, err
}

func (ctx *MgoUserCtx) Can(u membership.User, do string) bool {

	return false
}
