// Copyright 2012 The Toys Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package mgosessions

import (
	"errors"
	"github.com/kidstuff/toys/secure/membership/sessions"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"net/http"
	"time"
)

var (
	ErrNotFound error = errors.New("session: entry not found in database")
	ErrNoCookie error = errors.New("session: session cookie not found")
	ErrInvalid  error = errors.New("session: invalid session data")
)

type MgoProvider struct {
	req        *http.Request
	resp       http.ResponseWriter
	cookieName string
	expiration time.Duration
	matchAddr  bool
	matchAgent bool
	collection *mgo.Collection
}

func NewMgoProvider(w http.ResponseWriter, r *http.Request,
	c *mgo.Collection) sessions.Provider {
	p := &MgoProvider{}
	p.req = r
	p.resp = w
	p.cookieName = "toysSession"
	p.expiration = 7200 * time.Second
	p.matchAddr = true
	p.collection = c

	return p
}

func (p *MgoProvider) SetCookieName(name string) {
	p.cookieName = name
}

func (p *MgoProvider) CookieName() string {
	return p.cookieName
}

func (p *MgoProvider) SetExpiration(exp time.Duration) {
	if exp <= 1*time.Second {
		p.expiration = 7200 * time.Second
		return
	}
	p.expiration = exp
	p.collection.EnsureIndex(mgo.Index{
		Key:         []string{"lastactivity"},
		ExpireAfter: exp,
		Sparse:      true,
	})
}

func (p *MgoProvider) Expiration() time.Duration {
	return p.expiration
}

func (p *MgoProvider) SetMatchRemoteAddr(match bool) {
	p.matchAddr = match
}

func (p *MgoProvider) MatchRemoteAddr() bool {
	return p.matchAddr
}

func (p *MgoProvider) SetMatchUserAgent(match bool) {
	p.matchAgent = match
}

func (p *MgoProvider) MatchUserAgent() bool {
	return p.matchAgent
}

func (p *MgoProvider) load() (*sessions.SessionEntry, error) {
	var agent = p.req.UserAgent()
	if len(agent) > 120 {
		agent = agent[:120]
	}

	cookie, err := p.req.Cookie(p.CookieName())
	if err == nil {
		entry := &sessions.SessionEntry{}
		err = p.collection.FindId(cookie.Value).One(&entry)
		if err == nil {
			if (p.MatchUserAgent() && entry.UserAgent != agent) ||
				(p.MatchRemoteAddr() && entry.RemoteAddr != p.req.RemoteAddr) {
				p.collection.RemoveId(cookie.Value)
				return sessions.NewSessionEntry(p.req.RemoteAddr, agent), ErrInvalid
			} else {
				entry.LastActivity = time.Now()
				return entry, nil
			}
		}
	} else {
		return sessions.NewSessionEntry(p.req.RemoteAddr, agent), ErrNoCookie
	}
	return sessions.NewSessionEntry(p.req.RemoteAddr, agent), ErrNotFound
}

func (p *MgoProvider) setData(name string, val interface{}, flash bool) error {
	var err error
	entry, lerr := p.load()
	if lerr != nil {
		http.SetCookie(p.resp, &http.Cookie{
			Name:    p.cookieName,
			Value:   entry.Id,
			MaxAge:  int(p.Expiration().Seconds()),
			Expires: entry.LastActivity.Add(p.Expiration()),
		})
	}

	if flash {
		entry.FlashData[name] = val
		err = p.collection.UpdateId(entry.Id, bson.M{"$set": bson.M{
			"flashdata":    entry.FlashData,
			"lastactivity": entry.LastActivity,
		}})
	} else {
		entry.Data[name] = val
		err = p.collection.UpdateId(entry.Id, bson.M{"$set": bson.M{
			"data":         entry.Data,
			"lastactivity": entry.LastActivity,
		}})
	}
	if err != nil {
		return p.collection.Insert(entry)
	}

	return nil
}

func (p *MgoProvider) Set(name string, val interface{}) error {
	return p.setData(name, val, false)
}

func (p *MgoProvider) Get(name string) interface{} {
	entry, err := p.load()
	if err != nil {
		return nil
	}
	return entry.Data[name]
}

func (p *MgoProvider) GetInt(name string) int {
	v, ok := p.Get(name).(int)
	if !ok {
		return 0
	}
	return v
}

func (p *MgoProvider) GetBool(name string) bool {
	v, ok := p.Get(name).(bool)
	if !ok {
		return false
	}
	return v
}

func (p *MgoProvider) GetString(name string) string {
	v, ok := p.Get(name).(string)
	if !ok {
		return ""
	}
	return v
}

func (p *MgoProvider) Delete(name ...string) error {
	entry, err := p.load()
	if err != nil {
		return err
	}

	for i := range name {
		delete(entry.Data, name[i])
	}

	err = p.collection.UpdateId(entry.Id, bson.M{"$set": bson.M{
		"data":         entry.Data,
		"lastactivity": entry.LastActivity,
	}})
	if err != nil {
		return p.collection.Insert(entry)
	}

	return nil
}

func (p *MgoProvider) DeleteAll(flash bool) error {
	entry, err := p.load()
	if err != nil {
		return err
	}

	entry.Data = map[string]interface{}{}
	if flash {
		entry.FlashData = map[string]interface{}{}
	}

	err = p.collection.UpdateId(entry.Id, bson.M{"$set": bson.M{
		"data":         entry.Data,
		"lastactivity": entry.LastActivity,
	}})
	if err != nil {
		return p.collection.Insert(entry)
	}

	return nil
}

func (p *MgoProvider) SetFlash(name string, val interface{}) error {
	return p.setData(name, val, true)
}

func (p *MgoProvider) GetFlash(name string) interface{} {
	entry, err := p.load()
	if err != nil {
		return nil
	}
	d := entry.FlashData[name]
	delete(entry.FlashData, name)

	err = p.collection.UpdateId(entry.Id, bson.M{"$set": bson.M{
		"flashdata":    entry.FlashData,
		"lastactivity": entry.LastActivity,
	}})
	if err != nil {
		p.collection.Insert(entry)
	}

	return d
}

func (p *MgoProvider) GetFlashInt(name string) int {
	v, ok := p.GetFlash(name).(int)
	if !ok {
		return 0
	}
	return v
}

func (p *MgoProvider) GetFlashBool(name string) bool {
	v, ok := p.GetFlash(name).(bool)
	if !ok {
		return false
	}
	return v
}

func (p *MgoProvider) GetFlashString(name string) string {
	v, ok := p.GetFlash(name).(string)
	if !ok {
		return ""
	}
	return v
}

func (p *MgoProvider) Destroy() error {
	entry, err := p.load()

	if err == nil || err == ErrNotFound {
		http.SetCookie(p.resp, &http.Cookie{
			MaxAge: -1,
		})
	}

	if err == nil {
		return p.collection.RemoveId(entry.Id)
	}
	return nil
}
