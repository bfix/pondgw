package main

import (
	"github.com/bfix/gospel/logger"
)

type target struct {
	day   int
	week  int
	month int
	year  int
}

type Statistics struct {
	fileRef string

	NumMailUsers int
	NumPondUsers int

	current          target
	NumMessagesToday int
	NumMessagesWeek  int
	NumMessagesMonth int
	NumMessagesYear  int
}

func ReadStatistics(fname string) (*Statistics, error) {
	s := new(Statistics)
	rows, err := g.db.Query(g.config.Database.CountMailUser)
	if err != nil {
		logger.Println(logger.ERROR, "Unable to query registered user table (email)")
		return nil, err
	}
	if !rows.Next() {
		logger.Println(logger.ERROR, "Unable to count email user records")
		return nil, err
	}
	if err = rows.Scan(&s.NumMailUsers); err != nil {
		logger.Println(logger.ERROR, "Unable to count email user records")
		return nil, err
	}
	rows, err = g.db.Query(g.config.Database.CountPondUser)
	if err != nil {
		logger.Println(logger.ERROR, "Unable to query registered user table (pond)")
		return nil, err
	}
	if !rows.Next() {
		logger.Println(logger.ERROR, "Unable to count Pond user records")
		return nil, err
	}
	if err = rows.Scan(&s.NumPondUsers); err != nil {
		logger.Println(logger.ERROR, "Unable to count Pond user records")
		return nil, err
	}
	rows, err = g.db.Query(g.config.Database.SelectStats)
	if err != nil {
		logger.Println(logger.ERROR, "Unable to query registered user table (stats)")
		return nil, err
	}
	var (
		name  string
		value int
	)
	for rows.Next() {
		if err = rows.Scan(&name, &value); err != nil {
			logger.Println(logger.ERROR, "Unable to retrieve stats records")
			return nil, err
		}
		switch name {
		}
	}
	return s, nil
}

func (s *Statistics) Sync() {

}

func (s *Statistics) IncMailUser() {
	s.NumMailUsers++
	s.Sync()
}
