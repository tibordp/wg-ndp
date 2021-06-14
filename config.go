package main

import "time"

const (
	listenPort              int           = 24601
	heartbeatClientInterval time.Duration = 13 * time.Second
	heartbeatServerInterval time.Duration = 11 * time.Second
	staleEvictionInterval   time.Duration = 37 * time.Second
)
