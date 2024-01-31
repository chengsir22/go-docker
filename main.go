package main

import "fmt"

func main() {
	fmt.Println("hello world")
}

//dlv --headless --listen=:2345 --api-version=2 --accept-multiclient exec ./go-docker
