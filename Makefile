
.PHONY:update
update:
	git add . && git commit -m "update" && git push

.PHONY:build
build:
	go build -v .

.PHONY:run
run:
	go run *.go

