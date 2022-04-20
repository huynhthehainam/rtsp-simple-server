FROM golang:1.18

WORKDIR /code

COPY . .

RUN go get -d -v ./...

RUN go install -v ./...

CMD [ "go","run","main.go" ]