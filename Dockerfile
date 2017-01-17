FROM golang:1.7-alpine
RUN apk add --update git && rm -rf /var/cache/apk/*

WORKDIR /go/src/github.com/agileventures/ldapserver
ADD . /go/src/github.com/agileventures/ldapserver

RUN go get github.com/vjeantet/ldapserver
CMD go run server.go
