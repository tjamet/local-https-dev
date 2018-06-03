FROM golang:alpine AS build

ADD vendor /go/src/github.com/tjamet/local-https-dev/vendor
ADD server /go/src/github.com/tjamet/local-https-dev/server
RUN go build -o /server /go/src/github.com/tjamet/local-https-dev/server/main.go

FROM alpine
RUN apk add --no-cache ca-certificates
COPY --from=build /server /server
ENTRYPOINT ["/server"]