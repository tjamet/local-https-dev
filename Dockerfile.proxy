FROM golang:alpine AS build

ADD vendor /go/src/github.com/tjamet/local-https-dev/vendor
ADD server /go/src/github.com/tjamet/local-https-dev/server
ADD proxy /go/src/github.com/tjamet/local-https-dev/proxy
RUN go build -o /proxy /go/src/github.com/tjamet/local-https-dev/proxy/main.go

FROM alpine
RUN apk add --no-cache ca-certificates
COPY --from=build /proxy /proxy
ENTRYPOINT ["/proxy"]