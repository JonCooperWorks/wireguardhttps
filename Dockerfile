FROM golang:1.15

WORKDIR /go/src/github.com/joncooperworks/wireguardhttps
COPY . .

RUN go build -o wireguardhttps cmd/wireguardhttps.go

EXPOSE 80
EXPOSE 443

ENTRYPOINT ["./wireguardhttps"]