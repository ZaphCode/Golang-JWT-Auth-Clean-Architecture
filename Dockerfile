FROM golang:1.18.4
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN go build -o /auth-app
EXPOSE 8080
CMD ["/auth-app"]