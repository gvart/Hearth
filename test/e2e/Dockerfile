# Hearth image for the end-to-end tests, built from the current checkout
# (context: the repository root). Not the release image; see /Dockerfile.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/hearth ./cmd/hearth

# alpine rather than distroless: the agent containers idle on `sleep` and the
# hub healthcheck needs `nc`.
FROM alpine:3.22
COPY --from=build /out/hearth /usr/bin/hearth
