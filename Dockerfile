FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY --from=web /web/dist web/dist
# An empty /data to copy into the final image, so the volume starts out writable by the nonroot user.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /gatehouse . && mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /gatehouse /gatehouse
COPY --from=build --chown=nonroot:nonroot /data /data
COPY policy.json /etc/gatehouse/policy.json
ENV GATEHOUSE_ADDR=0.0.0.0:8787 \
    GATEHOUSE_DB=/data/gatehouse.db \
    GATEHOUSE_POLICY=/etc/gatehouse/policy.json
VOLUME /data
EXPOSE 8787
ENTRYPOINT ["/gatehouse"]
