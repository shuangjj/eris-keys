# TODO - build eris/base
FROM eris/base:latest

MAINTAINER Eris Industries <support@erisindustries.com>

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    libgmp3-dev && \
  rm -rf /var/lib/apt/lists/*

ENV repository=github.com/eris-ltd/eris-keys
COPY . /go/src/$repository/
WORKDIR /go/src/$repository/

RUN go get ./... && go install

WORKDIR /home/eris/
USER $user

# Final Config
VOLUME "/home/eris/.eris/keys"
EXPOSE 4767
ENTRYPOINT ["eris-keys"]
CMD ["server", "--host", "0.0.0.0"]
