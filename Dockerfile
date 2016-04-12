# TODO - build eris/base
FROM chainlex/eris-base:latest

MAINTAINER Eris Industries <support@erisindustries.com>

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    libgmp3-dev && \
  rm -rf /var/lib/apt/lists/*

ENV REPOSITORY "github.com/eris-ltd/eris-keys"
COPY . /go/src/$REPOSITORY/
WORKDIR /go/src/$REPOSITORY/
RUN chown -R $USER:$USER ./
RUN go install

# set the repo and install mint-client
ENV REPOSITORY github.com/eris-ltd/mint-client
ENV BRANCH master
RUN mkdir --parents $GOPATH/src/$REPOSITORY
WORKDIR $GOPATH/src/$REPOSITORY
RUN git clone --quiet https://$REPOSITORY . && \
  git checkout --quiet $BRANCH && \
  go install ./mintkey && \
  mv $GOPATH/bin/mintkey /usr/local/bin

USER $USER
ENV HOME "/home/eris/"
ENV DATA "/home/eris/.eris/keys"
RUN mkdir -p $DATA
RUN chown -R $USER:$USER $DATA

# Final Config
VOLUME $DATA
EXPOSE 4767
CMD ["eris-keys", "server", "--host", "0.0.0.0", "--log", "3"]
