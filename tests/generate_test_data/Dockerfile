FROM ubuntu:latest
RUN apt-get update
RUN apt-get -y install curl git libc++-dev jq
WORKDIR /script
RUN mkdir artifacts
COPY ./entrypoint.sh .
RUN chmod a+x ./entrypoint.sh
ADD hello_world/ ./hello_world
RUN chmod -R a+w /script
ENTRYPOINT [ "/script/entrypoint.sh" ]
