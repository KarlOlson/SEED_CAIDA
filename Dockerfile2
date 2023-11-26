FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
RUN echo 'exec zsh' > /root/.bashrc

RUN apt-get update && apt-get install -y --no-install-recommends curl dnsutils ipcalc iproute2 iputils-ping jq mtr-tiny nano netcat tcpdump termshark vim-nox zsh
RUN curl -L https://grml.org/zsh/zshrc > /root/.zshrc
RUN mkdir -p /usr/share/doc/bird2/examples/
RUN touch /usr/share/doc/bird2/examples/bird.conf
RUN apt-get update && apt-get install -y --no-install-recommends bird2
