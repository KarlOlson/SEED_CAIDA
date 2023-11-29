#FROM handsonsecurity/seedemu-base
FROM karlolson1/seedog:v1
ARG DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /usr/share/doc/bird2/examples/
RUN touch /usr/share/doc/bird2/examples/bird.conf
RUN apt-get update && apt-get install -y --no-install-recommends bird2
