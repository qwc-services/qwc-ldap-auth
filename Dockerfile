FROM sourcepole/qwc-uwsgi-base:alpine-v2021.12.16

ADD . /srv/qwc_service
RUN pip3 install --no-cache-dir -r /srv/qwc_service/requirements.txt
