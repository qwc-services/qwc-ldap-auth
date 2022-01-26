FROM sourcepole/qwc-uwsgi-base:alpine-v2022.01.26

ADD . /srv/qwc_service
RUN pip3 install --no-cache-dir -r /srv/qwc_service/requirements.txt
