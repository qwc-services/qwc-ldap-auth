FROM sourcepole/qwc-uwsgi-base:alpine-v2025.10.13

WORKDIR /srv/qwc_service
ADD pyproject.toml uv.lock ./

# git: Required for pip with git repos
RUN \
    apk add --no-cache --update --virtual build-deps gcc python3-dev musl-dev libffi-dev git && \
    apk add --no-cache --update --virtual postgresql-dev libpq-dev && \
    uv sync --frozen && \
    uv cache clean && \
    apk del build-deps

ADD src /srv/qwc_service/

ENV SERVICE_MOUNTPOINT=/auth
