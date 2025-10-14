FROM python:3.12-slim

ARG APP_USER=1000
ARG APP_GROUP=1000

ENV PYTHONUNBUFFERED=1 \
    TZ=Europe/Oslo \
    # pip:
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=100 \
    # poetry:
    POETRY_VERSION=2.1.4 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_CACHE_DIR='/var/cache/pypoetry' \
    POETRY_HOME='/usr/local' \
    # pipx:
    PIPX_BIN_DIR=/opt/pipx/bin \
    PIPX_HOME=/opt/pipx/home \
    # venv
    VIRTUAL_ENV=/venv \
    PATH="/opt/pipx/bin:/venv/bin:$PATH"

RUN addgroup --gid $APP_GROUP app && adduser --uid $APP_USER --gid $APP_GROUP --system app

RUN python -m pip install --upgrade pip pipx && \
    pipx install "poetry==$POETRY_VERSION"

COPY . .

RUN python3 -m venv ${VIRTUAL_ENV}
RUN poetry install --no-root --no-interaction --no-ansi

EXPOSE 8000

ENTRYPOINT [ "/bin/sh", "-c" ]
CMD [ "streamlit run main.py --server.port 8000" ]