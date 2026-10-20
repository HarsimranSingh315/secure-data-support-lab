FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 curl && rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir "psycopg[binary]==3.2.3"
RUN useradd --system --no-create-home appuser
COPY services/common/lab-route /usr/local/bin/lab-route
COPY services/app/app.py /srv/app.py
COPY services/app/app-entrypoint.sh /usr/local/bin/app-entrypoint.sh
RUN chmod +x /usr/local/bin/lab-route /usr/local/bin/app-entrypoint.sh
EXPOSE 8443
# Starts as root only to set the lab route and copy certs; the app itself runs as appuser.
ENTRYPOINT ["/usr/local/bin/lab-route", "/usr/local/bin/app-entrypoint.sh"]
