FROM postgres:16-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-16-pgaudit iproute2 && \
    rm -rf /var/lib/apt/lists/*
COPY services/common/lab-route /usr/local/bin/lab-route
COPY services/db/db-entrypoint.sh /usr/local/bin/db-entrypoint.sh
COPY services/db/postgresql.conf services/db/pg_hba.conf /etc/postgresql/
COPY services/db/01-init.sh /docker-entrypoint-initdb.d/01-init.sh
RUN chmod +x /usr/local/bin/lab-route /usr/local/bin/db-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/lab-route", "/usr/local/bin/db-entrypoint.sh"]
CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"]
