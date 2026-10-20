FROM python:3.12-slim
RUN useradd --system --no-create-home dam && mkdir /dam && chown dam:dam /dam
COPY services/dam/dam.py services/dam/rules.json /srv/
USER dam
ENTRYPOINT ["python3", "/srv/dam.py", "--log", "/pglogs/postgresql.csv", "--alerts", "/dam/alerts.jsonl", "--rules", "/srv/rules.json"]
