# spamhaus-check Dockerfile
# Version: 3.1.1
FROM python:3.12-slim

# zabbix_sender pushes results to the Zabbix server's trapper port (10051).
# tzdata lets the container observe a real timezone (see ENV TZ below) -
# without it, a container always runs on UTC regardless of the host's
# clock settings, since it doesn't inherit host timezone config.
RUN apt-get update \
    && apt-get install -y --no-install-recommends zabbix-sender tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV TZ=Europe/Kyiv

WORKDIR /app
COPY spamhaus_zabbix_check.py entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# /data holds ips.txt (your input list, create this yourself) and
# state.json (the previous run's per-IP status, written automatically).
# Bind-mount a host directory here so state survives container recreation.
VOLUME /data

# Runs once a day at this wall-clock time, in the TZ set above.
ENV RUN_AT=09:00

ENTRYPOINT ["/app/entrypoint.sh"]