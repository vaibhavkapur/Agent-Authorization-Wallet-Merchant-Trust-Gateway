# Single image for every Python service (api, gateway, registry, issuer, worker).
# The service is chosen by the compose command.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY packages ./packages
COPY apps/api ./apps/api
COPY apps/merchant-gateway ./apps/merchant-gateway
COPY apps/test-registry ./apps/test-registry
COPY apps/test-issuer ./apps/test-issuer
COPY fixtures ./fixtures
COPY migrations ./migrations

RUN pip install --no-deps \
      ./packages/signer-interface ./packages/authorization-domain ./packages/ap2-profile \
      ./packages/vi-profile ./packages/tap-verifier ./packages/execution-coordinator \
      ./apps/api ./apps/merchant-gateway ./apps/test-registry ./apps/test-issuer

EXPOSE 8000 8010 8020 8030
CMD ["uvicorn", "aaw_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
