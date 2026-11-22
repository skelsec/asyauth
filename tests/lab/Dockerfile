# Throwaway MIT krb5 KDC + MIT GSSAPI peer for the asyauth interop tests.
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		krb5-kdc krb5-admin-server krb5-user python3 python3-gssapi \
	&& rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY entrypoint.sh peer.py genvectors.py /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
