# Hearth hub image, built by goreleaser (dockers_v2 in .goreleaser.yaml).
# The build context is prepared by goreleaser and holds <os>/<arch>/hearth per
# platform, so this file does not build from source: use `task release:snapshot`.
#
#   docker run -d -p 7443:7443 -p 7080:7080 -v hearth:/var/lib/hearth ghcr.io/gvart/hearth
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/hearth /usr/bin/hearth

# Hub state (SQLite, CA, certificates). An empty dir owned by nonroot, so a
# fresh named volume mounted here is writable by the hub.
ENV HEARTH_DATA_DIR=/var/lib/hearth
COPY --from=gcr.io/distroless/static-debian12:nonroot --chown=nonroot:nonroot /home/nonroot /var/lib/hearth
VOLUME ["/var/lib/hearth"]

# 7443: agents (mTLS). 7080: web UI and JSON API (HTTP).
EXPOSE 7443 7080

USER nonroot:nonroot
ENTRYPOINT ["hearth"]
CMD ["hub"]
