# Build a runnable image. Multi-stage so the wheel build tooling does not ship.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY threat_detector ./threat_detector
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
# Captures can be large and pandas is not frugal; fail loudly rather than
# swapping. libpcap is needed only if the image is used to read .pcap files.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Never run a network analysis tool as root.
RUN useradd --create-home --uid 10001 detector
WORKDIR /home/detector

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl "gunicorn>=21.0" "scapy>=2.5" \
    && rm -rf /tmp/*.whl

USER detector
ENV DATA_FILE=/data/packets.csv \
    BASELINE_FILE=/data/baseline.csv \
    MODEL_FILE=/var/lib/detector/model.pkl \
    MODEL_KEY_FILE=/var/lib/detector/signing.key \
    HOST=0.0.0.0 \
    PORT=5000 \
    PYTHONUNBUFFERED=1
VOLUME ["/data", "/var/lib/detector"]
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health').status==200 else 1)"

# Binding to 0.0.0.0 inside a container is normal, but the app refuses to do it
# without API_TOKEN set — publish the port only behind something that
# authenticates, or pass API_TOKEN.
ENTRYPOINT ["threat-detector"]
CMD ["serve", "--production"]
