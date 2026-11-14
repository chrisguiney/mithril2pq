# Three stages:
#   build      compiles mithril2pq
#   mithril2pq the static binary alone:  docker build --target mithril2pq -t mithril2pq .
#   notebook   JupyterLab with DuckDB and the exploration notebook (the default target):
#              docker build -t mithril2pq-notebook .

FROM golang:1.26.10-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mithril2pq .

FROM gcr.io/distroless/static-debian12:nonroot AS mithril2pq
COPY --from=build /out/mithril2pq /usr/local/bin/mithril2pq
ENTRYPOINT ["/usr/local/bin/mithril2pq"]

FROM python:3.12-slim AS notebook
COPY notebooks/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY --from=mithril2pq /usr/local/bin/mithril2pq /usr/local/bin/mithril2pq
RUN useradd --create-home --uid 1000 jupyter
COPY --chown=jupyter notebooks/explore.ipynb /work/explore.ipynb
USER jupyter
WORKDIR /work
# Mount the mithril2pq output directory here (read-only is fine). Set
# JUPYTER_TOKEN to choose the login token; otherwise Jupyter logs a random one.
ENV MITHRIL2PQ_DATA=/data
EXPOSE 8888
CMD ["jupyter", "lab", "--ip=0.0.0.0", "--port=8888", "--no-browser", "--ServerApp.root_dir=/work"]
