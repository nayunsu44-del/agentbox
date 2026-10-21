# 컨트롤 플레인 이미지 (NF-5). deploy/docker-compose.yml이 Caddy(TLS) 뒤에 띄운다.
#
# 샌드박스는 호스트의 Docker 데몬에 만든다(/var/run/docker.sock). 화면 연결은 docker CLI로
# docker exec를 하므로 CLI도 넣는다. 격리 런타임(runsc 등)은 호스트 데몬에 설치돼 있어야 한다.
FROM docker:27-cli AS dockercli

FROM python:3.13-slim
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /src
COPY pyproject.toml README.md ./
COPY agentbox ./agentbox
RUN pip install --no-cache-dir . && rm -rf /src
WORKDIR /
ENV AGENTBOX_HOME=/var/lib/agentbox PYTHONUNBUFFERED=1
EXPOSE 8765
# 컨테이너 안에서는 0.0.0.0에 열지만 호스트에는 포트를 내지 않는다. Caddy만 이 포트에 붙는다.
CMD ["agentbox", "serve", "--host", "0.0.0.0", "--port", "8765", "--behind-tls-proxy"]
