# 데스크톱 템플릿 샌드박스 이미지 (UX-1, UX-2, TL-2).
#
#   docker build -t agentbox-desktop:0.1 images/desktop
#
# 사용자 두 명으로 나눈다.
#   agent   (uid 1000)  에이전트의 exec·파일 도구가 도는 계정
#   desktop (uid 1001)  X 서버와 Xfce가 도는 계정. agent 그룹에 들어 있어 /workspace를 같이 쓴다.
# X 서버는 desktop만 읽을 수 있는 쿠키로 잠근다. 그래서 에이전트가 exec로 xdotool을 돌려
# 화면 인수 중인 사람의 입력을 엿보거나 GUI 도구 대기를 건너뛸 수 없다.
# VNC는 포트를 열지 않는다. 컨트롤 플레인이 연결마다 docker exec로 x11vnc -inetd를 띄운다.
# x11vnc -inetd는 표준 입력을 양방향 소켓으로 쓰는데 docker exec가 주는 건 파이프라서,
# socat이 socketpair를 만들어 사이를 잇는다.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        xvfb xauth x11vnc socat xdotool scrot x11-xserver-utils \
        xfce4-session xfwm4 xfce4-panel xfdesktop4 xfce4-settings xfconf thunar xfce4-terminal mousepad \
        dbus-x11 adwaita-icon-theme-full fonts-noto-cjk fonts-dejavu-core \
        novnc \
        bash coreutils findutils procps ca-certificates curl less file \
    && rm -rf /var/lib/apt/lists/*

# ubuntu:24.04에 이미 있는 uid 1000 ubuntu 계정을 agent로 바꾼다.
RUN usermod -l agent -d /home/agent -m ubuntu && groupmod -n agent ubuntu \
    && useradd -m -u 1001 -U -G agent -s /bin/bash desktop \
    && chmod 700 /home/desktop \
    && mkdir -p /home/desktop/Desktop && ln -s /workspace /home/desktop/Desktop/workspace \
    && chown -R desktop:desktop /home/desktop \
    && cp -a /home/desktop /usr/local/share/agentbox-desktop-home \
    && chown -R root:root /usr/local/share/agentbox-desktop-home

COPY agentbox-desktop-start /usr/local/bin/agentbox-desktop-start
RUN chmod 755 /usr/local/bin/agentbox-desktop-start

LABEL agentbox.template="desktop" agentbox.desktop.display=":0" agentbox.desktop.user="desktop"
CMD ["/usr/local/bin/agentbox-desktop-start"]
