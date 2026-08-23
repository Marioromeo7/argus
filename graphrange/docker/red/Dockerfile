FROM kalilinux/kali-rolling:latest
# Pin to a single known-reliable mirror — the base image's default sources
# list round-robins multiple mirrors, and mirror1.sox.rs was consistently
# unreachable from this network (two clean retries both failed on it while
# other mirrors in the same list succeeded).
RUN echo "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list
RUN apt-get update && apt-get install -y python3 python3-pip curl wget --no-install-recommends
# NO tools preinstalled — supervisor delivers them on demand
WORKDIR /workspace
CMD ["sleep", "infinity"]
