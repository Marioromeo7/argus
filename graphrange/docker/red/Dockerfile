FROM kalilinux/kali-rolling:latest
# Pin to a single known-reliable mirror — the base image's default sources
# list round-robins multiple mirrors, and mirror1.sox.rs was consistently
# unreachable from this network (two clean retries both failed on it while
# other mirrors in the same list succeeded).
RUN echo "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list
# git added 2026-09-01 -- found live: several real, non-apt-packaged tools
# (jwt_tool, xxeinjector, and any future GitHub-only tool) install via
# `git clone`, but the base image never had git at all. This silently
# failed jwt_tool's install for the entire multi-day validation saga up to
# this point -- prior "tool=jwt_tool fired correctly" checks only
# confirmed the NAME was selected/recorded, never that the install itself
# succeeded. A foundational dependency belongs in the base image (like
# curl/wget already are), not repeated piecemeal in every git-based tool's
# own install_command.
RUN apt-get update && apt-get install -y python3 python3-pip curl wget git --no-install-recommends
# NO tools preinstalled — supervisor delivers them on demand
WORKDIR /workspace
CMD ["sleep", "infinity"]
