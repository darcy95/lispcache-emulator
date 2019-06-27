FROM perl:5
WORKDIR /usr/src/lisp
COPY LICENSE /usr/src/lisp/
COPY lispcache-emulator.pl /usr/src/lisp/
COPY lisp-database /usr/src/lisp/
COPY README /usr/src/lisp/
RUN ["cpanm", "Socket6"]
RUN ["cpanm", "Net::Patricia"]
