FROM ubuntu@sha256:ed4a42283d9943135ed87d4ee34e542f7f5ad9ecf2f244870e23122f703f91c2

RUN apt update
RUN apt install -y socat

COPY ./flag /flag
COPY ./titanfull /titanfull

RUN chmod 755 /flag /titanfull

EXPOSE 5000
CMD socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/titanfull