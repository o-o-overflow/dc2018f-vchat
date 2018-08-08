FROM ubuntu:18.04
RUN apt-get update && apt-get install -y \
    gdb \
    xinetd \
    ejabberd \
    libgloox15 \
    libgloox-dev \
    libflite1 \
    libpng16-16 \
    libqrencode3 \
    libzbar0 \
    libmagick++-6.q16-7

RUN touch /flag && chmod 644 /flag && echo -n "TESTFLAG" | shasum -a 512 | cut -c 1-48  > /flag
COPY service.conf /service.conf
COPY src/vchat /vchat
COPY src/vbot /vbot
RUN chmod 755 /vchat /vbot

EXPOSE 2555
ENV VCHAT_SERVER ooo.vchat
ENV VCHAT_MESSAGE hello
CMD ["xinetd", "-dontfork", "-f", "/service.conf"]
