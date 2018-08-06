FROM ubuntu:18.04
RUN apt-get update && apt-get install -y xinetd libgloox15 libflite1 libpng16-16 libqrencode3 libzbar0 libmagick++-6.q16-7
RUN touch /flag && chmod 644 /flag && echo -ne "TESTFLAG" | md5sum | cut -f1 -d' ' > /flag
COPY service.conf /service.conf
COPY src/vchat /vchat
COPY src/vbot /vbot
RUN chmod 755 /vchat /vbot

EXPOSE 2555
ENV VCHAT_SERVER ooo.vchat
ENV VCHAT_MESSAGE hello
CMD ["/usr/sbin/xinetd", "-filelog", "-", "-dontfork", "-f", "/service.conf"]
