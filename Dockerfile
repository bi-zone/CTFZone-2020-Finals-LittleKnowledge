FROM gcc:7.5.0 as builder
WORKDIR /lib_build/
COPY ./zknlib/ /lib_build/
RUN make clean
RUN make libzkn

FROM python:3.7-slim
RUN pip3 install pycryptodome
RUN groupadd -r crypto && useradd -r -u 1001 -g crypto crypto

RUN mkdir -p /home/crypto
RUN chown -R crypto /home/crypto
USER crypto

COPY team_server.py /home/crypto/
COPY support.py /home/crypto/
COPY public.pem /home/crypto/
COPY --from=builder /lib_build/obj/libzkn.so /home/crypto/
#RUN ls -al /home/crypto
WORKDIR /home/crypto

EXPOSE 1337

CMD ["python3","/home/crypto/team_server.py"]